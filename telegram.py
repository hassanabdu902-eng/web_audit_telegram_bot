import os
import re
import sys
import asyncio
import json
import logging
import secrets
import signal
import threading
import multiprocessing as mp
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from queue import Empty

# IMPORTANT: this file is named telegram.py, which shadows the installed
# python-telegram-bot package named ``telegram``. Temporarily remove this
# script directory from sys.path while importing the real package.
_THIS_DIR = os.path.abspath(os.path.dirname(__file__))
_ORIGINAL_SYS_PATH = list(sys.path)
try:
    sys.path = [
        entry for entry in sys.path
        if os.path.abspath(entry or os.curdir) != _THIS_DIR
    ]
    from telegram import Update
    from telegram.ext import (
        ApplicationBuilder,
        CommandHandler,
        MessageHandler,
        ContextTypes,
        filters,
    )
finally:
    sys.path = _ORIGINAL_SYS_PATH

from scanner import scan_url
from report_generator import build_pdf


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
DEV_NAME = os.getenv("DEV_NAME", "YOUR DEV NAME").strip()
AUTHORIZED_USERS = {
    x.strip()
    for x in os.getenv("AUTHORIZED_USERS", "").split(",")
    if x.strip()
}
MAX_CONCURRENT = max(1, int(os.getenv("MAX_CONCURRENT", "1")))

# Maximum amount of time allowed for the scanner worker process.
# Change on Render with MAX_SCAN_SECONDS, e.g. 300 or 360.
MAX_SCAN_SECONDS = max(30, int(os.getenv("MAX_SCAN_SECONDS", "300")))

# How often Telegram receives a heartbeat while the scanner is running.
HEARTBEAT_SECONDS = max(5, int(os.getenv("HEARTBEAT_SECONDS", "20")))

# Render provides these automatically for Web Services.
RENDER_EXTERNAL_URL = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
PORT = int(os.getenv("PORT", "10000"))
HOST = "0.0.0.0"

WEBHOOK_PATH = os.getenv("TELEGRAM_WEBHOOK_PATH", "/telegram").strip() or "/telegram"
if not WEBHOOK_PATH.startswith("/"):
    WEBHOOK_PATH = "/" + WEBHOOK_PATH

TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
if not TELEGRAM_WEBHOOK_SECRET:
    TELEGRAM_WEBHOOK_SECRET = secrets.token_urlsafe(32).replace("/", "_").replace("+", "-")

URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.I)
MAX_WEBHOOK_BODY = 2 * 1024 * 1024

sem = asyncio.Semaphore(MAX_CONCURRENT)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("web-audit-bot")


# -----------------------------------------------------------------------------
# Scanner worker process
# -----------------------------------------------------------------------------
def _scan_worker(result_queue, url, active_allowed):
    """Run scanner in a separate process so the timeout can actually stop it."""
    try:
        report = scan_url(url, active_allowed)
        result_queue.put(("ok", report))
    except BaseException as exc:
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


def _run_scan_with_timeout(url, active_allowed, timeout_seconds, heartbeat_seconds, heartbeat_cb):
    """Run scan_url in a child process and periodically invoke heartbeat_cb."""
    # fork is available on Linux/Render and avoids re-importing the whole bot.
    # spawn is used as a fallback for platforms without fork.
    try:
        ctx = mp.get_context("fork")
    except ValueError:
        ctx = mp.get_context("spawn")

    result_queue = ctx.Queue(maxsize=1)
    process = ctx.Process(
        target=_scan_worker,
        args=(result_queue, url, active_allowed),
        name="security-scan-worker",
    )
    process.daemon = True
    process.start()

    started = time.monotonic()
    deadline = started + timeout_seconds
    next_heartbeat = started + heartbeat_seconds

    try:
        while True:
            now = time.monotonic()
            remaining = deadline - now

            if remaining <= 0:
                if process.is_alive():
                    log.warning("Scan timeout reached; terminating scanner process")
                    process.terminate()
                    process.join(timeout=5)
                    if process.is_alive():
                        process.kill()
                        process.join(timeout=2)
                raise TimeoutError(
                    f"The security audit exceeded the {timeout_seconds}-second maximum runtime."
                )

            wait_for = min(1.0, remaining)
            try:
                status, payload = result_queue.get(timeout=wait_for)
                if status == "error":
                    raise RuntimeError(payload)
                return payload
            except Empty:
                pass

            now = time.monotonic()
            if now >= next_heartbeat:
                elapsed = int(now - started)
                heartbeat_cb(elapsed, timeout_seconds)
                next_heartbeat = now + heartbeat_seconds

            if not process.is_alive():
                # The worker exited without putting a result in the queue.
                try:
                    status, payload = result_queue.get_nowait()
                except Empty:
                    raise RuntimeError(
                        f"Scanner process stopped unexpectedly (exit code {process.exitcode})."
                    )
                if status == "error":
                    raise RuntimeError(payload)
                return payload
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=3)
        try:
            result_queue.close()
            result_queue.join_thread()
        except Exception:
            pass


# -----------------------------------------------------------------------------
# Telegram helpers
# -----------------------------------------------------------------------------
def user_label(user):
    if not user:
        return "Unknown Telegram user"
    if user.username:
        return f"@{user.username}"
    name = " ".join(x for x in [user.first_name, user.last_name] if x)
    return f"{name} (ID: {user.id})" if name else f"ID: {user.id}"


def authorized(user_id):
    return str(user_id) in AUTHORIZED_USERS


def format_elapsed(seconds):
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


async def safe_edit(message, text):
    try:
        await message.edit_text(text)
    except Exception as exc:
        # Telegram can reject an edit when the text is identical or a request
        # races with another update. Do not kill the scan because of that.
        log.debug("Telegram message edit failed: %s", exc)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    await update.message.reply_text(
        "🔐 Web Security Audit Bot\n\n"
        "Send /scan https://example.com\n"
        "Or simply paste a URL to start the full 60-check audit.\n\n"
        "The bot sends heartbeat updates while a scan is running and stops a "
        f"scan after {MAX_SCAN_SECONDS} seconds if it does not finish.\n\n"
        "Active tests are disabled unless your Telegram ID is explicitly "
        "listed in AUTHORIZED_USERS on the server."
    )


async def run_scan(update: Update, url: str):
    if not update.message:
        return

    user = update.effective_user
    if not user:
        await update.message.reply_text("❌ Could not identify the Telegram user.")
        return

    telegram_user = user_label(user)
    active_allowed = authorized(user.id)

    msg = await update.message.reply_text(
        "🔎 Starting security audit...\n"
        f"Target: {url}\n"
        f"Telegram user: {telegram_user}\n"
        f"Active tests: {'enabled (authorized)' if active_allowed else 'disabled'}\n"
        f"Maximum runtime: {MAX_SCAN_SECONDS}s\n"
        "Progress: 0/60 — starting scanner"
    )

    async with sem:
        started = time.monotonic()

        async def heartbeat(elapsed, maximum):
            # This is a heartbeat rather than a fake per-check counter. The
            # current scanner exposes its 60 results only when scan_url returns.
            await safe_edit(
                msg,
                "🔎 Security audit running...\n"
                f"Target: {url}\n"
                f"Telegram user: {telegram_user}\n\n"
                "Progress: scanner is processing the 60 checks\n"
                f"Elapsed: {format_elapsed(elapsed)} / {format_elapsed(maximum)}\n"
                f"Next heartbeat: {HEARTBEAT_SECONDS}s\n"
                "Status: 🟢 scanner still running"
            )

        def heartbeat_from_worker(elapsed, maximum):
            # Called from the asyncio thread while waiting for the child process.
            future = asyncio.run_coroutine_threadsafe(
                heartbeat(elapsed, maximum), asyncio.get_running_loop()
            )
            try:
                future.result(timeout=10)
            except Exception as exc:
                log.debug("Heartbeat delivery failed: %s", exc)

        try:
            await heartbeat(0, MAX_SCAN_SECONDS)

            # Run the scanner outside the event loop. The scanner itself is
            # isolated in a child process so MAX_SCAN_SECONDS can really stop it.
            report = await asyncio.to_thread(
                _run_scan_with_timeout,
                url,
                active_allowed,
                MAX_SCAN_SECONDS,
                HEARTBEAT_SECONDS,
                heartbeat_from_worker,
            )

            elapsed = int(time.monotonic() - started)
            results = report.get("results", []) if isinstance(report, dict) else []
            check_count = len(results)

            await safe_edit(
                msg,
                "📄 Scan complete.\n"
                f"Progress: {check_count}/60 checks returned\n"
                f"Elapsed: {format_elapsed(elapsed)}\n\n"
                "Generating professional PDF..."
            )

            pdf_path = await asyncio.to_thread(
                build_pdf, report, telegram_user, DEV_NAME
            )

            summary = report.get("summary", {})
            await safe_edit(
                msg,
                "✅ Audit completed\n\n"
                f"Target: {report.get('target', url)}\n"
                f"Checks: {check_count}/60\n"
                f"Elapsed: {format_elapsed(elapsed)}\n"
                f"Findings: {summary.get('findings', 0)}\n"
                f"High: {summary.get('high', 0)} | "
                f"Medium: {summary.get('medium', 0)} | "
                f"Low: {summary.get('low', 0)}\n\n"
                "📎 Sending PDF..."
            )

            with open(pdf_path, "rb") as f:
                await update.message.reply_document(
                    document=f,
                    filename=os.path.basename(pdf_path),
                    caption=f"🔐 Security Audit\nGenerated for {telegram_user}",
                )

        except TimeoutError as exc:
            elapsed = int(time.monotonic() - started)
            log.warning("Audit timed out for %s after %ss", url, elapsed)
            await safe_edit(
                msg,
                "⏱️ Audit stopped by maximum runtime.\n\n"
                f"Target: {url}\n"
                f"Elapsed: {format_elapsed(elapsed)}\n"
                f"Maximum: {format_elapsed(MAX_SCAN_SECONDS)}\n\n"
                "The scanner did not finish within the configured limit. "
                "Increase MAX_SCAN_SECONDS on Render if you want to allow "
                "longer audits."
            )

        except Exception as exc:
            log.exception("Scan failed for %s", url)
            await safe_edit(
                msg,
                f"❌ Scan failed: {type(exc).__name__}: {exc}"
            )


async def scan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    if not context.args:
        await update.message.reply_text("Usage:\n/scan https://example.com")
        return

    url = context.args[0].strip()
    if not URL_RE.match(url):
        await update.message.reply_text("❌ Send a complete http:// or https:// URL.")
        return

    await run_scan(update, url)


async def text_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    text = (update.message.text or "").strip()
    if URL_RE.match(text):
        await run_scan(update, text)
    else:
        await update.message.reply_text(
            "Send a URL like:\nhttps://example.com\n\nor use /scan https://example.com"
        )


# -----------------------------------------------------------------------------
# Render HTTP/Webhook server
# -----------------------------------------------------------------------------
class WebhookHandler(BaseHTTPRequestHandler):
    server_version = "WebAuditHealth/1.1"

    def log_message(self, fmt, *args):
        log.info("HTTP %s - %s", self.address_string(), fmt % args)

    def _send(self, status, body, content_type="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/healthz":
            self._send(200, "ok\n")
            return

        if path == "/":
            self._send(200, "Web Security Audit Bot is running.\n")
            return

        self._send(404, "not found\n")

    def do_HEAD(self):
        path = urlparse(self.path).path
        if path in ("/", "/healthz"):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path

        if path != WEBHOOK_PATH:
            self._send(404, "not found\n")
            return

        supplied_secret = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not secrets.compare_digest(supplied_secret, TELEGRAM_WEBHOOK_SECRET):
            self._send(403, "forbidden\n")
            return

        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "0")
        except ValueError:
            self._send(400, "bad content-length\n")
            return

        if length <= 0 or length > MAX_WEBHOOK_BODY:
            self._send(413, "payload too large\n")
            return

        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, "invalid json\n")
            return

        # Acknowledge Telegram immediately. The scan continues asynchronously.
        self._send(200, "ok\n")

        loop = getattr(self.server, "asyncio_loop", None)
        application = getattr(self.server, "telegram_application", None)
        if loop is None or application is None:
            log.error("Webhook received before Telegram application was ready")
            return

        try:
            update = Update.de_json(payload, application.bot)
            future = asyncio.run_coroutine_threadsafe(
                application.process_update(update), loop
            )
            future.add_done_callback(_log_webhook_future)
        except Exception:
            log.exception("Failed to queue Telegram update")


def _log_webhook_future(future):
    try:
        future.result()
    except Exception:
        log.exception("Telegram update processing failed")


class WebhookHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_http_server(application, loop):
    server = WebhookHTTPServer((HOST, PORT), WebhookHandler)
    server.asyncio_loop = loop
    server.telegram_application = application

    thread = threading.Thread(
        target=server.serve_forever,
        name="render-http-server",
        daemon=True,
    )
    thread.start()
    log.info("HTTP server listening on %s:%s", HOST, PORT)
    return server, thread


# -----------------------------------------------------------------------------
# Application lifecycle
# -----------------------------------------------------------------------------
async def webhook_main():
    if not RENDER_EXTERNAL_URL:
        raise RuntimeError(
            "RENDER_EXTERNAL_URL is missing. This process is configured for "
            "Render Web Service mode."
        )

    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_url))

    await app.initialize()
    await app.start()

    loop = asyncio.get_running_loop()
    server, thread = start_http_server(app, loop)

    webhook_url = f"{RENDER_EXTERNAL_URL}{WEBHOOK_PATH}"
    log.info("Setting Telegram webhook to %s", webhook_url)

    try:
        await app.bot.set_webhook(
            url=webhook_url,
            secret_token=TELEGRAM_WEBHOOK_SECRET,
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=False,
        )
        log.info("Telegram webhook configured successfully")

        stop_event = asyncio.Event()

        def request_stop(*_args):
            loop.call_soon_threadsafe(stop_event.set)

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, request_stop)
            except (NotImplementedError, RuntimeError):
                pass

        await stop_event.wait()

    finally:
        log.info("Shutting down webhook server")
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

        try:
            await app.bot.delete_webhook(drop_pending_updates=False)
        except Exception:
            log.exception("Could not delete Telegram webhook")

        await app.stop()
        await app.shutdown()


def polling_main():
    """Local-development fallback when RENDER_EXTERNAL_URL is not present."""
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_url))
    log.info("RENDER_EXTERNAL_URL not set; using Telegram polling mode")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


def main():
    if not BOT_TOKEN:
        raise RuntimeError("Set BOT_TOKEN in the environment.")

    log.info(
        "Audit runtime limit=%ss, heartbeat=%ss, max concurrent=%s",
        MAX_SCAN_SECONDS,
        HEARTBEAT_SECONDS,
        MAX_CONCURRENT,
    )

    if RENDER_EXTERNAL_URL:
        asyncio.run(webhook_main())
    else:
        polling_main()


if __name__ == "__main__":
    main()
