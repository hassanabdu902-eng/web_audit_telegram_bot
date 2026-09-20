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
from queue import Empty
from urllib.parse import urlparse

# This file is named telegram.py, which can shadow the python-telegram-bot
# package. Temporarily remove this directory from sys.path while importing it.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_saved_sys_path = list(sys.path)
try:
    sys.path = [p for p in sys.path if os.path.abspath(p or os.curdir) != _THIS_DIR]
    from telegram import Update
    from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
finally:
    sys.path = _saved_sys_path

from scanner import scan_url
from report_generator import build_pdf


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
DEV_NAME = os.getenv("DEV_NAME", "YOUR DEV NAME").strip()

AUTHORIZED_USERS = {
    x.strip()
    for x in os.getenv("AUTHORIZED_USERS", "").split(",")
    if x.strip()
}

MAX_CONCURRENT = max(1, int(os.getenv("MAX_CONCURRENT", "1")))
MAX_SCAN_SECONDS = max(30, int(os.getenv("MAX_SCAN_SECONDS", "360")))
HEARTBEAT_SECONDS = max(5, int(os.getenv("HEARTBEAT_SECONDS", "20")))

HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "10000"))

RENDER_EXTERNAL_URL = os.getenv("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
WEBHOOK_PATH = os.getenv("TELEGRAM_WEBHOOK_PATH", "/telegram").strip()
if not WEBHOOK_PATH.startswith("/"):
    WEBHOOK_PATH = "/" + WEBHOOK_PATH

TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
if not TELEGRAM_WEBHOOK_SECRET:
    # A random process-local secret is safe for development/fallback mode.
    # For a stable Render webhook, set TELEGRAM_WEBHOOK_SECRET in the service.
    TELEGRAM_WEBHOOK_SECRET = secrets.token_urlsafe(32)

MAX_WEBHOOK_BODY = 2 * 1024 * 1024

URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)

SCAN_LIMITER = None
BACKGROUND_TASKS = set()
ACTIVE_CHATS = set()

HTTP_SERVER = None
HTTP_THREAD = None
TELEGRAM_APPLICATION = None
ASYNCIO_LOOP = None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("security-audit-bot")


# ---------------------------------------------------------------------------
# Progress labels
# ---------------------------------------------------------------------------

PROGRESS_NAMES = [
    "DNS Lookup",
    "Security Headers",
    "TLS Analysis",
    "Subdomain Scan",
    "Admin Panels",
    "Port Scan",
    "HTTP Methods",
    "Technology Detection",
    "Cookie Security",
    "CORS Configuration",
    "Directory Listing",
    "Sensitive Files",
    "API Endpoints",
    "Source Code Analysis",
    "Login Security",
    "Security.txt",
    "Backup Files",
    "Server Disclosure",
    "Sensitive Data",
    "Subdomain Takeover",
    "HSTS Quality",
    "CSP Quality",
    "TLS Protocols",
    "TLS Certificate",
    "TLS Cipher Review",
    "DNSSEC",
    "CAA Record",
    "MX Records",
    "SPF Quality",
    "DMARC Quality",
    "Sitemap Exposure",
    "Redirect Security",
    "Mixed Content",
    "External Resource Integrity",
    "Cache-Control Security",
    "Information Disclosure Headers",
    "API Documentation",
    "WAF Detection",
    "WHOIS",
    "IP Geolocation",
    "Robots.txt",
    "WordPress Users",
    "XML-RPC",
    "WordPress Plugins",
    "WordPress Version",
    "Email Security",
    "CT Logs",
    "Wayback",
    "CVE Check",
    "Phishing Detection",
    "Trust Analysis",
    "CRLF",
    "Open Redirect",
    "Clickjacking",
    "VCS Exposure",
    "Command Injection",
    "File Inclusion",
    "SQL Injection",
    "XSS Test",
    "Final Analysis",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def user_label(user):
    if not user:
        return "Unknown user"
    if getattr(user, "username", None):
        return f"@{user.username}"
    name = " ".join(
        x for x in [
            getattr(user, "first_name", None),
            getattr(user, "last_name", None),
        ]
        if x
    ).strip()
    if name:
        return f"{name} (ID {user.id})"
    return f"ID {user.id}"


def is_authorized(user_id):
    return str(user_id) in AUTHORIZED_USERS


def format_elapsed(seconds):
    seconds = max(0, int(seconds))
    minutes, seconds = divmod(seconds, 60)
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


async def safe_edit(message, text):
    try:
        await message.edit_text(text)
    except Exception as exc:
        logger.debug("Telegram edit failed: %s", exc)


def add_background_task(coro):
    task = asyncio.create_task(coro)
    BACKGROUND_TASKS.add(task)

    def _done(t):
        BACKGROUND_TASKS.discard(t)
        try:
            exc = t.exception()
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.exception("Could not inspect background task: %s", e)
            return
        if exc:
            logger.exception("Background task failed", exc_info=exc)

    task.add_done_callback(_done)
    return task


def extract_url(text):
    if not text:
        return None
    candidate = text.strip().split()[0]
    if URL_RE.match(candidate):
        return candidate
    return None


# ---------------------------------------------------------------------------
# Scanner process isolation
# ---------------------------------------------------------------------------

def _scan_worker(result_queue, url, active_allowed):
    try:
        report = scan_url(url, active_allowed)
        result_queue.put(("ok", report))
    except Exception as exc:
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


def _run_scan_with_timeout(url, active_allowed, timeout_seconds, heartbeat_callback=None):
    """
    Run the scanner in a separate process so a slow/hung scanner cannot block
    the Telegram event loop or the web server.

    heartbeat_callback is called from the worker thread periodically.
    """
    if os.name == "posix":
        try:
            ctx = mp.get_context("fork")
        except ValueError:
            ctx = mp.get_context()
    else:
        ctx = mp.get_context("spawn")

    result_queue = ctx.Queue()
    process = ctx.Process(
        target=_scan_worker,
        args=(result_queue, url, active_allowed),
        daemon=True,
    )

    started = time.monotonic()
    last_heartbeat = started
    process.start()

    try:
        while True:
            now = time.monotonic()
            elapsed = now - started

            if heartbeat_callback and now - last_heartbeat >= HEARTBEAT_SECONDS:
                try:
                    heartbeat_callback(elapsed)
                except Exception:
                    logger.exception("Heartbeat callback failed")
                last_heartbeat = now

            try:
                status, payload = result_queue.get(timeout=1.0)
                if status == "ok":
                    return payload
                raise RuntimeError(payload)
            except Empty:
                pass

            if not process.is_alive():
                # The process exited without putting a result.
                try:
                    status, payload = result_queue.get_nowait()
                    if status == "ok":
                        return payload
                    raise RuntimeError(payload)
                except Empty:
                    exit_code = process.exitcode
                    raise RuntimeError(
                        f"Scanner process exited without a report "
                        f"(exit code {exit_code})."
                    )

            if elapsed >= timeout_seconds:
                raise TimeoutError(
                    f"Scan exceeded MAX_SCAN_SECONDS={timeout_seconds}."
                )
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=3)
            if process.is_alive():
                try:
                    process.kill()
                except AttributeError:
                    pass
                process.join(timeout=2)
        else:
            process.join(timeout=1)

        try:
            result_queue.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Telegram handlers
# ---------------------------------------------------------------------------

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    active_state = (
        "Active/high-impact checks are enabled for your Telegram ID."
        if is_authorized(update.effective_user.id)
        else "Active/high-impact checks are disabled for your Telegram ID."
    )

    await update.message.reply_text(
        "🛡️ Security Audit Bot\n\n"
        "Send a URL or use:\n"
        "/scan https://example.com\n"
        "/status\n"
        "/help\n\n"
        "The audit runs in the background so Telegram stays responsive.\n"
        "Only scan systems you are authorized to assess.\n\n"
        f"{active_state}"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start_command(update, context)


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    await update.message.reply_text(
        "📊 Bot status\n\n"
        f"Active scans: {len(ACTIVE_CHATS)}\n"
        f"Maximum concurrent scans: {MAX_CONCURRENT}\n"
        f"Scan timeout: {MAX_SCAN_SECONDS}s\n"
        f"Heartbeat: every {HEARTBEAT_SECONDS}s\n"
        f"Background tasks: {len(BACKGROUND_TASKS)}"
    )


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    if not context.args:
        await update.message.reply_text(
            "Usage:\n/scan https://example.com"
        )
        return

    url = context.args[0].strip()

    if not URL_RE.match(url):
        await update.message.reply_text(
            "❌ Please provide a valid HTTP/HTTPS URL."
        )
        return

    add_background_task(run_scan(update, url))


async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    url = extract_url(update.message.text)
    if url:
        add_background_task(run_scan(update, url))
        return

    await update.message.reply_text(
        "Send an HTTP/HTTPS URL to start an audit.\n"
        "Example: https://example.com\n\n"
        "Or use /scan https://example.com"
    )


# ---------------------------------------------------------------------------
# Scan workflow
# ---------------------------------------------------------------------------

async def run_scan(update: Update, url: str):
    if not update.message:
        return

    user = update.effective_user
    chat_id = update.effective_chat.id if update.effective_chat else update.message.chat_id

    if chat_id in ACTIVE_CHATS:
        await update.message.reply_text(
            "⏳ A scan is already running in this chat. "
            "Please wait for it to finish."
        )
        return

    ACTIVE_CHATS.add(chat_id)
    started = time.monotonic()

    status_message = None

    try:
        active_allowed = is_authorized(user.id)

        status_message = await update.message.reply_text(
            "🔎 Security Audit\n\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "Progress: starting\n"
            "━━━━━━━━━━━━━━━━━━\n\n"
            "🔄 Starting scanner\n"
            "⏳ Please wait...\n\n"
            "Elapsed: 0s"
        )

        if SCAN_LIMITER is None:
            raise RuntimeError("Scan limiter is not initialized.")

        await SCAN_LIMITER.acquire()

        try:
            async def heartbeat(elapsed):
                # The scanner currently returns the complete report rather
                # than per-check events. Therefore this is deliberately an
                # estimate and never claims exact checks are complete.
                estimated = min(
                    len(PROGRESS_NAMES) - 1,
                    max(1, int((elapsed / max(1, MAX_SCAN_SECONDS)) * len(PROGRESS_NAMES))),
                )
                recent = PROGRESS_NAMES[max(0, estimated - 4):estimated]

                lines = [
                    "🔎 Security Audit",
                    "",
                    "━━━━━━━━━━━━━━━━━━",
                    f"Progress: ~{estimated}/{len(PROGRESS_NAMES)} checks",
                    "━━━━━━━━━━━━━━━━━━",
                    "",
                    "🔄 Scanner is still running",
                ]

                if recent:
                    lines.append("")
                    lines.append("Recent activity:")
                    for name in recent:
                        lines.append(f"• {name}")

                lines.extend([
                    "",
                    f"⏱ Elapsed: {format_elapsed(elapsed)}",
                    f"⏳ Timeout: {format_elapsed(MAX_SCAN_SECONDS)}",
                ])

                await safe_edit(status_message, "\n".join(lines))

            def heartbeat_from_thread(elapsed):
                if ASYNCIO_LOOP is None:
                    return
                try:
                    asyncio.run_coroutine_threadsafe(
                        heartbeat(elapsed),
                        ASYNCIO_LOOP,
                    )
                except Exception:
                    logger.debug("Could not schedule heartbeat", exc_info=True)

            try:
                report = await asyncio.to_thread(
                    _run_scan_with_timeout,
                    url,
                    active_allowed,
                    MAX_SCAN_SECONDS,
                    heartbeat_from_thread,
                )
            except TimeoutError as exc:
                await safe_edit(
                    status_message,
                    "⏱ Scan timed out\n\n"
                    f"Target: {url}\n"
                    f"Limit: {format_elapsed(MAX_SCAN_SECONDS)}\n\n"
                    "The scanner process was stopped so Telegram remains responsive."
                )
                return

            elapsed = time.monotonic() - started

            if not isinstance(report, dict):
                raise RuntimeError("Scanner returned an invalid report.")

            results = report.get("results", [])
            if not isinstance(results, list):
                results = []

            await safe_edit(
                status_message,
                "✅ Scan complete\n\n"
                f"Target: {url}\n"
                f"Checks returned: {len(results)}\n"
                f"Elapsed: {format_elapsed(elapsed)}\n\n"
                "📄 Generating professional PDF report..."
            )

            # PDF creation can also be CPU/file heavy, so keep it away from
            # the Telegram event loop.
            pdf_path = await asyncio.to_thread(
                build_pdf,
                report,
                user_label(user),
                DEV_NAME,
            )

            summary = report.get("summary", {})
            if not isinstance(summary, dict):
                summary = {}

            findings = summary.get("findings")
            high = summary.get("high")
            medium = summary.get("medium")
            low = summary.get("low")

            summary_lines = [
                "🛡️ Security Audit Complete",
                "",
                f"🌐 Target: {url}",
                f"👤 User: {user_label(user)}",
                f"⏱ Duration: {format_elapsed(elapsed)}",
                "",
                "📊 Summary",
            ]

            if findings is not None:
                summary_lines.append(f"Findings: {findings}")
            if high is not None:
                summary_lines.append(f"High: {high}")
            if medium is not None:
                summary_lines.append(f"Medium: {medium}")
            if low is not None:
                summary_lines.append(f"Low: {low}")

            summary_lines.extend([
                "",
                "📎 PDF report is attached below."
            ])

            await safe_edit(status_message, "\n".join(summary_lines))

            try:
                with open(pdf_path, "rb") as document:
                    await update.message.reply_document(
                        document=document,
                        filename=os.path.basename(pdf_path),
                        caption=(
                            "🛡️ Security Audit Report\n"
                            f"Target: {url}\n"
                            f"Generated by: {DEV_NAME}"
                        ),
                    )
            finally:
                # Render's filesystem is ephemeral. Remove the generated
                # report after Telegram has received it.
                try:
                    os.remove(pdf_path)
                except OSError:
                    pass

        finally:
            SCAN_LIMITER.release()

    except asyncio.CancelledError:
        if status_message:
            await safe_edit(
                status_message,
                "🛑 Scan cancelled."
            )
        raise

    except Exception as exc:
        logger.exception("Scan failed for %s", url)
        if status_message:
            await safe_edit(
                status_message,
                "❌ Scan failed\n\n"
                f"Target: {url}\n"
                f"Error: {type(exc).__name__}: {exc}"
            )
        else:
            try:
                await update.message.reply_text(
                    f"❌ Scan failed: {type(exc).__name__}: {exc}"
                )
            except Exception:
                pass

    finally:
        ACTIVE_CHATS.discard(chat_id)


# ---------------------------------------------------------------------------
# Webhook HTTP server
# ---------------------------------------------------------------------------

class WebhookHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send_text(self, status_code, body):
        body_bytes = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, fmt, *args):
        logger.info("HTTP %s - %s", self.address_string(), fmt % args)

    def do_HEAD(self):
        if self.path in ("/", "/healthz"):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/healthz":
            self._send_text(200, "ok\n")
            return

        if parsed.path == "/":
            self._send_text(200, "Security audit bot is running.\n")
            return

        self._send_text(404, "not found\n")

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path != WEBHOOK_PATH:
            self._send_text(404, "not found\n")
            return

        provided_secret = self.headers.get(
            "X-Telegram-Bot-Api-Secret-Token",
            "",
        )

        if not secrets.compare_digest(
            provided_secret,
            TELEGRAM_WEBHOOK_SECRET,
        ):
            self._send_text(403, "forbidden\n")
            return

        content_length = self.headers.get("Content-Length")

        try:
            length = int(content_length or "0")
        except ValueError:
            self._send_text(400, "invalid content length\n")
            return

        if length <= 0:
            self._send_text(400, "empty body\n")
            return

        if length > MAX_WEBHOOK_BODY:
            self._send_text(413, "payload too large\n")
            return

        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))

            if not isinstance(payload, dict):
                raise ValueError("Telegram update must be a JSON object.")

            logger.info("📥 Telegram webhook received")

            application = TELEGRAM_APPLICATION
            loop = ASYNCIO_LOOP

            if application is None or loop is None:
                raise RuntimeError("Telegram application is not ready.")

            update = Update.de_json(payload, application.bot)

            # Put the update into PTB's queue and return immediately.
            # Telegram webhook processing therefore never waits for the
            # potentially multi-minute scanner.
            future = asyncio.run_coroutine_threadsafe(
                application.update_queue.put(update),
                loop,
            )
            future.result(timeout=5)

            self._send_text(200, "ok\n")

        except Exception as exc:
            logger.exception("Webhook processing failed: %s", exc)
            try:
                self._send_text(500, "internal error\n")
            except Exception:
                pass


class WebhookHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_http_server(application, loop):
    global HTTP_SERVER, HTTP_THREAD, TELEGRAM_APPLICATION, ASYNCIO_LOOP

    TELEGRAM_APPLICATION = application
    ASYNCIO_LOOP = loop

    HTTP_SERVER = WebhookHTTPServer(
        (HOST, PORT),
        WebhookHandler,
    )

    HTTP_THREAD = threading.Thread(
        target=HTTP_SERVER.serve_forever,
        name="webhook-http-server",
        daemon=True,
    )
    HTTP_THREAD.start()

    logger.info("HTTP server listening on %s:%s", HOST, PORT)


# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

def register_handlers(application):
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("scan", scan_command))

    application.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            text_handler,
        )
    )


async def webhook_main():
    global SCAN_LIMITER

    if not RENDER_EXTERNAL_URL:
        raise RuntimeError(
            "RENDER_EXTERNAL_URL is required for webhook mode."
        )

    SCAN_LIMITER = asyncio.Semaphore(MAX_CONCURRENT)

    application = ApplicationBuilder().token(BOT_TOKEN).build()
    register_handlers(application)

    await application.initialize()
    await application.start()

    start_http_server(application, asyncio.get_running_loop())

    webhook_url = f"{RENDER_EXTERNAL_URL}{WEBHOOK_PATH}"

    logger.info("Setting Telegram webhook: %s", webhook_url)

    await application.bot.set_webhook(
        url=webhook_url,
        secret_token=TELEGRAM_WEBHOOK_SECRET,
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=False,
        max_connections=40,
    )

    info = await application.bot.get_webhook_info()

    logger.info(
        "Webhook configured | url=%s | pending=%s | last_error=%s",
        info.url,
        info.pending_update_count,
        info.last_error_message,
    )

    stop_event = asyncio.Event()

    def request_stop():
        logger.info("Shutdown signal received.")
        stop_event.set()

    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_stop)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        await stop_event.wait()
    finally:
        logger.info("Shutting down...")

        if HTTP_SERVER is not None:
            try:
                HTTP_SERVER.shutdown()
            except Exception:
                logger.exception("HTTP server shutdown failed.")

        if HTTP_THREAD is not None:
            HTTP_THREAD.join(timeout=5)

        try:
            await application.bot.delete_webhook(drop_pending_updates=False)
        except Exception:
            logger.exception("Could not delete webhook.")

        for task in list(BACKGROUND_TASKS):
            task.cancel()

        if BACKGROUND_TASKS:
            await asyncio.gather(
                *BACKGROUND_TASKS,
                return_exceptions=True,
            )

        await application.stop()
        await application.shutdown()


def polling_main():
    global SCAN_LIMITER

    SCAN_LIMITER = asyncio.Semaphore(MAX_CONCURRENT)

    application = ApplicationBuilder().token(BOT_TOKEN).build()
    register_handlers(application)

    logger.info("Starting polling mode.")

    application.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=False,
    )


def main():
    if not BOT_TOKEN:
        raise RuntimeError(
            "BOT_TOKEN is missing. Set BOT_TOKEN in the environment."
        )

    logger.info("Security audit bot starting.")
    logger.info("Authorized users configured: %d", len(AUTHORIZED_USERS))
    logger.info("Max concurrent scans: %d", MAX_CONCURRENT)
    logger.info("Max scan seconds: %d", MAX_SCAN_SECONDS)

    if RENDER_EXTERNAL_URL:
        logger.info("Webhook mode enabled.")
        asyncio.run(webhook_main())
    else:
        logger.info(
            "RENDER_EXTERNAL_URL is not set; using polling mode."
        )
        polling_main()


if __name__ == "__main__":
    main()
