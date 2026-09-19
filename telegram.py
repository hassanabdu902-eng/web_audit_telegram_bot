import os
import re
import asyncio
import json
import logging
import secrets
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

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

# Render provides these automatically for Web Services.
RENDER_EXTERNAL_URL = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
PORT = int(os.getenv("PORT", "10000"))
HOST = "0.0.0.0"

# Webhook path/header protection. Set TELEGRAM_WEBHOOK_SECRET in Render if you
# want a stable secret; otherwise a random secret is generated at startup.
WEBHOOK_PATH = os.getenv("TELEGRAM_WEBHOOK_PATH", "/telegram").strip() or "/telegram"
if not WEBHOOK_PATH.startswith("/"):
    WEBHOOK_PATH = "/" + WEBHOOK_PATH
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
if not TELEGRAM_WEBHOOK_SECRET:
    TELEGRAM_WEBHOOK_SECRET = secrets.token_urlsafe(32).replace("/", "_").replace("+", "-")

# Only accept normal HTTP(S) URLs. This is deliberately conservative.
URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.I)

MAX_WEBHOOK_BODY = 2 * 1024 * 1024  # 2 MiB

sem = asyncio.Semaphore(MAX_CONCURRENT)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("web-audit-bot")


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
    # Empty AUTHORIZED_USERS means active checks remain disabled.
    return str(user_id) in AUTHORIZED_USERS


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    await update.message.reply_text(
        "🔐 Web Security Audit Bot\n\n"
        "Send /scan https://example.com\n"
        "Or simply paste a URL to start the full 60-check audit.\n\n"
        "The report includes HTTP status evidence, admin/cPanel discovery, "
        "ports, DNS, TLS, headers, backups and other exposure checks. "
        "Requests are paced by the scanner configuration.\n\n"
        "Active tests are disabled unless your Telegram ID is explicitly "
        "listed in AUTHORIZED_USERS on the server."
    )


async def run_scan(update: Update, url: str):
    """Run one audit without blocking the Telegram event loop."""
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
        f"Active tests: {'enabled (authorized)' if active_allowed else 'disabled'}"
    )

    async with sem:
        try:
            # Scanner is synchronous, so keep it off the asyncio event loop.
            report = await asyncio.to_thread(scan_url, url, active_allowed)

            await msg.edit_text("📄 Scan complete. Generating PDF...")
            pdf_path = await asyncio.to_thread(
                build_pdf, report, telegram_user, DEV_NAME
            )

            summary = report.get("summary", {})
            await update.message.reply_text(
                "✅ Audit completed\n\n"
                f"Target: {report.get('target')}\n"
                f"Checks: {len(report.get('results', []))}\n"
                f"Findings: {summary.get('findings', 0)}\n"
                f"High: {summary.get('high', 0)} | "
                f"Medium: {summary.get('medium', 0)} | "
                f"Low: {summary.get('low', 0)}"
            )

            with open(pdf_path, "rb") as f:
                await update.message.reply_document(
                    document=f,
                    filename=os.path.basename(pdf_path),
                    caption=f"🔐 Security Audit\nGenerated for {telegram_user}",
                )

        except Exception as exc:
            log.exception("Scan failed for %s", url)
            try:
                await msg.edit_text(
                    f"❌ Scan failed: {type(exc).__name__}: {exc}"
                )
            except Exception:
                pass


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
    """Small stdlib HTTP server so no extra web framework is required."""

    server_version = "WebAuditHealth/1.0"

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

        # Telegram sends this header when set_webhook(secret_token=...) is used.
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

        # Acknowledge Telegram immediately. The actual update is processed by
        # the asyncio event loop so Telegram never waits for a long scan.
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

    if RENDER_EXTERNAL_URL:
        asyncio.run(webhook_main())
    else:
        polling_main()


if __name__ == "__main__":
    main()
