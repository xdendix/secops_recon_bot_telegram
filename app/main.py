import asyncio
import logging
import datetime
import sentry_sdk
from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery, BufferedInputFile

from app.core.config import TELEGRAM_BOT_TOKEN, SENTRY_DSN
from app.bot.keyboards import get_recon_keyboard
from app.recon.paths import analyze_paths
from app.recon.headers import analyze_headers
from app.recon.cookies import analyze_cookies

# Initialize Sentry for Performance and Error Monitoring
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        traces_sample_rate=1.0,
    )
    logging.info("Sentry SDK successfully initialized.")

if TELEGRAM_BOT_TOKEN is None:
    raise ValueError("TELEGRAM_BOT_TOKEN must be configured")

bot = Bot(token=TELEGRAM_BOT_TOKEN)
dp = Dispatcher()

# --- COMMAND HANDLERS ---


@dp.message(CommandStart())
async def command_start_handler(message: Message) -> None:
    welcome_text = (
        "🛡️ *Welcome to SecOps Recon Bot* 🛡️\n\n"
        "I am your automated cybersecurity assistant. "
        "Simply send me a target URL (e.g., `github.com`) to initiate the reconnaissance modules."
    )
    await message.answer(welcome_text, parse_mode="Markdown")


@dp.message(Command("headers"))
async def command_headers_handler(message: Message) -> None:
    args = (message.text or "").split(maxsplit=1)

    if len(args) < 2:
        await message.answer(
            "⚠️ *Invalid Format!*\nUsage: `/headers <url>`\nExample: `/headers example.com`",
            parse_mode="Markdown",
        )
        return

    target_url = args[1]
    status_msg = await message.answer(
        f"🔍 *Scanning headers* for `{target_url}`...\nPlease wait.",
        parse_mode="Markdown",
    )

    with sentry_sdk.start_transaction(op="bot.command", name="/headers"):
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, analyze_headers, target_url)

        if "success" not in result or not result["success"]:
            error = result.get("error", "Unknown error")
            await status_msg.edit_text(
                f"❌ *Scan Failed*\n`{error}`", parse_mode="Markdown"
            )
            return

        missing = result.get("missing", [])
        missing_text = (
            "✅ *Excellent!* All critical security headers found."
            if not missing
            else "❌ *Missing Security Headers:*\n"
            + "\n".join([f"• `{h}`" for h in missing])
        )

        report = (
            f"🛡️ *SECURITY REPORT*\n"
            f"*Target:* `{result.get('url', target_url)}`\n"
            f"*Status:* `{result.get('status_code', 'Unknown')}`\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"{missing_text}"
        )
        await status_msg.edit_text(report, parse_mode="Markdown")


@dp.message(Command("cookies"))
async def command_cookies_handler(message: Message) -> None:
    args = (message.text or "").split(maxsplit=1)

    if len(args) < 2:
        await message.answer(
            "⚠️ *Invalid Format!*\nUsage: `/cookies <url>`\nExample: `/cookies github.com`",
            parse_mode="Markdown",
        )
        return

    target_url = args[1]
    status_msg = await message.answer(
        f"🔍 *Scanning cookies* for `{target_url}`...\nPlease wait.",
        parse_mode="Markdown",
    )

    with sentry_sdk.start_transaction(op="bot.command", name="/cookies"):
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, analyze_cookies, target_url)

        if not result["success"]:
            await status_msg.edit_text(
                f"❌ *Scan Failed*\n`{result['error']}`", parse_mode="Markdown"
            )
            return

        total = result["total_cookies"]
        insecure = result["insecure_cookies"]

        if total == 0:
            report = f"ℹ️ *No cookies found* on `{result['url']}`."
        elif not insecure:
            report = f"✅ *Excellent!* All {total} cookies have proper security flags."
        else:
            issues_text = "".join(
                [
                    f"• `{cookie['name']}`: {', '.join(cookie['issues'])}\n"
                    for cookie in insecure
                ]
            )
            report = (
                f"🍪 *COOKIE SECURITY REPORT*\n"
                f"*Target:* `{result['url']}`\n"
                f"⚠️ *Vulnerable Cookies:* {len(insecure)}/{total}\n"
                f"━━━━━━━━━━━━━━━━━━\n"
                f"{issues_text}"
            )
        await status_msg.edit_text(report, parse_mode="Markdown")


# --- INTERACTIVE UI HANDLERS (AUTO-DETECT URL) ---


@dp.message(F.text & ~F.text.startswith("/"))
async def handle_target_url(message: Message) -> None:
    target_url = (message.text or "").strip()

    # Basic validation to ensure input resembles a domain or URL
    if "." not in target_url:
        await message.answer(
            "⚠️ *Invalid Target!*\nPlease send a valid domain (e.g., `github.com`)",
            parse_mode="Markdown",
        )
        return

    await message.answer(
        f"*Target:* `{target_url}`\nSelect a reconnaissance module below:",
        reply_markup=get_recon_keyboard(target_url),
        parse_mode="Markdown",
    )


@dp.callback_query(F.data == "cancel")
async def callback_cancel(callback: CallbackQuery) -> None:
    # Type Guard: Ensure the message is accessible before editing
    if isinstance(callback.message, Message):
        await callback.message.edit_text(
            "*Scan Cancelled.* Target discarded.", parse_mode="Markdown"
        )
    await callback.answer()


@dp.callback_query(
    F.data.startswith("hdr|")
    | F.data.startswith("cok|")
    | F.data.startswith("pth|")
    | F.data.startswith("rpt|")
)
async def callback_scan_execute(callback: CallbackQuery) -> None:
    await callback.answer()

    msg = callback.message
    callback_data = callback.data

    if not isinstance(msg, Message) or not callback_data:
        return

    action, target_url = callback_data.split("|", 1)
    status_msg = await msg.reply(
        f"⏳ *Auditing* `{target_url}`...\nPlease wait.", parse_mode="Markdown"
    )
    loop = asyncio.get_running_loop()

    if action == "hdr":
        with sentry_sdk.start_transaction(op="bot.inline", name="scan_headers"):
            result = await loop.run_in_executor(None, analyze_headers, target_url)

            if not result.get("success"):
                await status_msg.edit_text(
                    f"❌ *Audit Failed*\n`{result.get('error', 'Unknown error')}`",
                    parse_mode="Markdown",
                )
                return

            found = result.get("found", [])
            missing = result.get("missing", [])
            total = len(found) + len(missing)

            # Objective Reporting Structure
            report_lines = [
                f"*SECURITY AUDIT*",
                f"*Target:* `{result.get('url')}`",
                f"*Status:* `{result.get('status_code')}`",
                f"━━━━━━━━━━━━━━━━━━",
            ]

            if missing:
                report_lines.append(
                    f"⚠️ *Vulnerable (Missing):* {len(missing)}/{total}"
                )
                report_lines.extend([f"❌ `{h}`" for h in missing])
                report_lines.append("")

            if found:
                report_lines.append(f"✅ *Secured (Found):* {len(found)}/{total}")
                report_lines.extend([f"🛡️ `{h}`" for h in found])

            await status_msg.edit_text("\n".join(report_lines), parse_mode="Markdown")

    elif action == "cok":
        with sentry_sdk.start_transaction(op="bot.inline", name="scan_cookies"):
            result = await loop.run_in_executor(None, analyze_cookies, target_url)

            if not result.get("success"):
                await status_msg.edit_text(
                    f"❌ *Audit Failed*\n`{result.get('error', 'Unknown error')}`",
                    parse_mode="Markdown",
                )
                return

            total = result.get("total_cookies", 0)
            insecure = result.get("insecure_cookies", [])

            report_lines = [
                f"🍪 *COOKIE SECURITY AUDIT*",
                f"*Target:* `{result.get('url')}`",
                f"━━━━━━━━━━━━━━━━━━",
            ]

            if total == 0:
                report_lines.append(
                    "ℹ️ *Result:* No cookies were issued by the server."
                )
            else:
                secure_count = total - len(insecure)
                report_lines.append(f"✅ *Secured Cookies:* {secure_count}/{total}")

                if insecure:
                    report_lines.append(
                        f"⚠️ *Vulnerable Cookies:* {len(insecure)}/{total}"
                    )
                    for cookie in insecure:
                        issues_str = ", ".join(cookie.get("issues", []))
                        report_lines.append(f"❌ `{cookie.get('name')}`: {issues_str}")

            await status_msg.edit_text("\n".join(report_lines), parse_mode="Markdown")

    elif action == "pth":
        with sentry_sdk.start_transaction(op="bot.inline", name="scan_paths"):
            result = await loop.run_in_executor(None, analyze_paths, target_url)

            if not result.get("success"):
                await status_msg.edit_text(
                    f"❌ *Audit Failed*\n`{result.get('error', 'Unknown error')}`",
                    parse_mode="Markdown",
                )
                return

            found_paths = result.get("found_paths", [])

            report_lines = [
                f"📂 *SENSITIVE PATH AUDIT*",
                f"*Target:* `{result.get('url')}`",
                f"━━━━━━━━━━━━━━━━━━",
            ]

            if not found_paths:
                report_lines.append("✅ *Result:* No exposed sensitive paths detected.")
            else:
                report_lines.append(f"⚠️ *Exposed Paths Found:* {len(found_paths)}")
                for path in found_paths:
                    report_lines.append(f"🚨 `{path}`")

            await status_msg.edit_text("\n".join(report_lines), parse_mode="Markdown")

    elif action == "rpt":
        with sentry_sdk.start_transaction(op="bot.inline", name="generate_report"):
            # Enterprise Best Practice: Run all scanners concurrently
            hdr_task = loop.run_in_executor(None, analyze_headers, target_url)
            cok_task = loop.run_in_executor(None, analyze_cookies, target_url)
            pth_task = loop.run_in_executor(None, analyze_paths, target_url)

            # Await all tasks simultaneously for maximum performance
            hdr_res, cok_res, pth_res = await asyncio.gather(
                hdr_task, cok_task, pth_task
            )

            timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )

            # Determine the final URL to display in the report, prioritizing successful scans
            final_url = (
                hdr_res.get("url")
                or cok_res.get("url")
                or pth_res.get("url")
                or target_url
            )

            # Constructing the Markdown Report Objectively
            report_lines = [
                f"# SecOps Enterprise Reconnaissance Report",
                f"**Target:** `{final_url}`",  # Use the most reliable URL from the scans
                f"**Generated:** `{timestamp}`",
                f"---",
                f"## 1. HTTP Security Headers",
            ]

            if hdr_res.get("success"):
                found = hdr_res.get("found", [])
                missing = hdr_res.get("missing", [])
                report_lines.append(f"- **Status Code:** {hdr_res.get('status_code')}")
                report_lines.append(f"- **Secured (Found):** {len(found)}")
                for h in found:
                    report_lines.append(f"  - [x] {h}")
                report_lines.append(f"- **Vulnerable (Missing):** {len(missing)}")
                for h in missing:
                    report_lines.append(f"  - [ ] {h}")
            else:
                report_lines.append(f"> Error: {hdr_res.get('error')}")

            report_lines.extend(["", "## 2. Cookie Security Flags"])
            if cok_res.get("success"):
                total = cok_res.get("total_cookies", 0)
                insecure = cok_res.get("insecure_cookies", [])
                report_lines.append(f"- **Total Cookies:** {total}")
                if total > 0:
                    report_lines.append(f"- **Vulnerable Cookies:** {len(insecure)}")
                    for c in insecure:
                        issues_str = ", ".join(c.get("issues", []))
                        report_lines.append(f"  - [ ] `{c.get('name')}`: {issues_str}")
            else:
                report_lines.append(f"> Error: {cok_res.get('error')}")

            report_lines.extend(["", "## 3. Sensitive Path Exposure"])
            if pth_res.get("success"):
                found_paths = pth_res.get("found_paths", [])
                report_lines.append(f"- **Exposed Paths Detected:** {len(found_paths)}")
                for p in found_paths:
                    report_lines.append(f"  - [!] `{p}`")
            else:
                report_lines.append(f"> Error: {pth_res.get('error')}")

            report_md = "\n".join(report_lines)

            # In-Memory File Generation (Zero Disk I/O)
            file_bytes = report_md.encode("utf-8")
            safe_filename = (
                target_url.replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
            )
            document = BufferedInputFile(
                file_bytes, filename=f"Audit_{safe_filename}.md"
            )

            # Delete the "Auditing..." message and send the physical document
            await status_msg.delete()
            await msg.reply_document(
                document=document,
                caption=f"📄 *Enterprise Audit Report* generated for `{target_url}`",
                parse_mode="Markdown",
            )


# --- APPLICATION ENTRY POINT ---


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting SecOps Recon Bot service...")

    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Bot service stopped gracefully.")
