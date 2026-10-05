from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton


def get_recon_keyboard(target_url: str) -> InlineKeyboardMarkup:
    """
    Generates an inline keyboard for the reconnaissance modules.
    Truncates the URL to safely comply with Telegram's 64-byte callback_data limit.
    """
    safe_url = target_url[:40]

    keyboard = [
        [
            InlineKeyboardButton(text="🔍 Headers", callback_data=f"hdr|{safe_url}"),
            InlineKeyboardButton(text="🍪 Cookies", callback_data=f"cok|{safe_url}"),
            InlineKeyboardButton(text="📂 Paths", callback_data=f"pth|{safe_url}"),
        ],
        [
            InlineKeyboardButton(
                text="📄 Generate Full Report", callback_data=f"rpt|{safe_url}"
            )
        ],
        [InlineKeyboardButton(text="Cancel", callback_data="cancel")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=keyboard)
