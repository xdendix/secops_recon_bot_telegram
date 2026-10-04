import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
SENTRY_DSN = os.getenv("SENTRY_DSN")

# Enterprise best practice: Fail fast if critical configurations are missing
if not TELEGRAM_BOT_TOKEN:
    raise ValueError(
        "CRITICAL ERROR: TELEGRAM_BOT_TOKEN is missing in the environment variables."
    )
