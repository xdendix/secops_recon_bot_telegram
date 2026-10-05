# SecOps Recon Bot

An automated, asynchronous Telegram bot designed for enterprise-grade web reconnaissance and objective security auditing. Built as a submission for the MLH Community Event.

## Overview

SecOps Recon Bot is a Red Teaming and Web Security utility that allows security analysts to perform rapid, concurrent reconnaissance directly from Telegram. It is engineered with strict type checking, robust error handling, and Application Performance Monitoring (APM) to ensure production-level stability.

## Core Capabilities

* **HTTP Security Headers Audit:** Objectively analyzes critical security headers (e.g., HSTS, CSP, X-Frame-Options) with automatic protocol fallback (HTTPS to HTTP) and final URL resolution.
* **Cookie Security Flag Inspector:** Scans target responses for missing `Secure` and `HttpOnly` flags on session cookies.
* **Sensitive Path Scanner (Dir-Buster Lite):** Utilizes thread-pooling to concurrently brute-force common administrative endpoints and sensitive files (e.g., `.env`, `robots.txt`, `.git/HEAD`) while intentionally filtering out generic 301/302 catch-all redirects to eliminate false positives.
* **In-Memory Report Generation:** Concurrently executes all scanning modules and compiles the results into a downloadable, elegantly formatted Markdown document using Zero Disk I/O.

## Technical Architecture

To meet enterprise standards, this project implements several key architectural decisions:
* **Asynchronous Core:** Powered by `aiogram` 3.x for non-blocking Telegram update polling.
* **Thread Pool Execution:** Synchronous I/O bounds (like `requests`) are offloaded to `asyncio.get_running_loop().run_in_executor()` to prevent the Telegram bot from hanging during heavy network scans.
* **Strict Type Guarding:** Enforced `TypedDict` and variable type guarding to ensure 100% compliance with Pylance strict type checking.
* **Distributed Tracing & APM:** Fully integrated with `sentry-sdk`. Every bot command, inline callback, and HTTP request is wrapped in Sentry Transactions and Spans for real-time performance monitoring.

## Prerequisites

* Python 3.10 or higher
* A Telegram Bot Token (obtained from [@BotFather](https://t.me/BotFather))
* A Sentry DSN (for performance and error tracking)

## Installation

1. **Clone the repository**
   ```bash
   git clone [https://github.com/yourusername/secops-recon-bot.git](https://github.com/yourusername/secops-recon-bot.git)
   cd secops-recon-bot
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. **Install the dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**
   Create a `.env` file in the root directory and define the following variables:
   ```env
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
   SENTRY_DSN=your_sentry_dsn_here
   ```

## Usage

Start the bot service:
   ```bash
   python -m app.main
   ```

Once running, interact with the bot on Telegram:
1. Send `/start` to initialize.
2. Submit any target domain (e.g., `github.com` or `https://example.com`).
3. Use the interactive Inline Keyboard to run individual modules or generate a full Markdown report.

## Disclaimer

This tool is developed strictly for educational purposes, ethical hacking, and authorized security auditing. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.