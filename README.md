# OSINT Tree Telegram Bot

Telegram bot built with Python 3.10+ and aiogram 3.x.

This repository is a safe demo: search results are synthetic/mock data only.
It does not connect to leaked databases, credential dumps, private datasets,
doxxing services, or other unauthorized sources.

## Run

1. Create a bot with BotFather and copy the token.
2. Create a .env file:
   BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
3. Install:
   python -m pip install -r requirements.txt
4. Start:
   python osint_bot.py

The bot supports /start, /help, typed searches, Unicode tree rendering,
refresh, JSON export and starting a new search.
