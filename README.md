# OSINT Tree Telegram Bot

Telegram bot built with Python 3.10+ and aiogram 3.x.

## Maltego backend

The bot calls a configured Maltego Transform Server endpoint and converts the
returned Maltego entities into the Unicode tree shown in Telegram.

The configured transform determines the actual data source and permissions.
Use only transforms and data sources you are authorized to use.

The bot itself does not ship with leaked/private databases.

## Configure

Copy `.env.example` to `.env` and set:

```
BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
MALTEGO_TRANSFORM_URL=https://your-transform-host/run/yourtransform/
```

For separate transforms use:
`MALTEGO_PHONE_TRANSFORM_URL`,
`MALTEGO_EMAIL_TRANSFORM_URL`,
`MALTEGO_IP_TRANSFORM_URL`,
`MALTEGO_USERNAME_TRANSFORM_URL`.

The bot sends the documented Maltego XML transform request format and parses
the returned entities. Some transforms require provider-specific credentials.

## Run

```
python -m pip install -r requirements.txt
python osint_bot.py
```

Send an email, phone number, IP address, or username as a normal Telegram
message.
