import asyncio
import html
import ipaddress
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterator

from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command
from aiogram.types import (
    CallbackQuery,
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set in .env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("osint_bot")

router = Router()

# Demo-only storage. Nothing is written to a database.
LAST_RESULTS: dict[int, dict[str, Any]] = {}
LAST_QUERIES: dict[int, str] = {}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().-]{5,20}$")
USERNAME_RE = re.compile(r"^@?[A-Za-z0-9_.-]{3,64}$")


def classify_query(query: str) -> str:
    value = query.strip()

    try:
        ipaddress.ip_address(value)
        return "IP"
    except ValueError:
        pass

    if EMAIL_RE.fullmatch(value):
        return "Email"

    digits = re.sub(r"\D", "", value)
    if PHONE_RE.fullmatch(value) and 7 <= len(digits) <= 15:
        return "Phone"

    if USERNAME_RE.fullmatch(value):
        return "Username"

    return "Text"


async def search_osint(query: str) -> dict[str, Any]:
    """
    Safe synthetic/demo search.

    This function intentionally does NOT query leaked databases, private
    datasets, credential dumps, doxxing services, or unauthorized sources.
    Replace it only with lawful/public APIs or data owned by the user.
    """
    query = query.strip()
    kind = classify_query(query)

    result: dict[str, Any] = {
        "target": {
            "query": query,
            "type": kind,
        },
        "summary": {
            "status": "demo",
            "source": "synthetic/mock data",
            "note": "No private or leaked databases are queried.",
        },
    }

    if kind == "Email":
        result["email"] = {
            "value": query,
            "normalized": query.lower(),
            "public_sources": [],
            "breaches": {
                "checked": False,
                "reason": "Demo mode: no breach databases are queried.",
            },
        }
    elif kind == "Phone":
        result["phone"] = {
            "value": query,
            "normalized": re.sub(r"[^\d+]", "", query),
            "country": "not determined in demo mode",
            "public_sources": [],
        }
    elif kind == "IP":
        ip = ipaddress.ip_address(query)
        result["ip"] = {
            "address": query,
            "version": ip.version,
            "private": ip.is_private,
            "reserved": ip.is_reserved,
            "location": {
                "country": "not looked up",
                "city": "not looked up",
            },
        }
    elif kind == "Username":
        result["username"] = {
            "value": query.lstrip("@"),
            "public_profiles": [],
            "note": "Profile enumeration is disabled in demo mode.",
        }
    else:
        result["text"] = {
            "value": query,
            "matches": [],
        }

    await asyncio.sleep(0)
    return result


EMOJI_BY_KEY = {
    "target": "🎯",
    "phone": "📱",
    "email": "📧",
    "name": "👤",
    "username": "👤",
    "breaches": "🔑",
    "ip": "🌐",
    "location": "📍",
}


def label_for_key(key: str) -> str:
    return f"{EMOJI_BY_KEY.get(key.lower(), '•')} {key}"


def tree_generator(value: Any, prefix: str = "") -> Iterator[str]:
    """Recursively convert nested dict/list/scalars into a Unicode tree."""
    if isinstance(value, dict):
        items = list(value.items())
        for index, (key, child) in enumerate(items):
            last = index == len(items) - 1
            branch = "└── " if last else "├── "
            yield f"{prefix}{branch}{label_for_key(str(key))}"
            child_prefix = prefix + ("    " if last else "│   ")
            if isinstance(child, (dict, list)):
                yield from tree_generator(child, child_prefix)
            else:
                yield f"{child_prefix}└── {child}"
    elif isinstance(value, list):
        for index, child in enumerate(value):
            last = index == len(value) - 1
            branch = "└── " if last else "├── "
            yield f"{prefix}{branch}[{index}]"
            child_prefix = prefix + ("    " if last else "│   ")
            if isinstance(child, (dict, list)):
                yield from tree_generator(child, child_prefix)
            else:
                yield f"{child_prefix}└── {child}"
    else:
        yield f"{prefix}└── {value}"


def render_tree(data: dict[str, Any]) -> str:
    lines = list(tree_generator(data))
    return "\n".join(lines)


def split_text(text: str, limit: int = 3900) -> list[str]:
    if len(text) <= limit:
        return [text]

    parts: list[str] = []
    current = ""
    for line in text.splitlines(True):
        if len(current) + len(line) > limit and current:
            parts.append(current.rstrip())
            current = ""
        if len(line) > limit:
            while len(line) > limit:
                parts.append(line[:limit])
                line = line[limit:]
            current = line
        else:
            current += line

    if current.strip():
        parts.append(current.rstrip())

    return parts


def result_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🔄 Оновити граф",
                    callback_data="osint:refresh",
                ),
                InlineKeyboardButton(
                    text="📦 Експорт в JSON",
                    callback_data="osint:export",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="🔎 Новий пошук",
                    callback_data="osint:new",
                )
            ],
        ]
    )


async def send_result(message: Message, query: str) -> None:
    data = await search_osint(query)
    LAST_QUERIES[message.from_user.id] = query
    LAST_RESULTS[message.from_user.id] = data

    tree = render_tree(data)
    chunks = split_text(tree)

    for index, chunk in enumerate(chunks):
        text = f"<pre>{html.escape(chunk)}</pre>"
        if index == len(chunks) - 1:
            await message.answer(text, reply_markup=result_keyboard())
        else:
            await message.answer(text)


@router.message(Command("start"))
async def cmd_start(message: Message) -> None:
    await message.answer(
        "🤖 <b>OSINT Tree Bot</b>\n\n"
        "Демо-режим: вводь email, телефон, IP або username.\n"
        "Результати синтетичні — приватні/злиті бази не використовуються.\n\n"
        "Приклад: <code>test@example.com</code>\n"
        "Команди: /help"
    )


@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    await message.answer(
        "<b>Команди</b>\n"
        "/start — запуск\n"
        "/help — допомога\n\n"
        "<b>Пошук</b>\n"
        "Просто надішли email, телефон, IP або username.\n\n"
        "Результат показується деревом Unicode та може бути експортований у JSON.\n"
        "Пошук працює тільки з синтетичними даними."
    )


@router.message(F.text)
async def text_search(message: Message) -> None:
    query = (message.text or "").strip()
    if not query or query.startswith("/"):
        return

    try:
        await send_result(message, query)
    except Exception:
        log.exception("Search failed")
        await message.answer("❌ Не вдалося виконати демо-пошук. Спробуй ще раз.")


@router.callback_query(F.data == "osint:refresh")
async def refresh_result(callback: CallbackQuery) -> None:
    user_id = callback.from_user.id
    query = LAST_QUERIES.get(user_id)

    if not query:
        await callback.answer("Спочатку зроби пошук.", show_alert=True)
        return

    try:
        data = await search_osint(query)
        LAST_RESULTS[user_id] = data
        tree = render_tree(data)
        chunks = split_text(tree)

        await callback.message.answer(
            f"<pre>{html.escape(chunks[0])}</pre>",
            reply_markup=result_keyboard() if len(chunks) == 1 else None,
        )
        for chunk in chunks[1:]:
            await callback.message.answer(f"<pre>{html.escape(chunk)}</pre>")

        await callback.answer("Граф оновлено")
    except Exception:
        log.exception("Refresh failed")
        await callback.answer("Помилка оновлення", show_alert=True)


@router.callback_query(F.data == "osint:export")
async def export_result(callback: CallbackQuery) -> None:
    user_id = callback.from_user.id
    data = LAST_RESULTS.get(user_id)

    if not data:
        await callback.answer("Немає результату для експорту.", show_alert=True)
        return

    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".json",
            prefix="osint_result_",
            delete=False,
        ) as tmp:
            json.dump(data, tmp, ensure_ascii=False, indent=2)
            temp_path = tmp.name

        await callback.message.answer_document(
            FSInputFile(temp_path),
            caption="📦 JSON результату (демо-дані)",
        )
        await callback.answer("JSON готовий")
    except Exception:
        log.exception("Export failed")
        await callback.answer("Помилка експорту", show_alert=True)
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except OSError:
                log.warning("Could not remove temp file: %s", temp_path)


@router.callback_query(F.data == "osint:new")
async def new_search(callback: CallbackQuery) -> None:
    await callback.answer()
    await callback.message.answer("🔎 Надішли новий email, телефон, IP або username.")


async def main() -> None:
    bot = Bot(BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)

    log.info("Bot started")
    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
