import asyncio
import html
import ipaddress
import json
import logging
import os
import re
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterator

import aiohttp
from defusedxml import ElementTree as SafeET
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

LAST_RESULTS: dict[int, dict[str, Any]] = {}
LAST_QUERIES: dict[int, str] = {}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().-]{5,20}$")
USERNAME_RE = re.compile(r"^@?[A-Za-z0-9_.-]{3,64}$")

MALTEGO_TRANSFORM_URL = os.getenv(
    "MALTEGO_TRANSFORM_URL",
    "http://127.0.0.1:3000/run/public_osint/",
).strip()
MALTEGO_PHONE_TRANSFORM_URL = os.getenv("MALTEGO_PHONE_TRANSFORM_URL", "").strip()
MALTEGO_EMAIL_TRANSFORM_URL = os.getenv("MALTEGO_EMAIL_TRANSFORM_URL", "").strip()
MALTEGO_IP_TRANSFORM_URL = os.getenv("MALTEGO_IP_TRANSFORM_URL", "").strip()
MALTEGO_USERNAME_TRANSFORM_URL = os.getenv("MALTEGO_USERNAME_TRANSFORM_URL", "").strip()
MALTEGO_TIMEOUT = float(os.getenv("MALTEGO_TIMEOUT", "45"))
MALTEGO_SOFT_LIMIT = int(os.getenv("MALTEGO_SOFT_LIMIT", "128"))
MALTEGO_HARD_LIMIT = int(os.getenv("MALTEGO_HARD_LIMIT", "256"))


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


def get_maltego_transform_url(kind: str) -> str:
    specific = {
        "Phone": MALTEGO_PHONE_TRANSFORM_URL,
        "Email": MALTEGO_EMAIL_TRANSFORM_URL,
        "IP": MALTEGO_IP_TRANSFORM_URL,
        "Username": MALTEGO_USERNAME_TRANSFORM_URL,
    }.get(kind, "")
    return specific or MALTEGO_TRANSFORM_URL


def maltego_entity_type(kind: str, query: str) -> str:
    if kind == "Phone":
        return "PhoneNumber"
    if kind == "Email":
        return "EmailAddress"
    if kind == "IP":
        return "IPv6Address" if ":" in query else "IPv4Address"
    if kind == "Username":
        return "Alias"
    return "Phrase"


def safe_transform_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path.rstrip("/") or "/"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def build_maltego_xml(query: str, entity_type: str) -> bytes:
    root = ET.Element("MaltegoMessage")
    request = ET.SubElement(root, "MaltegoTransformRequestMessage")
    entities = ET.SubElement(request, "Entities")
    entity = ET.SubElement(entities, "Entity", {"Type": entity_type})
    genealogy = ET.SubElement(entity, "Genealogy")
    ET.SubElement(
        genealogy,
        "Type",
        {"Name": f"maltego.{entity_type}", "OldName": entity_type},
    )
    ET.SubElement(entity, "Value").text = query
    ET.SubElement(entity, "Weight").text = "0"
    ET.SubElement(
        request,
        "Limits",
        {
            "SoftLimit": str(MALTEGO_SOFT_LIMIT),
            "HardLimit": str(MALTEGO_HARD_LIMIT),
        },
    )
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def parse_maltego_xml(raw: bytes) -> dict[str, Any]:
    root = SafeET.fromstring(raw)
    entities: list[dict[str, Any]] = []

    for entity in root.findall(
        ".//MaltegoTransformResponseMessage/Entities/Entity"
    ):
        item: dict[str, Any] = {
            "type": entity.attrib.get("Type", "unknown"),
            "value": (entity.findtext("Value") or "").strip(),
            "weight": (entity.findtext("Weight") or "").strip(),
        }

        labels: dict[str, str] = {}
        for label in entity.findall(".//DisplayInformation/Label"):
            name = label.attrib.get("Name", "").strip()
            value = "".join(label.itertext()).strip()
            if name:
                labels[name] = value
        if labels:
            item["labels"] = labels
        entities.append(item)

    messages: list[dict[str, str]] = []
    for message in root.findall(
        ".//MaltegoTransformResponseMessage/UIMessages/UIMessage"
    ):
        message_type = message.attrib.get("MessageType", "Inform")
        message_text = "".join(message.itertext()).strip()
        if message_text:
            messages.append({"type": message_type, "text": message_text})

    exceptions = [
        "".join(exception.itertext()).strip()
        for exception in root.findall(
            ".//MaltegoTransformExceptionMessage/Exceptions/Exception"
        )
        if "".join(exception.itertext()).strip()
    ]

    return {
        "entities": entities,
        "messages": messages,
        "exceptions": exceptions,
    }


async def search_maltego(query: str, kind: str) -> dict[str, Any]:
    url = get_maltego_transform_url(kind)
    if not url:
        raise RuntimeError(
            "Maltego is not configured. Set MALTEGO_TRANSFORM_URL "
            "or a type-specific MALTEGO_*_TRANSFORM_URL in .env."
        )

    entity_type = maltego_entity_type(kind, query)
    payload = build_maltego_xml(query, entity_type)
    timeout = aiohttp.ClientTimeout(total=MALTEGO_TIMEOUT)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url,
                data=payload,
                headers={"Content-Type": "application/xml; charset=utf-8"},
                allow_redirects=True,
            ) as response:
                body = await response.read()
                if response.status >= 400:
                    detail = body.decode("utf-8", errors="replace")[:500]
                    raise RuntimeError(
                        f"Maltego HTTP {response.status}: {detail}"
                    )

        parsed = parse_maltego_xml(body)
        if parsed["exceptions"]:
            raise RuntimeError("; ".join(parsed["exceptions"][:3]))

        return {
            "target": {"query": query, "type": kind},
            "maltego": {
                "status": "ok",
                "transform": safe_transform_url(url),
                "input_entity": entity_type,
                "result_count": len(parsed["entities"]),
            },
            "entities": parsed["entities"],
            "messages": parsed["messages"],
        }
    except aiohttp.ClientError as exc:
        raise RuntimeError(f"Maltego network error: {exc}") from exc


async def search_osint(query: str) -> dict[str, Any]:
    query = query.strip()
    if not query:
        raise ValueError("Empty query")
    return await search_maltego(query, classify_query(query))


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
    return "\n".join(tree_generator(data))


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

    chunks = split_text(render_tree(data))
    for index, chunk in enumerate(chunks):
        await message.answer(
            f"<pre>{html.escape(chunk)}</pre>",
            reply_markup=result_keyboard() if index == len(chunks) - 1 else None,
        )


@router.message(Command("start"))
async def cmd_start(message: Message) -> None:
    await message.answer(
        "🤖 <b>OSINT Tree Bot</b>\n\n"
        "Введи email, телефон, IP або username — запит піде в налаштований Maltego Transform.\n"
        "Трансформ і його джерела визначаються твоєю конфігурацією Maltego.\n\n"
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
        "Для роботи пошуку в .env має бути вказаний MALTEGO_TRANSFORM_URL або URL для конкретного типу."
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
        await message.answer(
            "❌ Не вдалося виконати пошук через Maltego. "
            "Перевір URL transform у .env та логи сервісу."
        )


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
        chunks = split_text(render_tree(data))

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
            caption="📦 JSON результату Maltego Transform",
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
    await callback.message.answer(
        "🔎 Надішли новий email, телефон, IP або username."
    )


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
