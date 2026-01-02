# bot.py
# Telegram bot + PumpAPI stream alerts + trading via PumpAPI (Lightning)
# - user sets filters & trade params via Telegram buttons
# - user sends private key in Telegram -> we encrypt & store locally
# - bot shows wallet address (public key)
# - alert messages include Buy/Sell buttons
# - after trade, shows Solscan link https://solscan.io/tx/<signature>

import asyncio
import json as stdjson
import os
import random
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, List

import aiohttp
import orjson
import websockets
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken

import base58
from nacl.signing import SigningKey


# =========================
# ENV / CONFIG
# =========================
load_dotenv()

TG_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
if not TG_BOT_TOKEN:
    raise SystemExit("TELEGRAM_BOT_TOKEN is required")

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "").strip()
if not ENCRYPTION_KEY:
    raise SystemExit(
        'ENCRYPTION_KEY is required (Fernet key). Generate via: python -c "from cryptography.fernet import Fernet; '
        'print(Fernet.generate_key().decode())"'
    )

FERNET = Fernet(ENCRYPTION_KEY.encode("utf-8"))

STREAM_URL = os.getenv("PUMPAPI_STREAM_URL", "wss://stream.pumpapi.io/").strip()
TRADE_URL = os.getenv("PUMPAPI_TRADE_URL", "https://api.pumpapi.io").strip()

SOL_PRICE_USD = float(os.getenv("SOL_PRICE_USD", "126"))
DEFAULT_MC_THRESHOLD_USD = float(os.getenv("MC_THRESHOLD_USD", "10000"))

HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
TG_LONGPOLL_TIMEOUT = int(os.getenv("TG_LONGPOLL_TIMEOUT", "30"))
TG_LONGPOLL_GRACE = int(os.getenv("TG_LONGPOLL_GRACE", "15"))

FETCH_METADATA = os.getenv("FETCH_METADATA", "1").strip() not in ("0", "false", "False", "")
MAX_METADATA_ATTEMPTS = int(os.getenv("MAX_METADATA_ATTEMPTS", "5"))
METADATA_RETRY_EVERY_SECONDS = float(os.getenv("METADATA_RETRY_EVERY_SECONDS", "3"))

DATA_FILE = "bot_data.json"        # configs + encrypted keys
STATE_FILE = "notify_state.json"   # notification dedupe


# =========================
# UTIL
# =========================
def now_ms() -> int:
    return int(time.time() * 1000)


def safe_orjson_loads(msg: Any) -> Optional[Dict[str, Any]]:
    try:
        if isinstance(msg, (bytes, bytearray)):
            return orjson.loads(msg)
        if isinstance(msg, str):
            return orjson.loads(msg)
        return None
    except Exception:
        return None


def pretty_usd(x: float) -> str:
    return f"{x:,.0f}$"


def has_any_social(web: Optional[str], x: Optional[str], tg: Optional[str]) -> bool:
    return bool((web and web.strip()) or (x and x.strip()) or (tg and tg.strip()))


def extract_socials(metadata: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    candidates = []
    if isinstance(metadata, dict):
        candidates.append(metadata)
        ext = metadata.get("extensions")
        if isinstance(ext, dict):
            candidates.append(ext)

    def pick(obj: Dict[str, Any], keys) -> Optional[str]:
        for k in keys:
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None

    web = x = tg = None
    for obj in candidates:
        if not isinstance(obj, dict):
            continue
        web = web or pick(obj, ["website", "web", "site", "url"])
        x = x or pick(obj, ["twitter", "x", "twitter_url", "x_url"])
        tg = tg or pick(obj, ["telegram", "tg", "telegram_url", "tg_url"])
    return web, x, tg


def compute_mc_usd(event: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    mc_sol = event.get("marketCapSol")
    if isinstance(mc_sol, (int, float)) and mc_sol > 0:
        return float(mc_sol), float(mc_sol) * SOL_PRICE_USD

    mc_q = event.get("marketCapQuote")
    if isinstance(mc_q, (int, float)) and mc_q > 0:
        return None, float(mc_q)

    return None, None


def encrypt_str(s: str) -> str:
    return FERNET.encrypt(s.encode("utf-8")).decode("utf-8")


def decrypt_str(token: str) -> str:
    return FERNET.decrypt(token.encode("utf-8")).decode("utf-8")


def derive_wallet_address(private_key_str: str) -> Optional[str]:
    """
    Supports:
    - Solana keypair JSON array: [..] len 64
    - base58 secret key string: decodes to 32 or 64 bytes
    Returns base58 public key address or None.
    """
    s = (private_key_str or "").strip()
    if not s:
        return None

    # 1) JSON array keypair
    try:
        arr = stdjson.loads(s)
        if isinstance(arr, list) and all(isinstance(x, int) for x in arr):
            b = bytes(arr)
            if len(b) == 64:
                pub = b[32:64]
                return base58.b58encode(pub).decode()
            if len(b) == 32:
                pub = SigningKey(b).verify_key.encode()
                return base58.b58encode(pub).decode()
    except Exception:
        pass

    # 2) base58 secret key
    try:
        b = base58.b58decode(s)
        if len(b) == 64:
            pub = b[32:64]
            return base58.b58encode(pub).decode()
        if len(b) == 32:
            pub = SigningKey(b).verify_key.encode()
            return base58.b58encode(pub).decode()
    except Exception:
        return None

    return None


# =========================
# STORAGE
# =========================
def load_json_file(path: str, default: Dict[str, Any]) -> Dict[str, Any]:
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = stdjson.load(f)
        return data if isinstance(data, dict) else default
    except Exception:
        return default


def save_json_file(path: str, data: Dict[str, Any]) -> None:
    tmp = dict(data)
    tmp["updatedAt"] = now_ms()
    with open(path, "w", encoding="utf-8") as f:
        stdjson.dump(tmp, f, ensure_ascii=False, indent=2)


def default_chat_cfg() -> Dict[str, Any]:
    return {
        # filters
        "mc_threshold": DEFAULT_MC_THRESHOLD_USD,
        "notify_migrate": True,
        "require_socials": True,

        # trade defaults
        "slippage": 20,                  # percent
        "priorityFee": "auto-75",        # string or float
        "maxPriorityFee": 0.01,          # SOL cap for auto modes
        "jitoTip": None,                 # optional float
        "guaranteedDelivery": True,
        "maxBuySol": 0.2,                # per-click limit

        # wallet
        "enc_privateKey": None,
        "wallet_address": None,
    }


# =========================
# TELEGRAM API (long polling)
# =========================
class TelegramAPI:
    def __init__(self, token: str, session: aiohttp.ClientSession):
        self.base = f"https://api.telegram.org/bot{token}"
        self.session = session

    async def _post(self, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base}/{method}"
        async with self.session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_SECONDS)) as r:
            data = await r.json(content_type=None)
            if not isinstance(data, dict) or not data.get("ok"):
                raise RuntimeError(f"Telegram API error {method}: {data}")
            return data

    async def delete_webhook(self) -> None:
        await self._post("deleteWebhook", {"drop_pending_updates": True})

    async def get_updates(self, offset: int, timeout: int = 30) -> List[Dict[str, Any]]:
        total = timeout + TG_LONGPOLL_GRACE
        url = f"{self.base}/getUpdates"
        params = {
            "offset": offset,
            "timeout": timeout,
            "allowed_updates": ["message", "callback_query"],
        }
        try:
            async with self.session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=total)) as r:
                data = await r.json(content_type=None)
                if not isinstance(data, dict) or not data.get("ok"):
                    raise RuntimeError(f"Telegram API error getUpdates: {data}")
                return data.get("result", []) or []
        except asyncio.TimeoutError:
            return []

    async def send_message(self, chat_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        return await self._post("sendMessage", payload)

    async def edit_message_text(self, chat_id: int, message_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None) -> None:
        payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "disable_web_page_preview": True}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        await self._post("editMessageText", payload)

    async def answer_callback_query(self, callback_query_id: str, text: Optional[str] = None) -> None:
        payload = {"callback_query_id": callback_query_id}
        if text:
            payload["text"] = text
            payload["show_alert"] = False
        await self._post("answerCallbackQuery", payload)

    async def delete_message(self, chat_id: int, message_id: int) -> None:
        await self._post("deleteMessage", {"chat_id": chat_id, "message_id": message_id})


# =========================
# UI BUILDERS
# =========================
def kb_inline(rows: List[List[Tuple[str, str]]]) -> Dict[str, Any]:
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for (t, d) in row] for row in rows]}


def start_kb() -> Dict[str, Any]:
    return kb_inline([
        [("Фильтры", "open:filters"), ("Трейд", "open:trade")],
        [("Кошелёк", "open:wallet"), ("Статус", "open:status")],
    ])


def filters_menu_kb(cfg: Dict[str, Any]) -> Dict[str, Any]:
    mc = float(cfg.get("mc_threshold", DEFAULT_MC_THRESHOLD_USD))
    mig = bool(cfg.get("notify_migrate", True))
    socials = bool(cfg.get("require_socials", True))
    return kb_inline([
        [(f"Капа: {pretty_usd(mc)}", "filters:mc")],
        [(f"Миграция: {'ВКЛ' if mig else 'ВЫК'}", "filters:toggle_migrate")],
        [(f"Web/X/TG: {'ВКЛ' if socials else 'ВЫК'}", "filters:toggle_socials")],
        [("⬅️ Назад", "back:main")],
    ])


def mc_menu_kb() -> Dict[str, Any]:
    return kb_inline([
        [("5k", "mc:set:5000"), ("10k", "mc:set:10000"), ("20k", "mc:set:20000")],
        [("50k", "mc:set:50000"), ("100k", "mc:set:100000")],
        [("Custom", "mc:set:custom")],
        [("⬅️ Назад", "mc:back")],
    ])


def trade_menu_kb(cfg: Dict[str, Any]) -> Dict[str, Any]:
    slip = cfg.get("slippage", 20)
    pf = cfg.get("priorityFee", "auto-75")
    gd = bool(cfg.get("guaranteedDelivery", True))
    return kb_inline([
        [(f"Slippage: {slip}%", "trade:slippage")],
        [(f"priorityFee: {pf}", "trade:priorityfee")],
        [(f"guaranteedDelivery: {'ON' if gd else 'OFF'}", "trade:toggle_gd")],
        [(f"maxBuySol: {cfg.get('maxBuySol', 0.2)}", "trade:maxbuy")],
        [("⬅️ Назад", "back:main")],
    ])


def slippage_menu_kb() -> Dict[str, Any]:
    return kb_inline([
        [("10%", "slip:set:10"), ("20%", "slip:set:20"), ("30%", "slip:set:30")],
        [("Custom", "slip:set:custom")],
        [("⬅️ Назад", "trade:back")],
    ])


def priorityfee_menu_kb() -> Dict[str, Any]:
    return kb_inline([
        [("auto-50", "pf:set:auto-50"), ("auto-75", "pf:set:auto-75"), ("auto-95", "pf:set:auto-95")],
        [("fixed", "pf:set:fixed"), ("Custom", "pf:set:custom")],
        [("⬅️ Назад", "trade:back")],
    ])


def wallet_menu_kb(wallet_ok: bool) -> Dict[str, Any]:
    return kb_inline([
        [("🔑 Подключить ключ", "wallet:add")],
        [("🧨 Удалить ключ", "wallet:remove")],
        [("⬅️ Назад", "back:main")],
    ])


def alert_trade_kb(mint: str) -> Dict[str, Any]:
    return kb_inline([
        [("Купить", f"ord:buy:{mint}"), ("Buy 0.05", f"ord:buyq:{mint}:0.05"), ("Buy 0.1", f"ord:buyq:{mint}:0.1")],
        [("Sell 100%", f"ord:sell:{mint}:100")],
        [("Настройки", "open:trade")],
    ])


def confirm_kb(order_id: str) -> Dict[str, Any]:
    return kb_inline([
        [("✅ Confirm", f"ord:confirm:{order_id}"), ("❌ Cancel", f"ord:cancel:{order_id}")],
    ])


def render_status(cfg: Dict[str, Any]) -> str:
    wallet_ok = bool(cfg.get("enc_privateKey"))
    addr = cfg.get("wallet_address") or ""
    lines = []
    lines.append("📌 Текущие настройки\n")
    lines.append(f"• Wallet: {'подключен ✅' if wallet_ok else 'НЕ подключен ❌'}")
    if wallet_ok:
        lines.append(f"• Address: {addr}")
    lines.append("")
    lines.append("⚙️ Фильтры:")
    lines.append(f"• Капа алерта: {pretty_usd(float(cfg.get('mc_threshold', DEFAULT_MC_THRESHOLD_USD)))}")
    lines.append(f"• Миграция: {'ВКЛ ✅' if cfg.get('notify_migrate', True) else 'ВЫК ❌'}")
    lines.append(f"• Требовать Web/X/TG: {'ВКЛ ✅' if cfg.get('require_socials', True) else 'ВЫК ❌'}")
    lines.append("")
    lines.append("💥 Трейд:")
    lines.append(f"• Slippage: {cfg.get('slippage', 20)}%")
    lines.append(f"• priorityFee: {cfg.get('priorityFee', 'auto-75')}")
    lines.append(f"• maxPriorityFee: {cfg.get('maxPriorityFee', 0.01)} SOL")
    lines.append(f"• guaranteedDelivery: {'true' if cfg.get('guaranteedDelivery', True) else 'false'}")
    lines.append(f"• maxBuySol: {cfg.get('maxBuySol', 0.2)} SOL")
    return "\n".join(lines)


# =========================
# Pump token tracking
# =========================
@dataclass
class TokenInfo:
    mint: str
    symbol: str = ""
    name: str = ""
    uri: str = ""
    web: Optional[str] = None
    x: Optional[str] = None
    tg: Optional[str] = None

    created_on_pump: bool = False  # create + pool=pump
    last_mc_sol: Optional[float] = None
    last_mc_usd: Optional[float] = None

    metadata_attempts: int = 0
    metadata_last_try_ms: int = 0

    updated_at_ms: int = field(default_factory=now_ms)


def update_from_event(t: TokenInfo, event: Dict[str, Any]) -> None:
    sym = event.get("symbol")
    name = event.get("name")
    uri = event.get("uri")

    if isinstance(sym, str) and sym.strip():
        t.symbol = sym.strip()
    if isinstance(name, str) and name.strip():
        t.name = name.strip()
    if isinstance(uri, str) and uri.strip():
        t.uri = uri.strip()

    mc_sol, mc_usd = compute_mc_usd(event)
    if mc_usd is not None:
        t.last_mc_sol = mc_sol
        t.last_mc_usd = mc_usd

    t.updated_at_ms = now_ms()


async def fetch_metadata(session: aiohttp.ClientSession, uri: str) -> Optional[Dict[str, Any]]:
    if not uri:
        return None
    try:
        async with session.get(uri, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_SECONDS)) as r:
            if r.status != 200:
                return None
            data = await r.read()
            return orjson.loads(data)
    except Exception:
        return None


async def maybe_enrich_metadata(session: aiohttp.ClientSession, t: TokenInfo) -> None:
    if not FETCH_METADATA:
        return
    if has_any_social(t.web, t.x, t.tg):
        return
    if not t.uri:
        return
    if t.metadata_attempts >= MAX_METADATA_ATTEMPTS:
        return

    last = t.metadata_last_try_ms / 1000.0 if t.metadata_last_try_ms else 0.0
    if last and (time.time() - last) < METADATA_RETRY_EVERY_SECONDS:
        return

    t.metadata_last_try_ms = now_ms()
    t.metadata_attempts += 1

    data = await fetch_metadata(session, t.uri)
    if not isinstance(data, dict):
        return

    web, x, tg = extract_socials(data)
    t.web = t.web or web
    t.x = t.x or x
    t.tg = t.tg or tg


def build_alert_message(t: TokenInfo, migrated: bool = False) -> str:
    symbol = t.symbol or (t.name if t.name else "UNKNOWN")
    mint = t.mint
    gmgn = f"https://gmgn.ai/sol/token/{mint}"

    mc_line = ""
    if t.last_mc_usd is not None:
        if t.last_mc_sol is not None:
            mc_line = f"{t.last_mc_usd:,.0f}$ (~{t.last_mc_sol:,.2f} SOL)"
        else:
            mc_line = f"{t.last_mc_usd:,.0f}$"

    lines = [
        symbol,
        f"CA: {mint}",
        f"GMGN: {gmgn}",
        "",
        f"MC: {mc_line}",
    ]
    if migrated:
        lines += ["", "MIGRATED: ✅"]

    lines += [
        "",
        f"Web: {t.web or ''}",
        f"X: {t.x or ''}",
        f"TG: {t.tg or ''}",
    ]
    return "\n".join(lines)


# =========================
# APP STATE
# =========================
class App:
    def __init__(self):
        self.data = load_json_file(DATA_FILE, {"updatedAt": now_ms(), "chats": {}})
        self.chats_cfg: Dict[str, Dict[str, Any]] = self.data.get("chats", {})

        self.notify_state = load_json_file(STATE_FILE, {"updatedAt": now_ms(), "mints": {}})
        self.mints_state: Dict[str, Any] = self.notify_state.get("mints", {})

        self.tokens: Dict[str, TokenInfo] = {}

        # chat state machine: chat_id -> dict
        self.chat_states: Dict[str, Dict[str, Any]] = {}
        # orders cache: order_id -> order dict
        self.orders: Dict[str, Dict[str, Any]] = {}

    def ensure_chat(self, chat_id: int) -> Dict[str, Any]:
        key = str(chat_id)
        if key not in self.chats_cfg:
            self.chats_cfg[key] = default_chat_cfg()
            save_json_file(DATA_FILE, {"chats": self.chats_cfg})
        # ensure new fields exist
        cfg = self.chats_cfg[key]
        for k, v in default_chat_cfg().items():
            cfg.setdefault(k, v)
        self.chats_cfg[key] = cfg
        return cfg

    def wallet_ok(self, chat_id: int) -> bool:
        cfg = self.ensure_chat(chat_id)
        return bool(cfg.get("enc_privateKey"))

    def set_wallet(self, chat_id: int, private_key: str) -> Optional[str]:
        cfg = self.ensure_chat(chat_id)
        pk = private_key.strip()
        cfg["enc_privateKey"] = encrypt_str(pk)
        addr = derive_wallet_address(pk)
        cfg["wallet_address"] = addr
        self.chats_cfg[str(chat_id)] = cfg
        save_json_file(DATA_FILE, {"chats": self.chats_cfg})
        return addr

    def remove_wallet(self, chat_id: int) -> None:
        cfg = self.ensure_chat(chat_id)
        cfg["enc_privateKey"] = None
        cfg["wallet_address"] = None
        self.chats_cfg[str(chat_id)] = cfg
        save_json_file(DATA_FILE, {"chats": self.chats_cfg})

    def get_private_key(self, chat_id: int) -> Optional[str]:
        cfg = self.ensure_chat(chat_id)
        enc = cfg.get("enc_privateKey")
        if not enc:
            return None
        try:
            return decrypt_str(enc)
        except InvalidToken:
            return None

    def active_chat_ids(self) -> List[int]:
        out = []
        for k in self.chats_cfg.keys():
            try:
                out.append(int(k))
            except Exception:
                pass
        return out

    def already_notified(self, mint: str, kind: str, chat_id: int) -> bool:
        ms = self.mints_state.get(mint) or {}
        arr = (ms.get(kind) or [])
        return str(chat_id) in set(arr)

    def mark_notified(self, mint: str, kind: str, chat_id: int) -> None:
        ms = self.mints_state.setdefault(mint, {"mc": [], "migrate": []})
        arr = ms.setdefault(kind, [])
        sid = str(chat_id)
        if sid not in arr:
            arr.append(sid)
            save_json_file(STATE_FILE, {"mints": self.mints_state})


# =========================
# TRADING (PumpAPI)
# =========================
async def pumpapi_trade(
    session: aiohttp.ClientSession,
    private_key: str,
    action: str,
    mint: str,
    amount: Any,
    denominated_in_quote: bool,
    slippage: int,
    priority_fee: Any,
    max_priority_fee: Optional[float],
    jito_tip: Optional[float],
    guaranteed_delivery: bool
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "privateKey": private_key,
        "action": action,
        "mint": mint,
        "amount": amount,
        "denominatedInQuote": "true" if denominated_in_quote else "false",
        "slippage": slippage,
        "guaranteedDelivery": bool(guaranteed_delivery),
        "priorityFee": priority_fee,
    }
    if max_priority_fee is not None:
        payload["maxPriorityFee"] = max_priority_fee
    if jito_tip is not None:
        payload["jitoTip"] = jito_tip

    async with session.post(TRADE_URL, json=payload, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT_SECONDS)) as r:
        data = await r.json(content_type=None)
        return data if isinstance(data, dict) else {"ok": False, "raw": data}


# =========================
# TELEGRAM LOOP
# =========================
async def telegram_loop(app: App, tg: TelegramAPI, session: aiohttp.ClientSession):
    await tg.delete_webhook()
    offset = 0

    while True:
        updates = await tg.get_updates(offset=offset, timeout=TG_LONGPOLL_TIMEOUT)
        for u in updates:
            offset = max(offset, u.get("update_id", 0) + 1)

            try:
                # -------------------------
                # MESSAGE
                # -------------------------
                if "message" in u:
                    msg = u["message"]
                    chat_id = (msg.get("chat") or {}).get("id")
                    if chat_id is None:
                        continue

                    text = (msg.get("text") or "").strip()
                    cfg = app.ensure_chat(chat_id)
                    state = app.chat_states.get(str(chat_id), {})

                    # awaiting private key
                    if state.get("mode") == "await_private_key" and text and not text.startswith("/"):
                        addr = app.set_wallet(chat_id, text)

                        # try delete user's message with key (best effort)
                        try:
                            await tg.delete_message(chat_id, msg.get("message_id"))
                        except Exception:
                            pass

                        app.chat_states.pop(str(chat_id), None)

                        extra = f"\nАдрес: {addr}" if addr else "\nАдрес: (не смог распознать формат ключа, но ключ сохранён)"
                        await tg.send_message(
                            chat_id,
                            "Ключ сохранён ✅ (зашифрован у меня на стороне)"
                            + extra +
                            "\n\nСовет: используй отдельный hot-wallet и держи на нём лимит средств.",
                            reply_markup=wallet_menu_kb(wallet_ok=True),
                        )
                        continue

                    # custom mc input
                    if state.get("mode") == "await_mc_custom" and text and not text.startswith("/"):
                        raw = text.lower().replace("$", "").replace(",", "").strip()
                        try:
                            val = float(raw[:-1]) * 1000.0 if raw.endswith("k") else float(raw)
                        except Exception:
                            val = None
                        if not val or val <= 0:
                            await tg.send_message(chat_id, "Не понял число. Пример: 10000 или 15k")
                            continue
                        cfg["mc_threshold"] = float(val)
                        app.chats_cfg[str(chat_id)] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        app.chat_states.pop(str(chat_id), None)
                        await tg.send_message(chat_id, "Готово ✅", reply_markup=filters_menu_kb(cfg))
                        continue

                    # custom slippage
                    if state.get("mode") == "await_slip_custom" and text and not text.startswith("/"):
                        try:
                            s = int(text.strip())
                            if s <= 0 or s > 99:
                                raise ValueError()
                        except Exception:
                            await tg.send_message(chat_id, "Slippage должен быть числом 1..99")
                            continue
                        cfg["slippage"] = s
                        app.chats_cfg[str(chat_id)] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        app.chat_states.pop(str(chat_id), None)
                        await tg.send_message(chat_id, "Slippage обновлён ✅", reply_markup=trade_menu_kb(cfg))
                        continue

                    # custom priority fee
                    if state.get("mode") == "await_pf_custom" and text and not text.startswith("/"):
                        raw = text.strip()
                        try:
                            pf: Any = float(raw)
                        except Exception:
                            pf = raw
                        cfg["priorityFee"] = pf
                        app.chats_cfg[str(chat_id)] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        app.chat_states.pop(str(chat_id), None)
                        await tg.send_message(chat_id, "priorityFee обновлён ✅", reply_markup=trade_menu_kb(cfg))
                        continue

                    # max buy input
                    if state.get("mode") == "await_maxbuy" and text and not text.startswith("/"):
                        try:
                            v = float(text.strip())
                            if v <= 0:
                                raise ValueError()
                        except Exception:
                            await tg.send_message(chat_id, "maxBuySol должен быть числом > 0, например 0.2")
                            continue
                        cfg["maxBuySol"] = v
                        app.chats_cfg[str(chat_id)] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        app.chat_states.pop(str(chat_id), None)
                        await tg.send_message(chat_id, "maxBuySol обновлён ✅", reply_markup=trade_menu_kb(cfg))
                        continue

                    # buy amount input
                    if state.get("mode") == "await_buy_amount" and text and not text.startswith("/"):
                        mint = state.get("mint")
                        if not mint:
                            app.chat_states.pop(str(chat_id), None)
                            continue

                        try:
                            amt = float(text.strip())
                            if amt <= 0:
                                raise ValueError()
                        except Exception:
                            await tg.send_message(chat_id, "Введи сумму SOL числом, например 0.05")
                            continue

                        max_buy = float(cfg.get("maxBuySol", 0.2))
                        if amt > max_buy:
                            await tg.send_message(chat_id, f"Слишком много. maxBuySol={max_buy} SOL")
                            continue

                        order_id = f"{chat_id}-{mint[:6]}-{random.randint(100000, 999999)}"
                        order = {
                            "chat_id": chat_id,
                            "action": "buy",
                            "mint": mint,
                            "amount": amt,
                            "denom_quote": True,
                            "snapshot": {
                                "slippage": int(cfg.get("slippage", 20)),
                                "priorityFee": cfg.get("priorityFee", "auto-75"),
                                "maxPriorityFee": float(cfg.get("maxPriorityFee", 0.01)),
                                "jitoTip": cfg.get("jitoTip", None),
                                "guaranteedDelivery": bool(cfg.get("guaranteedDelivery", True)),
                            },
                            "expiresAt": now_ms() + 60_000,
                        }
                        app.orders[order_id] = order
                        app.chat_states.pop(str(chat_id), None)

                        txt = (
                            f"Подтверди покупку:\n\n"
                            f"mint: {mint}\n"
                            f"amount: {amt} SOL\n"
                            f"slippage: {order['snapshot']['slippage']}%\n"
                            f"priorityFee: {order['snapshot']['priorityFee']}\n"
                            f"maxPriorityFee: {order['snapshot']['maxPriorityFee']} SOL\n"
                            f"guaranteedDelivery: {order['snapshot']['guaranteedDelivery']}\n"
                        )
                        await tg.send_message(chat_id, txt, reply_markup=confirm_kb(order_id))
                        continue

                    if text.startswith("/start"):
                        user = msg.get("from", {}) or {}
                        username = user.get("username")
                        first_name = user.get("first_name") or "бойц"
                        who = username if username else first_name
                        await tg.send_message(
                            chat_id,
                            f"GM {who}\n\nОкопы ждут тебя, пора настроить фильтры!",
                            reply_markup=start_kb(),
                        )
                        continue

                # -------------------------
                # CALLBACK
                # -------------------------
                if "callback_query" in u:
                    cq = u["callback_query"]
                    cq_id = cq.get("id")
                    data = (cq.get("data") or "").strip()
                    msg = cq.get("message") or {}
                    chat_id = (msg.get("chat") or {}).get("id")
                    message_id = msg.get("message_id")

                    if cq_id:
                        await tg.answer_callback_query(cq_id)

                    if chat_id is None or message_id is None:
                        continue

                    cfg = app.ensure_chat(chat_id)
                    key = str(chat_id)

                    # nav
                    if data == "back:main":
                        await tg.edit_message_text(chat_id, message_id, "Меню:", reply_markup=start_kb())
                        continue

                    if data == "open:filters":
                        await tg.edit_message_text(chat_id, message_id, "⚙️ Фильтры:", reply_markup=filters_menu_kb(cfg))
                        continue

                    if data == "open:trade":
                        await tg.edit_message_text(chat_id, message_id, "💥 Трейд настройки:", reply_markup=trade_menu_kb(cfg))
                        continue

                    if data == "open:wallet":
                        ok = app.wallet_ok(chat_id)
                        addr = cfg.get("wallet_address") or ""
                        text = "🔐 Кошелёк:\n\n"
                        text += f"Статус: {'подключен ✅' if ok else 'НЕ подключен ❌'}\n"
                        if ok:
                            text += f"Адрес: {addr}\n"
                        await tg.edit_message_text(chat_id, message_id, text, reply_markup=wallet_menu_kb(ok))
                        continue

                    if data == "open:status":
                        await tg.edit_message_text(chat_id, message_id, render_status(cfg), reply_markup=start_kb())
                        continue

                    # filters
                    if data == "filters:mc":
                        await tg.edit_message_text(chat_id, message_id, "Выбери капу:", reply_markup=mc_menu_kb())
                        continue

                    if data == "mc:back":
                        await tg.edit_message_text(chat_id, message_id, "⚙️ Фильтры:", reply_markup=filters_menu_kb(cfg))
                        continue

                    if data.startswith("mc:set:"):
                        v = data.split("mc:set:", 1)[1]
                        if v == "custom":
                            app.chat_states[key] = {"mode": "await_mc_custom"}
                            await tg.edit_message_text(chat_id, message_id, "Введи капу числом. Примеры: 10000 или 15k")
                            continue
                        cfg["mc_threshold"] = float(v)
                        app.chats_cfg[key] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        await tg.edit_message_text(chat_id, message_id, "⚙️ Фильтры:", reply_markup=filters_menu_kb(cfg))
                        continue

                    if data == "filters:toggle_migrate":
                        cfg["notify_migrate"] = not bool(cfg.get("notify_migrate", True))
                        app.chats_cfg[key] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        await tg.edit_message_text(chat_id, message_id, "⚙️ Фильтры:", reply_markup=filters_menu_kb(cfg))
                        continue

                    if data == "filters:toggle_socials":
                        cfg["require_socials"] = not bool(cfg.get("require_socials", True))
                        app.chats_cfg[key] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        await tg.edit_message_text(chat_id, message_id, "⚙️ Фильтры:", reply_markup=filters_menu_kb(cfg))
                        continue

                    # trade settings
                    if data == "trade:back":
                        await tg.edit_message_text(chat_id, message_id, "💥 Трейд настройки:", reply_markup=trade_menu_kb(cfg))
                        continue

                    if data == "trade:slippage":
                        await tg.edit_message_text(chat_id, message_id, "Slippage:", reply_markup=slippage_menu_kb())
                        continue

                    if data.startswith("slip:set:"):
                        v = data.split("slip:set:", 1)[1]
                        if v == "custom":
                            app.chat_states[key] = {"mode": "await_slip_custom"}
                            await tg.edit_message_text(chat_id, message_id, "Введи slippage числом (1..99)")
                            continue
                        cfg["slippage"] = int(v)
                        app.chats_cfg[key] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        await tg.edit_message_text(chat_id, message_id, "💥 Трейд настройки:", reply_markup=trade_menu_kb(cfg))
                        continue

                    if data == "trade:priorityfee":
                        await tg.edit_message_text(chat_id, message_id, "priorityFee:", reply_markup=priorityfee_menu_kb())
                        continue

                    if data.startswith("pf:set:"):
                        v = data.split("pf:set:", 1)[1]
                        if v == "custom":
                            app.chat_states[key] = {"mode": "await_pf_custom"}
                            await tg.edit_message_text(chat_id, message_id, "Введи priorityFee: число (0.0002) или строку (auto-75)")
                            continue
                        if v == "fixed":
                            app.chat_states[key] = {"mode": "await_pf_custom"}
                            await tg.edit_message_text(chat_id, message_id, "Введи fixed priorityFee числом, например 0.0002")
                            continue
                        cfg["priorityFee"] = v
                        app.chats_cfg[key] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        await tg.edit_message_text(chat_id, message_id, "💥 Трейд настройки:", reply_markup=trade_menu_kb(cfg))
                        continue

                    if data == "trade:toggle_gd":
                        cfg["guaranteedDelivery"] = not bool(cfg.get("guaranteedDelivery", True))
                        app.chats_cfg[key] = cfg
                        save_json_file(DATA_FILE, {"chats": app.chats_cfg})
                        await tg.edit_message_text(chat_id, message_id, "💥 Трейд настройки:", reply_markup=trade_menu_kb(cfg))
                        continue

                    if data == "trade:maxbuy":
                        app.chat_states[key] = {"mode": "await_maxbuy"}
                        await tg.edit_message_text(chat_id, message_id, "Введи maxBuySol числом (например 0.2)")
                        continue

                    # wallet
                    if data == "wallet:add":
                        app.chat_states[key] = {"mode": "await_private_key"}
                        await tg.edit_message_text(
                            chat_id,
                            message_id,
                            "⚠️ ВНИМАНИЕ\n"
                            "Отправь приватный ключ одним сообщением.\n"
                            "Я сохраню его ЗАШИФРОВАННЫМ.\n\n"
                            "Совет: используй отдельный hot-wallet.\n"
                            "После отправки — удали сообщение у себя, на всякий случай."
                        )
                        continue

                    if data == "wallet:remove":
                        app.remove_wallet(chat_id)
                        await tg.edit_message_text(chat_id, message_id, "Ключ удалён ✅", reply_markup=wallet_menu_kb(wallet_ok=False))
                        continue

                    # orders
                    if data.startswith("ord:buy:"):
                        mint = data.split("ord:buy:", 1)[1]
                        if not app.wallet_ok(chat_id):
                            await tg.send_message(chat_id, "Сначала подключи кошелёк: /start → Кошелёк")
                            continue
                        app.chat_states[key] = {"mode": "await_buy_amount", "mint": mint}
                        await tg.send_message(chat_id, f"Введи сумму покупки в SOL (maxBuySol={cfg.get('maxBuySol', 0.2)}):")
                        continue

                    if data.startswith("ord:buyq:"):
                        parts = data.split(":")
                        mint = parts[2]
                        amt = float(parts[3])

                        if not app.wallet_ok(chat_id):
                            await tg.send_message(chat_id, "Сначала подключи кошелёк: /start → Кошелёк")
                            continue

                        max_buy = float(cfg.get("maxBuySol", 0.2))
                        if amt > max_buy:
                            await tg.send_message(chat_id, f"Слишком много. maxBuySol={max_buy} SOL")
                            continue

                        order_id = f"{chat_id}-{mint[:6]}-{random.randint(100000, 999999)}"
                        order = {
                            "chat_id": chat_id,
                            "action": "buy",
                            "mint": mint,
                            "amount": amt,
                            "denom_quote": True,
                            "snapshot": {
                                "slippage": int(cfg.get("slippage", 20)),
                                "priorityFee": cfg.get("priorityFee", "auto-75"),
                                "maxPriorityFee": float(cfg.get("maxPriorityFee", 0.01)),
                                "jitoTip": cfg.get("jitoTip", None),
                                "guaranteedDelivery": bool(cfg.get("guaranteedDelivery", True)),
                            },
                            "expiresAt": now_ms() + 60_000,
                        }
                        app.orders[order_id] = order

                        txt = (
                            f"Подтверди покупку:\n\n"
                            f"mint: {mint}\n"
                            f"amount: {amt} SOL\n"
                            f"slippage: {order['snapshot']['slippage']}%\n"
                            f"priorityFee: {order['snapshot']['priorityFee']}\n"
                            f"maxPriorityFee: {order['snapshot']['maxPriorityFee']} SOL\n"
                            f"guaranteedDelivery: {order['snapshot']['guaranteedDelivery']}\n"
                        )
                        await tg.send_message(chat_id, txt, reply_markup=confirm_kb(order_id))
                        continue

                    if data.startswith("ord:sell:"):
                        parts = data.split(":")
                        mint = parts[2]

                        if not app.wallet_ok(chat_id):
                            await tg.send_message(chat_id, "Сначала подключи кошелёк: /start → Кошелёк")
                            continue

                        order_id = f"{chat_id}-{mint[:6]}-{random.randint(100000, 999999)}"
                        order = {
                            "chat_id": chat_id,
                            "action": "sell",
                            "mint": mint,
                            "amount": "100%",
                            "denom_quote": False,
                            "snapshot": {
                                "slippage": int(cfg.get("slippage", 20)),
                                "priorityFee": cfg.get("priorityFee", "auto-75"),
                                "maxPriorityFee": float(cfg.get("maxPriorityFee", 0.01)),
                                "jitoTip": cfg.get("jitoTip", None),
                                "guaranteedDelivery": bool(cfg.get("guaranteedDelivery", True)),
                            },
                            "expiresAt": now_ms() + 60_000,
                        }
                        app.orders[order_id] = order

                        txt = (
                            f"Подтверди продажу:\n\n"
                            f"mint: {mint}\n"
                            f"amount: 100%\n"
                            f"slippage: {order['snapshot']['slippage']}%\n"
                            f"priorityFee: {order['snapshot']['priorityFee']}\n"
                            f"maxPriorityFee: {order['snapshot']['maxPriorityFee']} SOL\n"
                            f"guaranteedDelivery: {order['snapshot']['guaranteedDelivery']}\n"
                        )
                        await tg.send_message(chat_id, txt, reply_markup=confirm_kb(order_id))
                        continue

                    if data.startswith("ord:cancel:"):
                        order_id = data.split("ord:cancel:", 1)[1]
                        app.orders.pop(order_id, None)
                        await tg.send_message(chat_id, "Отменено.")
                        continue

                    if data.startswith("ord:confirm:"):
                        order_id = data.split("ord:confirm:", 1)[1]
                        order = app.orders.get(order_id)
                        if not order:
                            await tg.send_message(chat_id, "Ордер не найден или истёк.")
                            continue
                        if now_ms() > int(order.get("expiresAt", 0)):
                            app.orders.pop(order_id, None)
                            await tg.send_message(chat_id, "Ордер истёк. Повтори.")
                            continue
                        if int(order.get("chat_id")) != int(chat_id):
                            await tg.send_message(chat_id, "Нельзя подтвердить чужой ордер.")
                            continue

                        pk = app.get_private_key(chat_id)
                        if not pk:
                            await tg.send_message(chat_id, "Кошелёк не подключен или ключ повреждён. /start → Кошелёк")
                            continue

                        snap = order["snapshot"]
                        await tg.send_message(chat_id, "Отправляю транзакцию...")

                        try:
                            resp = await pumpapi_trade(
                                session=session,
                                private_key=pk,
                                action=order["action"],
                                mint=order["mint"],
                                amount=order["amount"],
                                denominated_in_quote=bool(order["denom_quote"]),
                                slippage=int(snap["slippage"]),
                                priority_fee=snap["priorityFee"],
                                max_priority_fee=float(snap["maxPriorityFee"]) if snap.get("maxPriorityFee") is not None else None,
                                jito_tip=snap.get("jitoTip"),
                                guaranteed_delivery=bool(snap["guaranteedDelivery"]),
                            )
                            app.orders.pop(order_id, None)

                            confirmed = resp.get("confirmed")
                            sig = resp.get("signature") or resp.get("txid") or resp.get("txSig")
                            err = resp.get("error") or resp.get("message")

                            out = ["✅ Ответ PumpAPI"]
                            if sig:
                                out.append(f"signature: {sig}")
                                out.append(f"Solscan: https://solscan.io/tx/{sig}")
                            if confirmed is not None:
                                out.append(f"confirmed: {confirmed}")
                            if err:
                                out.append(f"error: {err}")

                            raw = stdjson.dumps(resp)
                            if len(raw) > 1500:
                                raw = raw[:1500] + "..."
                            out.append(f"raw: {raw}")

                            await tg.send_message(chat_id, "\n".join(out))

                        except Exception as e:
                            app.orders.pop(order_id, None)
                            await tg.send_message(chat_id, f"Ошибка отправки: {type(e).__name__} {repr(e)}")
                        continue

            except Exception as e:
                print(f"[TG] handler error: {type(e).__name__} {repr(e)}")
                traceback.print_exc()


# =========================
# PUMP STREAM LOOP
# =========================
async def pump_stream_loop(app: App, tg: TelegramAPI, session: aiohttp.ClientSession):
    backoff = 1.0
    while True:
        try:
            print(f"[PUMP] connecting {STREAM_URL}")
            async with websockets.connect(
                STREAM_URL,
                ping_interval=20,
                ping_timeout=20,
                close_timeout=10,
                max_queue=4096,
            ) as ws:
                print("[PUMP] connected")
                backoff = 1.0

                async for msg in ws:
                    event = safe_orjson_loads(msg)
                    if not isinstance(event, dict):
                        continue

                    mint = event.get("mint")
                    if not isinstance(mint, str) or not mint:
                        continue

                    tx_type = event.get("txType")
                    pool = event.get("pool")

                    # track only create + pool=pump
                    if tx_type == "create":
                        if pool != "pump":
                            continue
                        t = app.tokens.get(mint)
                        if t is None:
                            t = TokenInfo(mint=mint)
                            app.tokens[mint] = t
                        t.created_on_pump = True
                        update_from_event(t, event)
                        await maybe_enrich_metadata(session, t)
                        continue

                    t = app.tokens.get(mint)
                    if t is None or not t.created_on_pump:
                        continue

                    update_from_event(t, event)
                    await maybe_enrich_metadata(session, t)

                    chat_ids = app.active_chat_ids()
                    if not chat_ids:
                        continue

                    # MC alert
                    if tx_type != "migrate" and t.last_mc_usd is not None:
                        for chat_id in chat_ids:
                            cfg = app.ensure_chat(chat_id)
                            thr = float(cfg.get("mc_threshold", DEFAULT_MC_THRESHOLD_USD))
                            if t.last_mc_usd < thr:
                                continue
                            if app.already_notified(mint, "mc", chat_id):
                                continue
                            if bool(cfg.get("require_socials", True)) and not has_any_social(t.web, t.x, t.tg):
                                continue

                            await tg.send_message(chat_id, build_alert_message(t, migrated=False), reply_markup=alert_trade_kb(mint))
                            app.mark_notified(mint, "mc", chat_id)
                            print(f"[ALERT] MC {mint} -> chat {chat_id}")

                    # MIGRATE alert
                    if tx_type == "migrate":
                        for chat_id in chat_ids:
                            cfg = app.ensure_chat(chat_id)
                            if not bool(cfg.get("notify_migrate", True)):
                                continue
                            if app.already_notified(mint, "migrate", chat_id):
                                continue
                            if bool(cfg.get("require_socials", True)) and not has_any_social(t.web, t.x, t.tg):
                                continue

                            await tg.send_message(chat_id, build_alert_message(t, migrated=True), reply_markup=alert_trade_kb(mint))
                            app.mark_notified(mint, "migrate", chat_id)
                            print(f"[ALERT] MIGRATE {mint} -> chat {chat_id}")

                        # stop tracking after migrate
                        app.tokens.pop(mint, None)

        except Exception as e:
            print(f"[PUMP] error: {type(e).__name__} {repr(e)} | reconnect in {backoff:.1f}s")
            traceback.print_exc()
            await asyncio.sleep(backoff + random.random() * 0.2)
            backoff = min(backoff * 2.0, 30.0)


# =========================
# MAIN
# =========================
async def main():
    app = App()
    async with aiohttp.ClientSession() as session:
        tg = TelegramAPI(TG_BOT_TOKEN, session)
        await asyncio.gather(
            telegram_loop(app, tg, session),
            pump_stream_loop(app, tg, session),
        )


if __name__ == "__main__":
    asyncio.run(main())
