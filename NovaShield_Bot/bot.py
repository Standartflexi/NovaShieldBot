import asyncio
import json
import os
import secrets
import time
from typing import Optional, Dict, Any

import discord
from discord import app_commands
from discord.ext import commands
from aiohttp import web

CONFIG_PATH = "config.json"
DB_PATH = "licens.json"


# ---------------- Config ----------------
def load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


CFG = load_config()

DISCORD_TOKEN = CFG["discord_token"]
GUILD_ID = int(CFG["guild_id"])
LOG_CHANNEL_ID = int(CFG["log_channel_id"])

API_HOST = CFG["api"]["host"]
API_PORT = int(CFG["api"]["port"])
API_SECRET = CFG["api"]["secret"]
TRUST_X_FORWARDED_FOR = bool(CFG["api"].get("trust_x_forwarded_for", False))

ACTIVE_WINDOW_SECONDS = int(CFG["license"]["active_window_seconds"])
MISUSE_STRIKES_LIMIT = int(CFG["license"]["misuse_strikes_limit"])
REMINDER_CHECK_INTERVAL_SECONDS = int(CFG["license"]["reminder_check_interval_seconds"])


# ---------------- Helpers ----------------
def now_unix() -> int:
    return int(time.time())


def make_license_key() -> str:
    return secrets.token_hex(16)  # 32 hex chars


def parse_duration_to_seconds(inp: str) -> Optional[int]:
    s = inp.strip().lower()
    if len(s) < 2:
        return None
    num = s[:-1]
    unit = s[-1]
    if not num.isdigit():
        return None
    val = int(num)
    if unit == "d":
        return val * 86400
    if unit == "h":
        return val * 3600
    if unit == "m":
        return val * 60
    return None


def is_active_recent(last_seen: Optional[int], window: int) -> bool:
    if not last_seen:
        return False
    return (now_unix() - last_seen) <= window


def atomic_write_json(path: str, data: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


db_lock = asyncio.Lock()


def ensure_db_exists():
    if not os.path.exists(DB_PATH):
        atomic_write_json(DB_PATH, {"licenses": {}})


def load_db() -> Dict[str, Any]:
    ensure_db_exists()
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_db(db: Dict[str, Any]) -> None:
    atomic_write_json(DB_PATH, db)


# ---------------- DB functions (JSON) ----------------
async def db_create_license(license_key: str, kunden_id: str, ndc: str, duration_input: str, duration_seconds: int):
    created_at = now_unix()
    expires_at = created_at + duration_seconds

    async with db_lock:
        db = load_db()
        if license_key in db["licenses"]:
            raise RuntimeError("license_key collision")

        db["licenses"][license_key] = {
            "kunden_id": kunden_id,
            "ndc": ndc,
            "created_at": created_at,
            "duration_input": duration_input,
            "duration_seconds": duration_seconds,
            "expires_at": expires_at,

            "status": "active",
            "misuse_strikes": 0,
            "suspended_at": None,
            "suspended_reason": None,

            "locked": {"ip": None, "port": None},
            "last_server": {
                "server_name": None,
                "server_ip": None,
                "server_port": None,
                "resource_name": None,
                "reporter_ip": None,
                "last_seen": None
            },
            "reminders": {"sent_24h": False, "sent_1h": False}
        }
        save_db(db)

    return created_at, expires_at


async def db_get_license(license_key: str) -> Optional[Dict[str, Any]]:
    async with db_lock:
        db = load_db()
        lic = db["licenses"].get(license_key)
        if not lic:
            return None
        out = dict(lic)
        out["license_key"] = license_key
        return out


async def db_get_latest_license_by_kunden_id(kunden_id: str) -> Optional[Dict[str, Any]]:
    async with db_lock:
        db = load_db()
        best_key = None
        best_created = -1
        for k, v in db["licenses"].items():
            if v.get("kunden_id") == kunden_id:
                created = int(v.get("created_at", 0))
                if created > best_created:
                    best_created = created
                    best_key = k
        if not best_key:
            return None
        out = dict(db["licenses"][best_key])
        out["license_key"] = best_key
        return out


async def db_lock_license(license_key: str, ip: str, port: str):
    async with db_lock:
        db = load_db()
        lic = db["licenses"].get(license_key)
        if not lic:
            return
        lic["locked"]["ip"] = ip
        lic["locked"]["port"] = port
        save_db(db)


async def db_add_strike(license_key: str) -> int:
    async with db_lock:
        db = load_db()
        lic = db["licenses"].get(license_key)
        if not lic:
            return 0
        lic["misuse_strikes"] = int(lic.get("misuse_strikes", 0)) + 1
        strikes = int(lic["misuse_strikes"])
        save_db(db)
        return strikes


async def db_suspend_license(license_key: str, reason: str):
    async with db_lock:
        db = load_db()
        lic = db["licenses"].get(license_key)
        if not lic:
            return
        lic["status"] = "suspended"
        lic["suspended_at"] = now_unix()
        lic["suspended_reason"] = reason
        save_db(db)


async def db_update_last_server(license_key: str, payload: Dict[str, Any]):
    async with db_lock:
        db = load_db()
        lic = db["licenses"].get(license_key)
        if not lic:
            return
        lic["last_server"] = payload
        save_db(db)


async def db_mark_reminded(license_key: str, which: str):
    async with db_lock:
        db = load_db()
        lic = db["licenses"].get(license_key)
        if not lic:
            return
        if which == "24h":
            lic["reminders"]["sent_24h"] = True
        else:
            lic["reminders"]["sent_1h"] = True
        save_db(db)


async def db_get_all_active_not_expired() -> Dict[str, Dict[str, Any]]:
    async with db_lock:
        db = load_db()
        t = now_unix()
        res = {}
        for k, v in db["licenses"].items():
            if v.get("status") == "active" and int(v.get("expires_at", 0)) > t:
                res[k] = dict(v)
        return res


# ---------------- Discord ----------------
intents = discord.Intents.none()
bot = commands.Bot(command_prefix="!", intents=intents)


async def log_to_channel(text: str):
    ch = bot.get_channel(LOG_CHANNEL_ID)
    if isinstance(ch, discord.TextChannel):
        await ch.send(text)
        return
    try:
        fetched = await bot.fetch_channel(LOG_CHANNEL_ID)
        if isinstance(fetched, discord.TextChannel):
            await fetched.send(text)
    except Exception:
        pass


@bot.event
async def on_ready():
    print(f"✅ Bot online als {bot.user}")
    try:
        guild = discord.Object(id=GUILD_ID)
        bot.tree.copy_global_to(guild=guild)
        await bot.tree.sync(guild=guild)
        print("✅ Slash Commands (Guild) synchronisiert.")
    except Exception as e:
        print("⚠️ Sync Fehler:", e)

    if not getattr(bot, "_reminder_started", False):
        bot._reminder_started = True
        bot.loop.create_task(reminder_loop())


# /lizenz erstellen
group = app_commands.Group(name="lizenz", description="Lizenz Verwaltung")


@group.command(name="erstellen", description="Erstellt eine Lizenz")
@app_commands.describe(dauer="z.B. 30d, 12h, 15m", kunden_id="Discord User ID", ndc="nDC Wert")
async def lizenz_erstellen(interaction: discord.Interaction, dauer: str, kunden_id: str, ndc: str):
    if not interaction.user.guild_permissions.administrator:
        return await interaction.response.send_message("❌ Keine Rechte (Admin benötigt).", ephemeral=True)

    duration_seconds = parse_duration_to_seconds(dauer)
    if not duration_seconds:
        return await interaction.response.send_message("❌ Ungültige Dauer. Beispiele: `30d`, `12h`, `15m`", ephemeral=True)

    license_key = make_license_key()
    created_at, expires_at = await db_create_license(license_key, kunden_id, ndc, dauer, duration_seconds)

    await interaction.response.send_message(
        "✅ Lizenz erstellt\n"
        f"**Lizenz:** `{license_key}`\n"
        f"**Kunden (Discord ID):** `{kunden_id}`\n"
        f"**nDC:** `{ndc}`\n"
        f"**Dauer:** `{dauer}`\n"
        f"**Gültig bis:** <t:{expires_at}:F>\n"
        f"**IP/Port-Bind:** beim ersten Heartbeat",
        ephemeral=True,
    )


bot.tree.add_command(group)


@bot.tree.command(name="lizenzstatus", description="Prüft wo eine Lizenz aktuell aktiv ist")
@app_commands.describe(lizenz="Lizenz-Key", kunden_id="Discord User ID (falls ohne lizenz)")
async def lizenzstatus(interaction: discord.Interaction, lizenz: Optional[str] = None, kunden_id: Optional[str] = None):
    if not lizenz and not kunden_id:
        return await interaction.response.send_message("❌ Bitte `lizenz` oder `kunden_id` angeben.", ephemeral=True)

    if lizenz:
        lic = await db_get_license(lizenz)
        if not lic:
            return await interaction.response.send_message("❌ Lizenz nicht gefunden.", ephemeral=True)
    else:
        lic = await db_get_latest_license_by_kunden_id(kunden_id)  # type: ignore
        if not lic:
            return await interaction.response.send_message("❌ Keine Lizenz für diese Kunden ID gefunden.", ephemeral=True)

    expired = now_unix() > int(lic["expires_at"])
    last_server = lic.get("last_server") or {}
    last_seen = last_server.get("last_seen")
    active_now = (not expired) and (lic["status"] == "active") and is_active_recent(last_seen, ACTIVE_WINDOW_SECONDS)

    if lic["status"] == "suspended":
        status_txt = f"⛔ gesperrt — {lic.get('suspended_reason') or 'kein Grund'}"
    elif expired:
        status_txt = "❌ abgelaufen"
    else:
        status_txt = "✅ aktiv (online)" if active_now else "⚠️ gültig, aber aktuell nicht gemeldet"

    locked = lic.get("locked") or {}
    lock_txt = f"{locked.get('ip') or '-'}:{locked.get('port') or '-'}"
    strikes_txt = f"{int(lic.get('misuse_strikes', 0))}/{MISUSE_STRIKES_LIMIT}"

    if last_seen:
        where = (
            f"**Server:** {last_server.get('server_name') or 'unbekannt'}\n"
            f"**IP:** {last_server.get('server_ip') or 'unbekannt'}:{last_server.get('server_port') or '?'}\n"
            f"**Reporter IP:** {last_server.get('reporter_ip') or 'unbekannt'}\n"
            f"**Resource:** {last_server.get('resource_name') or 'unbekannt'}\n"
            f"**Letzte Meldung:** <t:{int(last_seen)}:R>"
        )
    else:
        where = "Keine Aktivierungsdaten (Server hat noch keinen Heartbeat gesendet)."

    await interaction.response.send_message(
        "**Lizenzstatus**\n"
        f"**Lizenz:** `{lic['license_key']}`\n"
        f"**Kunden (Discord ID):** `{lic['kunden_id']}`\n"
        f"**nDC:** `{lic['ndc']}`\n"
        f"**Dauer:** `{lic.get('duration_input')}`\n"
        f"**Ablauf:** <t:{int(lic['expires_at'])}:F>\n"
        f"**Status:** {status_txt}\n"
        f"**Strikes:** `{strikes_txt}`\n"
        f"**Gelockt auf:** `{lock_txt}`\n\n"
        f"**Aktivierungsort (letzter):**\n{where}",
        ephemeral=True,
    )


# ---------------- Reminder Loop ----------------
async def send_expiry_dm(license_key: str, lic: Dict[str, Any], which: str):
    try:
        user_id = int(lic["kunden_id"])  # kunden_id als Discord ID
    except ValueError:
        await log_to_channel(f"⚠️ Reminder nicht möglich: kunden_id ist keine Discord ID (Lizenz `{license_key}` kunden_id=`{lic['kunden_id']}`)")
        return

    try:
        user = await bot.fetch_user(user_id)
        if not user:
            return
        time_left_txt = "in 24 Stunden" if which == "24h" else "in 1 Stunde"
        await user.send(
            f"⏳ **Lizenz läuft bald ab**\n"
            f"Deine Lizenz `{license_key}` läuft {time_left_txt} ab.\n"
            f"Ablauf: <t:{int(lic['expires_at'])}:F>"
        )
    except Exception:
        await log_to_channel(f"⚠️ DM Reminder konnte nicht zugestellt werden: User `{lic['kunden_id']}` Lizenz `{license_key}` ({which})")


async def reminder_loop():
    await bot.wait_until_ready()
    while not bot.is_closed():
        try:
            candidates = await db_get_all_active_not_expired()
            t = now_unix()

            for license_key, lic in candidates.items():
                seconds_left = int(lic["expires_at"]) - t
                reminders = lic.get("reminders") or {}
                if seconds_left <= 86400 and not bool(reminders.get("sent_24h", False)):
                    await send_expiry_dm(license_key, lic, "24h")
                    await db_mark_reminded(license_key, "24h")

                if seconds_left <= 3600 and not bool(reminders.get("sent_1h", False)):
                    await send_expiry_dm(license_key, lic, "1h")
                    await db_mark_reminded(license_key, "1h")

        except Exception:
            pass

        await asyncio.sleep(REMINDER_CHECK_INTERVAL_SECONDS)


# ---------------- HTTP API ----------------
def get_reporter_ip(request: web.Request) -> Optional[str]:
    if TRUST_X_FORWARDED_FOR:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote


async def handle_heartbeat(request: web.Request) -> web.Response:
    secret = request.headers.get("x-api-secret", "")
    if not API_SECRET or secret != API_SECRET:
        return web.json_response({"ok": False, "error": "unauthorized"}, status=401)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "invalid_json"}, status=400)

    license_key = data.get("license_key")
    if not license_key:
        return web.json_response({"ok": False, "error": "license_key_missing"}, status=400)

    lic = await db_get_license(license_key)
    if not lic:
        return web.json_response({"ok": False, "error": "license_not_found"}, status=404)

    t = now_unix()
    if t > int(lic["expires_at"]):
        return web.json_response({"ok": False, "error": "license_expired"}, status=403)

    if lic["status"] == "suspended":
        return web.json_response({"ok": False, "error": "license_suspended"}, status=403)

    payload_ip = str(data.get("server_ip") or "unknown")
    payload_port = str(data.get("server_port") or "unknown")
    server_name = data.get("server_name")
    resource_name = data.get("resource_name")
    reporter_ip = get_reporter_ip(request)

    locked = lic.get("locked") or {"ip": None, "port": None}

    # 1) Lock on first heartbeat
    if not locked.get("ip") and payload_ip != "unknown" and payload_port != "unknown":
        await db_lock_license(license_key, payload_ip, payload_port)
        await log_to_channel(
            "🔒 **Lizenz gelockt**\n"
            f"License `{license_key}` → `{payload_ip}:{payload_port}`\n"
            f"Server: `{server_name or 'unbekannt'}` Resource: `{resource_name or 'unbekannt'}`"
        )
        lic = await db_get_license(license_key) or lic
        locked = lic.get("locked") or locked

    # 2) Enforce lock
    if locked.get("ip") and locked.get("port"):
        if payload_ip != locked["ip"] or payload_port != locked["port"]:
            strikes = await db_add_strike(license_key)

            await log_to_channel(
                "🚨 **Lizenz Missbrauch erkannt**\n"
                f"License `{license_key}`\n"
                f"Locked: `{locked['ip']}:{locked['port']}`\n"
                f"Got: `{payload_ip}:{payload_port}` ReporterIP: `{reporter_ip or 'unbekannt'}`\n"
                f"Server: `{server_name or 'unbekannt'}` Resource: `{resource_name or 'unbekannt'}`\n"
                f"Strikes: `{strikes}/{MISUSE_STRIKES_LIMIT}`"
            )

            if strikes >= MISUSE_STRIKES_LIMIT:
                reason = f"Auto-suspend: IP/Port mismatch ({strikes} strikes)"
                await db_suspend_license(license_key, reason)
                await log_to_channel(
                    "⛔ **Lizenz automatisch gesperrt**\n"
                    f"License `{license_key}`\n"
                    f"Grund: {reason}"
                )
                return web.json_response({"ok": False, "error": "license_suspended"}, status=403)

            return web.json_response({"ok": False, "error": "ip_mismatch", "strikes": strikes}, status=403)

    # 3) Save last server data into licens.json
    await db_update_last_server(
        license_key,
        {
            "server_name": server_name,
            "server_ip": payload_ip,
            "server_port": payload_port,
            "resource_name": resource_name,
            "reporter_ip": reporter_ip,
            "last_seen": t
        }
    )

    return web.json_response({"ok": True})


async def start_api():
    app = web.Application()
    app.router.add_post("/api/heartbeat", handle_heartbeat)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, API_HOST, API_PORT)
    await site.start()
    print(f"✅ API läuft auf http://{API_HOST}:{API_PORT}")


# ---------------- Main ----------------
async def main():
    ensure_db_exists()
    await start_api()
    await bot.start(DISCORD_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
