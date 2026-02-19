import requests

# Your Telegram bot token and chat ID
BOT_TOKEN = "8324783319:AAHl78HCC5ZDrJcteSxSGLHKm37GgF9ZOvo"
CHAT_ID = "1609312246"

def send_telegram_alert(ip, confidence):
    message = f"⚠️ Suspicious device detected\nIP: {ip}\nConfidence: {confidence:.2f}%"
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    try:
        requests.post(url, data=data)
        print(f"[📲] Telegram alert sent to {CHAT_ID}")
    except Exception as e:
        print(f"[!] Telegram alert failed: {e}")
