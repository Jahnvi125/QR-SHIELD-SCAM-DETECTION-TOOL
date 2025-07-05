import os
import cv2
import json
import hashlib
import requests
import validators
import smtplib
import re
from fpdf import FPDF
from PIL import Image, ImageTk
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv
import tkinter as tk
from tkinter import filedialog, messagebox
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import csv
import webbrowser

# Load .env credentials
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")

# Fonts and Themes
FONT = ("Segoe UI", 12)
THEMES = {
    "Dark": {"bg": "#121212", "text": "#ffffff", "button": "#FF5722", "button_text": "#ffffff"},
    "Light": {"bg": "#ffffff", "text": "#222222", "button": "#FFA726", "button_text": "#000000"}
}
current_theme = "Dark"

# Languages
LANGUAGES = {
    "English": {
        "title": "QR SHIELD - Scam Detection Tool",
        "upload": "Upload QR Code Image",
        "scan_live": "Scan QR Code (Camera)",
        "report": "Generate PDF Report",
        "email_sent": "Malicious scan alert email sent!",
        "threat_levels": {"Malicious": "Malicious", "Suspicious": "Suspicious", "Safe": "Safe"},
        "cyber_btn": "⚠ Report to Cybercrime",
        "view_log": "📄 View Scan History"
    },
    "Hindi": {
        "title": "QR SHIELD - क्यूआर स्कैम डिटेक्शन टूल",
        "upload": "क्यूआर कोड छवि अपलोड करें",
        "scan_live": "क्यूआर कोड स्कैन करें (कैमरा)",
        "report": "पीडीएफ रिपोर्ट बनाएं",
        "email_sent": "मेल अलर्ट भेज दिया गया है!",
        "threat_levels": {"Malicious": "हानिकारक", "Suspicious": "संदिग्ध", "Safe": "सुरक्षित"},
        "cyber_btn": "⚠ साइबर क्राइम रिपोर्ट",
        "view_log": "📄 स्कैन इतिहास देखें"
    }
}
current_language = "English"

# Keywords for UPI/URL analysis
malicious_domains = ["badsite.com", "phishingexample.com", "malwaretest.net"]
permissions_keywords = ["camera", "location", "contacts", "storage", "sms", "phone"]
suspicious_upi_ids = ["random", "test", "fake", "donation", "help", "emergency", "relief"]

# Secure QR logging
def hash_qr_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def log_scan(data, verdict):
    hash_val = hash_qr_data(data)
    log_file = "threat_db.json"
    try:
        with open(log_file, "r") as f:
            db = json.load(f)
    except:
        db = {}

    if hash_val not in db:
        db[hash_val] = {
            "verdict": verdict,
            "timestamp": datetime.now().isoformat()
        }
        with open(log_file, "w") as f:
            json.dump(db, f, indent=4)
        print("✅ New scan logged.")
    else:
        print("ℹ️ Already scanned.")
# --- QR & UPI Scanning ---
def scan_qr_from_image(image_path):
    detector = cv2.QRCodeDetector()
    img = cv2.imread(image_path)
    data, bbox, _ = detector.detectAndDecode(img)
    return data

def scan_qr_from_camera():
    cap = cv2.VideoCapture(0)
    detector = cv2.QRCodeDetector()
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        data, bbox, _ = detector.detectAndDecode(frame)
        cv2.imshow("Scan QR - Press Q to exit", frame)
        if data:
            cap.release()
            cv2.destroyAllWindows()
            analyze_qr_data(data)
            return
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
    cap.release()
    cv2.destroyAllWindows()

# --- UPI Parsing ---
def is_upi_qr(data):
    return data.startswith("upi://pay?")

def parse_upi_qr(data):
    try:
        parsed = urlparse(data)
        query = parse_qs(parsed.query)
        return {
            "pa": query.get("pa", [""])[0],
            "pn": query.get("pn", [""])[0],
            "am": query.get("am", [""])[0],
            "note": query.get("tn", [""])[0] if "tn" in query else ""
        }
    except:
        return None

def detect_suspicious_upi_id(upi_id):
    return any(keyword in upi_id.lower() for keyword in suspicious_upi_ids)

# --- URL Threat Analysis ---
def analyze_url(url):
    return (
        any(k in url.lower() for k in ["login", "verify", "account", "secure", "update", "payment"]) or
        re.search(r"https?://\d+\.\d+\.\d+\.\d+", url) or
        url.count('-') > 3 or len(url) > 75
    )

def reputation_check(url):
    return any(domain in url for domain in malicious_domains)

def check_with_google_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "qr-shield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(api_url, json=payload)
        return "matches" in res.json()
    except Exception as e:
        print("Safe Browsing Error:", e)
        return False

# --- APK/Permissions Check ---
def check_permissions(url):
    if url.endswith(".apk") or "play.google.com" in url:
        return [p for p in permissions_keywords if p in url.lower()] or ["camera", "storage"]
    return []

# --- Email Alert ---
def send_email_alert(data, status):
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = "⚠️ QR Scam Alert Detected"
        body = f"A malicious QR code was scanned:\n\nQR Data: {data}\nThreat Level: {status}"
        msg.attach(MIMEText(body, 'plain'))
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        messagebox.showinfo("Email", LANGUAGES[current_language]["email_sent"])
    except Exception as e:
        messagebox.showerror("Email Failed", f"Error: {e}")
# --- PDF Report ---
def generate_pdf_report(data, status, filename="scan_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    try:
        pdf.image("logo.png", x=10, y=8, w=30)
    except:
        pass
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="QR SHIELD Scan Report", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, f"QR Data:\n{data}")
    pdf.cell(0, 10, f"Threat Level: {status}", ln=True)
    if is_upi_qr(data):
        upi = parse_upi_qr(data)
        if upi:
            pdf.ln(5)
            pdf.cell(200, 10, txt="UPI Details:", ln=True)
            pdf.multi_cell(0, 10, f"- Name: {upi.get('pn')}")
            pdf.multi_cell(0, 10, f"- UPI ID: {upi.get('pa')}")
            pdf.multi_cell(0, 10, f"- Amount: ₹{upi.get('am') or 'N/A'}")
            pdf.multi_cell(0, 10, f"- Note: {upi.get('note') or 'N/A'}")
    pdf.ln(10)
    pdf.set_font("Arial", "I", 10)
    pdf.cell(0, 10, txt=f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.output(filename)
    messagebox.showinfo("Report", "PDF report created!")

# --- Report to Cybercrime ---
def report_to_cybercrime():
    if last_data:
        root.clipboard_clear()
        root.clipboard_append(last_data)
        messagebox.showinfo("Copied", "QR data copied. Now opening Cybercrime portal...")
    webbrowser.open("https://cybercrime.gov.in/")

# --- View Scan Log + CSV Export ---
def view_log():
    log_file = "threat_db.json"
    if not os.path.exists(log_file):
        messagebox.showinfo("Log", "No scan history yet.")
        return
    with open(log_file, "r") as f:
        db = json.load(f)

    log_win = tk.Toplevel(root)
    log_win.title("Scan Log")
    log_win.geometry("600x400")
    text = tk.Text(log_win, wrap="word", font=("Segoe UI", 10))
    text.pack(expand=True, fill="both")

    for hash_val, info in db.items():
        timestamp = info.get("timestamp", "N/A")
        verdict = info.get("verdict", "N/A")
        text.insert("end", f"Hash: {hash_val[:20]}...\nVerdict: {verdict}\nTime: {timestamp}\n\n")

    def export_csv():
        with open("scan_log.csv", "w", newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Hash", "Verdict", "Timestamp"])
            for h, i in db.items():
                writer.writerow([h, i["verdict"], i["timestamp"]])
        messagebox.showinfo("Exported", "CSV exported as scan_log.csv")

    tk.Button(log_win, text="📤 Export to CSV", command=export_csv).pack(pady=10)

# --- Upload from Image File ---
def upload_image():
    path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
    if path:
        data = scan_qr_from_image(path)
        if data:
            analyze_qr_data(data)
        else:
            messagebox.showwarning("No QR", "No QR code found in image.")
# Global state
last_data = ""
last_status = ""

# GUI setup
root = tk.Tk()
root.title("QR SHIELD")
root.geometry("760x700")
root.resizable(True, True)

# Load logo
try:
    logo_img = Image.open("logo.png").resize((120, 120), Image.Resampling.LANCZOS)
    logo_photo = ImageTk.PhotoImage(logo_img)
except:
    logo_photo = None

main_frame = tk.Frame(root)
main_frame.pack(expand=True, pady=10)

# Toolbar
toolbar = tk.Frame(main_frame)
toolbar.pack(anchor="center", pady=5)

lang_frame = tk.Frame(toolbar)
lang_frame.grid(row=0, column=0, padx=10)
tk.Button(lang_frame, text="English 🇬🇧", command=lambda: switch_language("English"), font=("Segoe UI", 10)).pack(side="left", padx=3)
tk.Button(lang_frame, text="Hindi 🇮🇳", command=lambda: switch_language("Hindi"), font=("Segoe UI", 10)).pack(side="left", padx=3)

def toggle_theme():
    new_theme = "Light" if current_theme == "Dark" else "Dark"
    apply_theme(new_theme)
    theme_btn.config(text="🌙 Dark Mode" if new_theme == "Light" else "☀️ Light Mode")

theme_btn = tk.Button(toolbar, text="☀️ Light Mode", command=toggle_theme, font=("Segoe UI", 10))
theme_btn.grid(row=0, column=1, padx=10)

# Title and logo
title_label = tk.Label(main_frame, text=LANGUAGES[current_language]["title"], font=("Segoe UI", 22, "bold"))
title_label.pack(pady=(15, 5))
if logo_photo:
    logo_label = tk.Label(main_frame, image=logo_photo, bd=0)
    logo_label.pack(pady=5)

# Buttons
button_frame = tk.Frame(main_frame)
button_frame.pack(pady=20)

def style_button(btn):
    btn.configure(font=FONT, relief="flat", padx=14, pady=10, bd=0, width=30)

upload_btn = tk.Button(button_frame, text=LANGUAGES[current_language]["upload"], command=upload_image)
scan_btn = tk.Button(button_frame, text=LANGUAGES[current_language]["scan_live"], command=scan_qr_from_camera)
report_btn = tk.Button(button_frame, text=LANGUAGES[current_language]["report"], command=lambda: generate_pdf_report(last_data, last_status))
cyber_btn = tk.Button(button_frame, text=LANGUAGES[current_language]["cyber_btn"], command=report_to_cybercrime)
view_btn = tk.Button(button_frame, text=LANGUAGES[current_language]["view_log"], command=view_log)

for b in [upload_btn, scan_btn, report_btn, cyber_btn, view_btn]:
    style_button(b)
    b.pack(pady=8)

# Output Labels
result_label = tk.Label(main_frame, text="", font=FONT, wraplength=600, justify="center")
result_label.pack(pady=15)
verdict_label = tk.Label(main_frame, text="", font=("Segoe UI", 14, "bold"))
verdict_label.pack()

# Apply theme
def apply_theme(theme_name):
    global current_theme
    current_theme = theme_name
    theme = THEMES[theme_name]
    root.configure(bg=theme["bg"])
    main_frame.configure(bg=theme["bg"])
    toolbar.configure(bg=theme["bg"])
    lang_frame.configure(bg=theme["bg"])
    title_label.configure(bg=theme["bg"], fg=theme["text"])
    if logo_photo:
        logo_label.configure(bg=theme["bg"])
    result_label.configure(bg=theme["bg"], fg=theme["text"])
    verdict_label.configure(bg=theme["bg"], fg=theme["text"])
    for b in [upload_btn, scan_btn, report_btn, cyber_btn, view_btn]:
        b.configure(bg=theme["button"], fg=theme["button_text"])

# Switch language
def switch_language(lang):
    global current_language
    current_language = lang
    labels = LANGUAGES[lang]
    title_label.config(text=labels["title"])
    upload_btn.config(text=labels["upload"])
    scan_btn.config(text=labels["scan_live"])
    report_btn.config(text=labels["report"])
    cyber_btn.config(text=labels["cyber_btn"])
    view_btn.config(text=labels["view_log"])

# Analysis function
def analyze_qr_data(data):
    global last_data, last_status
    last_data = data
    result_label.config(text=f"QR Data: {data}", fg=THEMES[current_theme]["text"])
    hash_val = hash_qr_data(data)

    try:
        with open("threat_db.json", "r") as f:
            db = json.load(f)
            if hash_val in db:
                prev = db[hash_val]
                verdict_label.config(text=f"Already scanned: {prev['verdict']} on {prev['timestamp']}", fg="orange")
                return
    except:
        pass

    if is_upi_qr(data):
        upi = parse_upi_qr(data)
        upi_id = upi.get("pa", "")
        status = "Malicious" if detect_suspicious_upi_id(upi_id) else "Suspicious"
        last_status = status
        verdict_label.config(text=f"Threat Level: {status}", fg="red" if status == "Malicious" else "orange")
        log_scan(data, status)
        if status == "Malicious":
            send_email_alert(data, status)
        return

    if validators.url(data):
        status = "Safe"
        if analyze_url(data) or reputation_check(data) or check_with_google_safe_browsing(data):
            status = "Malicious"
        last_status = status
        verdict_label.config(text=f"Threat Level: {status}", fg="red" if status == "Malicious" else "orange" if status == "Suspicious" else "green")
        log_scan(data, status)
        if ".apk" in data:
            perms = check_permissions(data)
            if perms:
                messagebox.showinfo("Permissions", "\n".join(perms))
        if status == "Malicious":
            send_email_alert(data, status)
    else:
        verdict_label.config(text="Invalid QR Data", fg="blue")
        last_status = "Safe"

# Init theme
apply_theme(current_theme)

# Run app
root.mainloop()
