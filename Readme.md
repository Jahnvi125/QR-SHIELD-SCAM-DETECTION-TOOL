# 🛡️ QR Shield - Scam QR Code Detector

**QR Shield** is a Python-based tool that scans QR codes and detects whether the embedded URL might be **suspicious or malicious**. Useful for avoiding scam links disguised in QR codes.

---

## 🚀 Features

- 📷 Scan QR codes from images
- 🔍 Extract and analyze embedded URLs
- ⚠️ Detect phishing/scam signs like:
  - Shortened URLs (bit.ly, tinyurl)
  - IP-based URLs
  - Suspicious domains
- 🖼️ Simple GUI using Tkinter (optional)

---

## 🛠️ Tech Stack

- Python 3.x
- OpenCV
- `pyzbar` (for QR scanning)
- `validators` (for URL checks)
- Tkinter (for GUI)
- Pillow (for image display)

---

## 📦 Installation

```bash
pip install opencv-python pyzbar validators pillow
