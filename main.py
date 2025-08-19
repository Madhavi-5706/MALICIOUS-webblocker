import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
import requests
import base64
import time
from urllib.parse import urlparse
import csv
from datetime import datetime
import os
import webbrowser
import ctypes
import sys
import logging
from PIL import Image, ImageTk
import threading
import random

# ---------------- Configuration ---------------- #
API_KEY = "1daa9cebb9d2ed7bee44fdacea4a9bbc2cd30097f304d5e084daa68adb9c3355"
# Store password file in user home directory for portability
ADMIN_PASSWORD_FILE = os.path.join(os.path.expanduser('~'), 'admin_password.txt')
HISTORY_FILE = "history/scan_history.csv"
LOG_FILE = "logs/logs.txt"
PROJECT_INFO_HTML = "project_info.html"

# --- Password Persistence ---
def load_admin_password():
    try:
        if os.path.exists(ADMIN_PASSWORD_FILE):
            with open(ADMIN_PASSWORD_FILE, 'r') as f:
                pwd = f.read().strip()
                if pwd:
                    return pwd
    except Exception:
        pass
    return "MHNBP123"

ADMIN_PASSWORD = load_admin_password()

def save_admin_password(new_pwd):
    try:
        with open(ADMIN_PASSWORD_FILE, 'w') as f:
            f.write(new_pwd)
    except Exception:
        messagebox.showwarning("Warning", "Could not save password file. Password will reset next time.")

# ---------------- Admin Rights Check ---------------- #
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    sys.exit()

# ---------------- Logging Setup ---------------- #
os.makedirs("logs", exist_ok=True)
os.makedirs("history", exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ---------------- Startup Authentication ---------------- #
def authenticate_startup():
    root_pass = tk.Tk()
    root_pass.withdraw()
    pwd = simpledialog.askstring("Authentication Required", "Enter startup password:", show="*")
    if pwd != ADMIN_PASSWORD:
        messagebox.showerror("Access Denied", "Incorrect password. Exiting...")
        root_pass.destroy()
        sys.exit()
    root_pass.destroy()

authenticate_startup()

# ---------------- Helper Functions ---------------- #
def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def get_hostname(url):
    try:
        return urlparse(url).netloc
    except:
        return url

def save_to_history(url, malicious, total, verdict):
    with open(HISTORY_FILE, mode="a", newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            f"{malicious}/{total}",
            verdict
        ])

def validate_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url

def cyberpunk_password_popup():
    temp_root = tk.Toplevel(root)
    temp_root.title("Admin Password Required")
    temp_root.geometry("400x200")
    temp_root.configure(bg="#0a0a0a")
    temp_root.resizable(False, False)
    temp_root.grab_set()
    temp_root.transient(root)

    password_var = tk.StringVar()
    show_password = tk.BooleanVar(value=False)
    result = {'success': False}

    def toggle_visibility():
        if show_password.get():
            pwd_entry.config(show='*')
            toggle_btn.config(text='👁️')
            show_password.set(False)
        else:
            pwd_entry.config(show='')
            toggle_btn.config(text='🙈')
            show_password.set(True)

    def check_password(event=None):
        if password_var.get() == ADMIN_PASSWORD:
            result['success'] = True
            temp_root.destroy()
        else:
            error_label.config(text="Incorrect password!", fg="#ff3366")
            password_var.set("")
            pwd_entry.focus_set()

    def on_closing():
        temp_root.destroy()

    temp_root.protocol("WM_DELETE_WINDOW", on_closing)

    tk.Label(temp_root, text="ADMIN AUTHENTICATION", font=("Consolas", 13, "bold"), bg="#0a0a0a", fg="#ff3366").pack(pady=(20, 5))
    tk.Label(temp_root, text="Enter admin password", font=("Consolas", 10), bg="#0a0a0a", fg="#ffffff").pack()
    entry_frame = tk.Frame(temp_root, bg="#0a0a0a")
    entry_frame.pack(pady=15)
    pwd_entry = tk.Entry(entry_frame, textvariable=password_var, show="*", font=("Consolas", 12), width=22,
                         bg="#1a1a2e", fg="#00ffcc", insertbackground="#00ffcc", relief="solid", bd=1)
    pwd_entry.pack(side="left", padx=(10, 0))
    pwd_entry.bind("<Return>", check_password)
    toggle_btn = tk.Button(entry_frame, text="👁️", command=toggle_visibility, font=("Segoe UI Emoji", 11),
                           bg="#1a1a2e", fg="#00ffcc", relief="flat", width=3)
    toggle_btn.pack(side="left")
    submit_btn = tk.Button(temp_root, text="SUBMIT", command=check_password, font=("Segoe UI", 10, "bold"),
                           bg="#ff3366", fg="#fff", relief="raised", padx=20, pady=5)
    submit_btn.pack(pady=5)
    error_label = tk.Label(temp_root, text="", font=("Consolas", 10, "bold"), bg="#0a0a0a")
    error_label.pack()
    pwd_entry.focus_set()
    temp_root.wait_window()
    return result['success']

def validate_password():
    return cyberpunk_password_popup()

def view_history():
    try:
        with open(HISTORY_FILE, "r") as file:
            content = file.read()
        history_win = tk.Toplevel(root)
        history_win.title("Scan History")
        history_win.geometry("600x400")
        history_win.configure(bg="#0a0a0a")
        text_area = scrolledtext.ScrolledText(history_win, font=("Consolas", 10), bg="#1a1a1a", fg="#00ff88")
        text_area.pack(expand=True, fill="both")
        text_area.insert(tk.END, content)
        text_area.config(state='disabled')
    except FileNotFoundError:
        messagebox.showinfo("History", "No scan history found.")

# ---------------- Password Change Function ---------------- #
def change_password_window():
    def validate_and_change():
        global ADMIN_PASSWORD
        current = current_entry.get()
        new = new_entry.get()
        confirm = confirm_entry.get()
        if current != ADMIN_PASSWORD:
            messagebox.showerror("Error", "Current password is incorrect.")
            return
        if (len(new) < 8 or
                not any(c.isupper() for c in new) or
                not any(c.islower() for c in new) or
                not any(c.isdigit() for c in new)):
            messagebox.showwarning("Weak Password", "Password must be at least 8 characters long and contain uppercase, lowercase, and numeric characters.")
            return
        if new != confirm:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return

        ADMIN_PASSWORD = new
        with open(ADMIN_PASSWORD_FILE, "w") as f:
            f.write(new)
        messagebox.showinfo("Success", "Password changed successfully.")
        win.destroy()

    win = tk.Toplevel(root)
    win.title("Change Password")
    win.geometry("400x320")
    win.configure(bg="#0a0a0a")
    win.resizable(False, False)
    show_password_state = tk.BooleanVar(value=False)
    def toggle_password_visibility():
        if show_password_state.get():
            new_entry.config(show='*')
            confirm_entry.config(show='*')
            toggle_btn.config(text='👁️ Show Password')
            show_password_state.set(False)
        else:
            new_entry.config(show='')
            confirm_entry.config(show='')
            toggle_btn.config(text='🙈 Hide Password')
            show_password_state.set(True)
    tk.Label(win, text="Change Password", bg="#0a0a0a", fg="#00ffcc", font=("Consolas", 13, "bold")).pack(pady=10)
    tk.Label(win, text="Current:", bg="#0a0a0a", fg="#ffffff").pack(pady=(5,0))
    current_entry = tk.Entry(win, show='*', bg="#1a1a2e", fg="#00ffcc", insertbackground="#00ffcc", width=30)
    current_entry.pack(pady=(0,10))
    tk.Label(win, text="New:", bg="#0a0a0a", fg="#ffffff").pack(pady=(5,0))
    new_entry = tk.Entry(win, show='*', bg="#1a1a2e", fg="#00ffcc", insertbackground="#00ffcc", width=30)
    new_entry.pack(pady=(0,10))
    tk.Label(win, text="Confirm:", bg="#0a0a0a", fg="#ffffff").pack(pady=(5,0))
    confirm_entry = tk.Entry(win, show='*', bg="#1a1a2e", fg="#00ffcc", insertbackground="#00ffcc", width=30)
    confirm_entry.pack(pady=(0,10))
    toggle_btn = tk.Button(win, text="👁️ Show Password", command=toggle_password_visibility,
                           bg="#0a0a0a", fg="#00ff88", relief="flat",
                           activebackground="#0a0a0a", activeforeground="#00ff88")
    toggle_btn.pack(pady=10)
    tk.Button(win, text="Change", command=validate_and_change, bg="#00ff88", fg="#0a0a0a", font=("Segoe UI", 10, "bold"), relief="raised").pack(pady=10)

# ---------------- Blinking Effect for Status Label ---------------- #
def blink_status_label(is_malicious=False, duration=3000):
    """Make the status label blink with color zigzag"""
    colors = ["#ff3366", "#ff0033", "#cc0033"] if is_malicious else ["#00ff88", "#00cc66", "#009944"]
    start_time = time.time() * 1000
    color_index = 0

    def blink():
        nonlocal color_index
        current_time = time.time() * 1000
        if current_time - start_time < duration:
            try:
                status_label.config(fg=colors[color_index % len(colors)])
                color_index += 1
                root.after(200, blink)
            except tk.TclError:
                pass
        else:
            # Final fixed color
            status_label.config(fg="#ff3366" if is_malicious else "#00ff88")

    blink()

# ---------------- Popup Function ---------------- #
def create_blinking_popup(title, message, is_malicious=False, threat_types=None):
    """Create a custom popup with blinking effect and malware type display"""
    popup = tk.Toplevel(root)
    popup.title(title)

    # Adjust popup size based on content
    if is_malicious and threat_types:
        popup.geometry("500x350")
    else:
        popup.geometry("500x250")

    popup.configure(bg="#0a0a0a")
    popup.resizable(False, False)

    # Center the popup
    popup.transient(root)
    popup.grab_set()

    # Configure colors based on threat level
    if is_malicious:
        colors = ["#ff3366", "#ff0033", "#cc0033", "#990033"]
        icon = "🚨"
    else:
        colors = ["#00ff88", "#00cc66", "#009944", "#006633"]
        icon = "✅"

    # Main frame
    main_frame = tk.Frame(popup, bg="#0a0a0a")
    main_frame.pack(expand=True, fill="both", padx=20, pady=20)

    # Icon and title
    title_frame = tk.Frame(main_frame, bg="#0a0a0a")
    title_frame.pack(pady=10)

    icon_label = tk.Label(title_frame, text=icon, font=("Segoe UI", 24), bg="#0a0a0a", fg=colors[0])
    icon_label.pack()

    title_label = tk.Label(title_frame, text=title, font=("Segoe UI", 14, "bold"), 
                          bg="#0a0a0a", fg=colors[0])
    title_label.pack()

    # Scrollable message to prevent overflow (fix for safe site zigzag issue)
    message_box = scrolledtext.ScrolledText(main_frame, font=("Segoe UI", 10), 
                                            bg="#0a0a0a", fg="#ffffff", 
                                            wrap="word", height=6, width=50, 
                                            relief="flat", borderwidth=0)
    message_box.insert(tk.END, message)
    message_box.config(state="disabled")
    message_box.pack(pady=10, fill="both", expand=True)

    # Malware types section (only for malicious sites)
    if is_malicious and threat_types:
        separator = tk.Frame(main_frame, height=2, bg="#ff3366")
        separator.pack(fill="x", pady=10)

        threat_title = tk.Label(main_frame, text="🦠 DETECTED THREAT TYPES:", 
                               font=("Segoe UI", 12, "bold"), bg="#0a0a0a", fg="#ff6b6b")
        threat_title.pack(pady=5)

        threat_frame = tk.Frame(main_frame, bg="#1a1a2e", relief="solid", bd=1)
        threat_frame.pack(pady=10, padx=10, fill="x")

        for threat_type in threat_types:
            threat_label = tk.Label(threat_frame, text=f"• {threat_type}", 
                                   font=("Segoe UI", 10, "bold"), bg="#1a1a2e", 
                                   fg="#ffaa00", anchor="w")
            threat_label.pack(pady=3, padx=15, fill="x")

        warning_label = tk.Label(main_frame, 
                               text="⚠ DO NOT VISIT THIS WEBSITE ⚠", 
                               font=("Segoe UI", 11, "bold"), bg="#0a0a0a", 
                               fg="#ff3366")
        warning_label.pack(pady=5)

    ok_button = tk.Button(main_frame, text="OK", command=popup.destroy, 
                         font=("Segoe UI", 10, "bold"), bg=colors[0], fg="#ffffff",
                         relief="flat", padx=20, cursor="hand2")
    ok_button.pack(pady=15)

    color_index = 0
    def blink():
        nonlocal color_index
        if popup.winfo_exists():
            try:
                current_color = colors[color_index % len(colors)]
                icon_label.config(fg=current_color)
                title_label.config(fg=current_color)
                ok_button.config(bg=current_color)
                color_index += 1
                popup.after(300, blink)
            except tk.TclError:
                pass

    blink()

    popup.focus_set()
    popup.wait_window()

def open_project_info_html():
    html_content = """
    <html>
    <head>
        <title>Project Information</title>
        <style>
            body {
                font-family: 'Courier New', Courier, monospace;
                background-color: #0a0a0a;
                color: #00ffcc;
                margin: 30px;
                text-shadow: 0 0 5px #00ffcc;
            }
            h2, h3 {
                color: #ff3366;
                text-shadow: 0 0 7px #ff3366;
                border-bottom: 2px solid #ff3366;
                padding-bottom: 10px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .logo {
                height: 60px;
                filter: drop-shadow(0 0 10px #00ffcc);
            }
            table {
                border-collapse: collapse;
                width: 100%;
                margin-top: 20px;
                border: 1px solid #00ffcc;
                box-shadow: 0 0 15px rgba(0, 255, 204, 0.3);
            }
            th, td {
                border: 1px solid rgba(0, 255, 204, 0.5);
                padding: 12px;
                text-align: left;
            }
            th {
                background-color: #1a1a2e;
                color: #ff3366;
                text-transform: uppercase;
            }
            p {
                line-height: 1.7;
                font-size: 1.1em;
                text-align: justify;
            }
            a {
                color: #00ffcc;
                text-decoration: none;
                transition: color 0.3s, text-shadow 0.3s;
            }
            a:hover {
                color: #ff3366;
                text-shadow: 0 0 8px #ff3366;
            }
        </style>
    </head>
    <body>
        <h2>
            <span>// PROJECT INFORMATION //</span>
            <img src="https://suprajatechnologies.com/images/logo.png" class="logo" alt="Supraja Logo">
        </h2>

        <p><b>Malicious Web Blocker</b> is a cybersecurity tool developed as part of an internship project by a passionate team of interns:
<b>V. Hema</b>, <b>K. Madhavi Priya</b>, <b>Sk. Nasrin Sultana</b>, <b>Ch. Bhavya</b>, and <b>P. Preetham</b>.
This tool is designed to proactively protect users from malicious websites and online threats.</p>

<p>It scans and analyzes user-entered URLs in real time, detects multiple threat types (such as phishing, suspicious domains, or malware indicators), and provides alerts using a visually engaging, cyber-themed interface.</p>

<p>In case of a detected threat, the tool provides detailed visual cues and allows users to block the website, enhancing their digital safety. This project incorporates modern UI elements, password-protected settings, and popup-based warnings for a more interactive and secure experience.</p>

<hr>

<h3>🔐 Key Features</h3>
<ul>
  <li>Real-time URL analysis and threat detection</li>
  <li>Cyberpunk-style popup alerts with threat levels</li>
  <li>Admin password protection for secure access</li>
  <li>Customizable color themes based on threat severity</li>
  <li>Option to block access to malicious websites</li>
  <li>Logs of scanned URLs for tracking</li>
</ul>

<hr>

<h3>🛠 Technologies Used</h3>
<ul>
  <li><b>Python</b> – Core logic and threat detection</li>
  <li><b>Tkinter</b> – GUI for popups and main interface</li>
  <li><b>Regular Expressions (Regex)</b> – Pattern matching for malicious URLs</li>
  <li><b>HTML</b> – For displaying project info and documentation</li>
  <li><b>File Handling</b> – Storing logs and admin credentials</li>
</ul>

<hr>



        <h3>// DEVELOPER ROSTER //</h3>
        <table>
            <tr><th>Name</th><th>Employee ID</th><th>Email</th></tr>
            <tr><td>V.Hema</td><td>ST#IS#7685</td><td><a href="mailto:vallamkondahema582@gmail.com">vallamkondahema582@gmail.com</a></td></tr>
            <tr><td>K.Madhavi Priya</td><td>ST#IS#7683</td><td><a href="mailto:madhavikunapareddy5@gmail.com">madhavikunapareddy5@gmail.com</a></td></tr>
            <tr><td>Ch.Bhavya</td><td>ST#IS#7672</td><td><a href="mailto:chegireddybhavya@gmail.com">chegireddybhavya@gmail.com</a></td></tr>
            <tr><td>Sk.Nasrin Sultana</td><td>ST#IS#7676</td><td><a href="mailto:nasrinkky17@gmail.com">nasrinkky17@gmail.com</a></td></tr>
            <tr><td>P.Preetham</td><td>ST#IS#7715</td><td><a href="mailto:preeth6016@gmail.com">preeth6016@gmail.com</a></td></tr>
        </table>

        <h3>// COMPANY DETAILS //</h3>
        <table>
            <tr><th>Company</th><th>Value</th></tr>
            <tr><td>Name</td><td>Supraja Technologies</td></tr>
            <tr><td>Email</td><td><a href="mailto:contact@suprajatechnologies.com">contact@suprajatechnologies.com</a></td></tr>
        </table>
    </body>
    </html>
    """
    file_path = os.path.join(os.getcwd(), "project_info.html")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    webbrowser.open_new_tab(f"file://{file_path}")

def open_demo_ui_html():
    html = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>🛡 Malicious Web Blocker UI</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      background: linear-gradient(45deg, #0a0a0a, #1a1a2e, #16213e);
      background-size: 400% 400%;
      animation: gradientShift 10s ease infinite;
      font-family: 'Segoe UI', sans-serif;
      color: #00ffcc;
      text-shadow: 0 0 10px #00ffcc;
      position: relative;
      overflow: hidden;
    }
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      width: 200%;
      height: 200%;
      background-image: 
        linear-gradient(rgba(0, 255, 204, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 255, 204, 0.03) 1px, transparent 1px);
      background-size: 50px 50px;
      animation: gridMove 20s linear infinite;
      z-index: -2;
    }
    body::after {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-image: radial-gradient(2px 2px at 20px 30px, #00ffcc, transparent),
                        radial-gradient(2px 2px at 40px 70px, rgba(0, 255, 204, 0.8), transparent),
                        radial-gradient(1px 1px at 90px 40px, rgba(0, 255, 204, 0.6), transparent),
                        radial-gradient(1px 1px at 130px 80px, rgba(0, 255, 204, 0.4), transparent);
      background-repeat: repeat;
      background-size: 200px 200px;
      animation: particleFloat 15s ease-in-out infinite;
      z-index: -1;
    }
    @keyframes gradientShift {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }
    @keyframes gridMove {
      0% { transform: translate(0, 0); }
      100% { transform: translate(50px, 50px); }
    }
    @keyframes particleFloat {
      0%, 100% { transform: translateY(0px) rotate(0deg); }
      33% { transform: translateY(-30px) rotate(120deg); }
      66% { transform: translateY(30px) rotate(240deg); }
    }
    .container {
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(0, 255, 204, 0.3);
      padding: 40px;
      max-width: 600px;
      margin: 80px auto;
      border-radius: 20px;
      box-shadow: 0 0 30px rgba(0, 255, 204, 0.3), inset 0 0 30px rgba(0, 255, 204, 0.1);
      position: relative;
    }
    .container::before {
      content: '';
      position: absolute;
      top: -2px;
      left: -2px;
      right: -2px;
      bottom: -2px;
      background: linear-gradient(45deg, #00ffcc, #0066ff, #00ffcc);
      border-radius: 22px;
      z-index: -1;
      animation: borderGlow 3s ease-in-out infinite alternate;
    }
    @keyframes borderGlow {
      0% { opacity: 0.5; }
      100% { opacity: 1; }
    }
    h1 {
      text-align: center;
      color: #00ffcc;
      margin-bottom: 30px;
      font-size: 2.5rem;
      text-shadow: 0 0 20px #00ffcc;
      animation: titlePulse 2s ease-in-out infinite alternate;
    }
    @keyframes titlePulse {
      0% { text-shadow: 0 0 20px #00ffcc; }
      100% { text-shadow: 0 0 30px #00ffcc, 0 0 40px #00ffcc; }
    }
    label, input, button {
      display: block;
      width: 100%;
      margin: 15px 0;
      font-size: 1.1rem;
    }
    input {
      padding: 12px;
      border: 2px solid rgba(0, 255, 204, 0.3);
      border-radius: 10px;
      outline: none;
      background: rgba(0, 0, 0, 0.7);
      color: #00ff88;
      transition: all 0.3s ease;
    }
    input:focus {
      border-color: #00ffcc;
      box-shadow: 0 0 15px rgba(0, 255, 204, 0.5);
    }
    button {
      padding: 12px;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      font-weight: bold;
      color: #fff;
      background: linear-gradient(135deg, #00ffcc, #0066ff);
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
    }
    button::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
      transition: left 0.5s;
    }
    button:hover::before {
      left: 100%;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 20px rgba(0, 255, 204, 0.4);
    }
    .status-safe {
      background: linear-gradient(135deg, #00ff88, #00cc66);
      animation: pulseGreen 1s infinite;
    }
    .status-malicious {
      background: linear-gradient(135deg, #ff3366, #cc0033);
      animation: pulseRed 1s infinite;
    }
    @keyframes pulseRed {
      0%, 100% { box-shadow: 0 0 20px rgba(255, 51, 102, 0.5); }
      50% { box-shadow: 0 0 30px rgba(255, 51, 102, 0.8); }
    }
    @keyframes pulseGreen {
      0%, 100% { box-shadow: 0 0 20px rgba(0, 255, 136, 0.5); }
      50% { box-shadow: 0 0 30px rgba(0, 255, 136, 0.8); }
    }
    .footer {
      text-align: center;
      margin-top: 30px;
      font-size: 1rem;
      color: rgba(0, 255, 204, 0.7);
      animation: footerGlow 3s ease-in-out infinite alternate;
    }
    @keyframes footerGlow {
      0% { text-shadow: 0 0 10px rgba(0, 255, 204, 0.3); }
      100% { text-shadow: 0 0 20px rgba(0, 255, 204, 0.6); }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡 Malicious Web Blocker</h1>
    <label for="url">Enter Website URL:</label>
    <input type="text" id="url" placeholder="https://example.com">
    <button onclick="showSafe()">✔ Simulate Safe</button>
    <button onclick="showMalicious()">🚨 Simulate Malicious</button>
    <div id="statusBox" style="margin-top:25px; padding:15px; text-align:center; font-weight:bold; border-radius:10px; background:rgba(0,0,0,0.5);">Status: Ready to scan</div>
    <div class="footer">🔒 Created by Supraja Tech Interns 💻</div>
  </div>
  <script>
    function showSafe() {
      const box = document.getElementById("statusBox");
      box.className = 'status-safe';
      box.innerHTML = "✅ This website is SAFE!<br><br><button onclick='resetStatus()'>OK</button>";
    }
    function showMalicious() {
      const box = document.getElementById("statusBox");
      box.className = 'status-malicious';
      box.innerHTML = "🚨 This website is MALICIOUS!<br><br><button onclick='resetStatus()'>OK</button>";
    }
    function resetStatus() {
      const box = document.getElementById("statusBox");
      box.className = '';
      box.innerHTML = "Status: Ready to scan";
    }
  </script>
</body>
</html>'''
    file_path = os.path.join(os.getcwd(), "demo_ui.html")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html)
    webbrowser.open_new_tab(f"file://{file_path}")

# ---------------- VirusTotal API ---------------- #
def check_website_safety_virustotal(url):
    url = validate_url(url)
    encoded_url = encode_url(url)
    headers = {"x-apikey": API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    response = requests.get(vt_url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Error {response.status_code}: {response.text}")
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    analysis = data["data"]["attributes"]["last_analysis_results"]
    ctype = data["data"]["attributes"].get("last_http_response_content_type", "unknown")
    date = data["data"]["attributes"].get("last_analysis_date", "unknown")
    flagged_vendors = {vendor: result["category"] for vendor, result in analysis.items()}
    
    # Extract detailed malware information
    malware_details = {}
    threat_categories = set()
    for vendor, result in analysis.items():
        if result["category"] in ["malicious", "suspicious"]:
            threat_name = result.get("result", "Unknown Threat")
            malware_details[vendor] = {
                "category": result["category"],
                "threat_name": threat_name,
                "engine_name": result.get("engine_name", vendor)
            }
            threat_categories.add(classify_threat_type(threat_name))
    
    return stats["malicious"], sum(stats.values()), flagged_vendors, ctype, date, malware_details, list(threat_categories)

def classify_threat_type(threat_name):
    """Classify the type of malware based on threat name"""
    threat_name_lower = threat_name.lower()
    
    # Malware type classifications
    if any(keyword in threat_name_lower for keyword in ['phishing', 'phish', 'fake', 'spoof']):
        return "🎣 Phishing"
    elif any(keyword in threat_name_lower for keyword in ['trojan', 'backdoor', 'rat']):
        return "🐴 Trojan/Backdoor"
    elif any(keyword in threat_name_lower for keyword in ['ransomware', 'crypto', 'locker']):
        return "🔒 Ransomware"
    elif any(keyword in threat_name_lower for keyword in ['adware', 'pup', 'potentially unwanted']):
        return "📢 Adware/PUP"
    elif any(keyword in threat_name_lower for keyword in ['spam', 'scam', 'fraud']):
        return "📧 Spam/Scam"
    elif any(keyword in threat_name_lower for keyword in ['malware', 'virus', 'worm']):
        return "🦠 Malware/Virus"
    elif any(keyword in threat_name_lower for keyword in ['exploit', 'cve', 'vulnerability']):
        return "⚡ Exploit Kit"
    elif any(keyword in threat_name_lower for keyword in ['botnet', 'c&c', 'command']):
        return "🤖 Botnet/C&C"
    elif any(keyword in threat_name_lower for keyword in ['suspicious', 'heuristic']):
        return "⚠ Suspicious Activity"
    else:
        return "🚨 Generic Threat"

# ---------------- Main UI Functions ---------------- #
def on_check():
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return
    try:
        status_label.config(text="🔍 Scanning...", fg="#00ccff")
        output_box.delete('1.0', tk.END)
        malicious, total, results, ctype, date, malware_details, threat_types = check_website_safety_virustotal(url)
        
        # Basic scan information
        output_box.insert(tk.END, f"🔗 URL: {url}\n🕓 Last Checked: {time.ctime(date)}\n📦 Content Type: {ctype}\n⚠ Malicious Vendors: {malicious}/{total}\n\n")
        
        if malicious > 0:
            # Display threat types
            if threat_types:
                output_box.insert(tk.END, "🦠 DETECTED THREAT TYPES:\n")
                for threat_type in threat_types:
                    output_box.insert(tk.END, f"   • {threat_type}\n")
                output_box.insert(tk.END, "\n")
            
            # Display detailed malware information
            output_box.insert(tk.END, "🚨 DETAILED THREAT ANALYSIS:\n")
            output_box.insert(tk.END, "=" * 50 + "\n")
            
            for vendor, details in malware_details.items():
                threat_name = details.get("threat_name", "Unknown")
                category = details.get("category", "unknown")
                
                if category == "malicious":
                    output_box.insert(tk.END, f"❌ {vendor}:\n")
                    output_box.insert(tk.END, f"   └─ Threat: {threat_name}\n")
                elif category == "suspicious":
                    output_box.insert(tk.END, f"⚠  {vendor}:\n")
                    output_box.insert(tk.END, f"   └─ Suspicious: {threat_name}\n")
                output_box.insert(tk.END, "\n")
            
            # Update status and UI
            status_text = f"🚨 {malicious}/{total} flagged as malicious"
            if threat_types:
                primary_threat = threat_types[0] if threat_types else "Unknown"
                status_text += f" | Primary: {primary_threat}"
            
            status_label.config(text=status_text, fg="#ff3366")
            block_btn.config(state="normal", bg="#ff3366")
            
            # Start blinking effect for status
            blink_status_label(is_malicious=True)
            
            # Create detailed popup message
            popup_message = f"WARNING: This website has been flagged as malicious by {malicious} out of {total} security vendors!"
            if threat_types:
                popup_message += f"\n\nPrimary threats detected:\n"
                for threat in threat_types[:3]:  # Show top 3 threats
                    popup_message += f"• {threat}\n"
                if len(threat_types) > 3:
                    popup_message += f"...and {len(threat_types) - 3} more threat types"
            
            popup_message += "\n\n⚠ DO NOT PROCEED TO THIS WEBSITE! ⚠"
            
            # Show custom blinking popup with threat types
            create_blinking_popup("🚨 MALICIOUS WEBSITE DETECTED!", 
                                popup_message,
                                is_malicious=True, 
                                threat_types=threat_types)
            verdict = "Malicious"
        else:
            output_box.insert(tk.END, "✅ No malicious vendors detected.\n")
            output_box.insert(tk.END, "🛡 This website appears to be safe.\n")
            output_box.insert(tk.END, "🔍 No threats found in security analysis.\n")
            
            status_label.config(text="✅ URL is safe", fg="#00ff88")
            block_btn.config(state="disabled", bg="#666666")
            
            # Start blinking effect for status
            blink_status_label(is_malicious=False)
            
            # Show custom blinking popup
            create_blinking_popup("✅ WEBSITE IS SAFE!", 
                                "This website has been verified as safe by our security analysis.\n\nNo threats detected - you can proceed safely.", 
                                is_malicious=False)
            verdict = "Safe"
        
        save_to_history(url, malicious, total, verdict)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def block_url():
    if not validate_password():
        return
    host = get_hostname(url_entry.get().strip())
    line = f"127.0.0.1 {host}\n"
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(hosts_path, "r+") as file:
            content = file.read()
            if host in content:
                messagebox.showinfo("Already Blocked", f"🚫 {host} is already blocked.")
                return
            file.write(line)
        messagebox.showinfo("Blocked", f"🚫 {host} has been blocked successfully.")
    except PermissionError:
        messagebox.showerror("Permission Error", "⚠ Please run the program as administrator.")

def unblock_url():
    if not validate_password(): return
    host = get_hostname(url_entry.get().strip())
    hosts_path = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
    try:
        with open(hosts_path, "r") as file:
            lines = file.readlines()
        with open(hosts_path, "w") as file:
            for line in lines:
                if host not in line:
                    file.write(line)
        messagebox.showinfo("Unblocked", f"✅ {host} has been unblocked successfully.")
    except PermissionError:
        messagebox.showerror("Permission Error", "Please run as administrator.")

# --- Cyberpunk theme for main window ---
root = tk.Tk()
root.title("🛡 Malicious Web Blocker - Cyber Security Tool")
root.geometry("700x750")
cyber_bg = "#0a0a0a"
cyber_accent = "#00ffcc"
cyber_secondary = "#1a1a2e"
cyber_text = "#ffffff"
cyber_danger = "#ff3366"
cyber_safe = "#00ff88"
root.configure(bg=cyber_bg)

# --- Place all other widgets above the canvas ---
header_frame = tk.Frame(root, bg=cyber_bg)
header_frame.pack(pady=20, fill="x")
title_font = ("Consolas", 20, "bold")
button_font = ("Consolas", 11, "bold")
label_font = ("Consolas", 11)
console_font = ("Consolas", 10)
header_frame = tk.Frame(root, bg=cyber_bg)
header_frame.pack(pady=20, fill="x")
title_label = tk.Label(header_frame, text="🛡 MALICIOUS WEB BLOCKER 🛡", bg=cyber_bg, fg=cyber_accent, font=title_font)
title_label.pack()
subtitle_label = tk.Label(header_frame, text="-- ADVANCED CYBER SECURITY & THREAT ANALYSIS --", bg=cyber_bg, fg=cyber_text, font=("Consolas", 11))
subtitle_label.pack(pady=5)
separator = tk.Frame(root, height=2, bg=cyber_accent)
separator.pack(fill="x", padx=40, pady=10)
control_panel = tk.Frame(root, bg=cyber_bg)
control_panel.pack(pady=10, padx=20, fill="x")
info_btn = tk.Button(control_panel, text="📘 PROJECT INFO", command=open_project_info_html, bg=cyber_secondary, fg=cyber_accent, font=button_font, relief="flat", bd=2, width=20, cursor="hand2")
info_btn.pack(side="left", padx=5)
history_btn = tk.Button(control_panel, text="📊 VIEW SCAN HISTORY", command=view_history, bg=cyber_secondary, fg=cyber_accent, font=button_font, relief="raised", bd=2, width=25, cursor="hand2")
history_btn.pack(side="left", padx=5)
password_btn = tk.Button(control_panel, text="🔐 CHANGE PASSWORD", command=change_password_window, bg=cyber_secondary, fg=cyber_accent, font=button_font, relief="flat", bd=2, width=20, cursor="hand2")
password_btn.pack(side="right", padx=5)
input_frame = tk.Frame(root, bg=cyber_secondary, bd=2, relief="sunken")
input_frame.pack(pady=20, padx=20, fill="x")
tk.Label(input_frame, text="🔗 Enter Target URL:", bg=cyber_secondary, fg=cyber_text, font=label_font).pack(anchor="w", padx=10, pady=5)
url_entry = tk.Entry(input_frame, font=("Consolas", 12), width=50, relief="solid", bd=1, bg="#0a0a0a", fg=cyber_accent, insertbackground=cyber_accent)
url_entry.pack(pady=10, fill="x", padx=10)
check_btn = tk.Button(root, text="[ 🔍 SCAN WEBSITE 🔍 ]", command=on_check, bg=cyber_accent, fg=cyber_bg, font=("Segoe UI", 12, "bold"), relief="raised", bd=3, width=30, cursor="hand2", pady=8)
check_btn.pack(pady=10)
status_frame = tk.Frame(root, bg=cyber_secondary, relief="groove", bd=2)
status_frame.pack(pady=10, fill="x", padx=20)
status_label = tk.Label(status_frame, text="[ STATUS: READY ]", font=("Consolas", 12, "bold"), bg=cyber_secondary, fg=cyber_text, pady=5)
status_label.pack()
host_control_frame = tk.Frame(root, bg=cyber_bg)
host_control_frame.pack(pady=15)
block_btn = tk.Button(host_control_frame, text="🚫 BLOCK SITE", command=block_url, bg="#666666", fg=cyber_text, font=button_font, width=18, relief="flat", state="disabled", cursor="hand2")
block_btn.pack(side="left", padx=10)
unblock_btn = tk.Button(host_control_frame, text="✅ UNBLOCK SITE", command=unblock_url, bg=cyber_safe, fg=cyber_bg, font=button_font, width=18, relief="flat", cursor="hand2")
unblock_btn.pack(side="right", padx=10)
console_frame = tk.Frame(root, bg=cyber_bg)
console_frame.pack(pady=15, padx=20, fill="both", expand=True)
tk.Label(console_frame, text=">> SCAN RESULTS CONSOLE:", bg=cyber_bg, fg=cyber_text, font=("Consolas", 10, "bold")).pack(anchor="w")
output_box = scrolledtext.ScrolledText(console_frame, width=70, height=12, font=console_font, bg=cyber_secondary, fg=cyber_accent, insertbackground=cyber_accent, selectbackground=cyber_accent, selectforeground=cyber_bg, relief="sunken", bd=2)
output_box.pack(fill="both", expand=True)
footer_label = tk.Label(root, text="-- Developed by Supraja Technologies Interns --", bg=cyber_bg, fg="#888888", font=("Consolas", 9))
footer_label.pack(pady=10, side="bottom")

root.mainloop()