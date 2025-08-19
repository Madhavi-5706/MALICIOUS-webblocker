# 🛡️ Malicious Web Blocker

**Advanced Cyber Security & Threat Analysis Tool**

Malicious Web Blocker is a Python and Tkinter-based tool that helps protect Windows users by scanning URLs using the VirusTotal API and blocking access to sites flagged as malicious or phishing threats.

## 🚀 Features
- **Real-time scanning of websites using VirusTotal API**
- **Alerts and blocks malicious URLs**
- **Easy-to-use graphical interface**
- **Scan history export (CSV)**
- **Admin authentication for blocking/unblocking operations**
- **Standalone Windows executable (`main.exe`) for easy use**
- **Prevents accidental visits to flagged sites**

## 🖥️ Installation & Usage

### Option 1: Windows Executable
- Download the latest release from the [Releases](https://github.com/Madhavi-5706/MALICIOUS-webblocker/releases) page.
- Run `main.exe` as **Administrator** for site blocking functionalities.

### Option 2: Python Source Code
- Clone this repository:
git clone https://github.com/Madhavi-5706/MALICIOUS-webblocker.git
cd MALICIOUS-webblocker

- Install dependencies:
pip install -r requirements.txt

- Run the tool:
python main.py


## Step-by-Step Usage Guide

1. **Launch the Tool**  
 Run `main.exe` (as Administrator) or `python main.py` to open the Malicious Web Blocker interface.

2. **Enter URL to Scan**  
 In the input box labeled "Enter Target URL", type or paste the website URL you want to check.

3. **Scan Website**  
 Click the **SCAN WEBSITE** button. The tool will query VirusTotal and analyze the URL for threats.

4. **View Scan Results**  
 The scan results will appear in the "SCAN RESULTS CONSOLE" showing the URL status, threat details, and detection count.

5. **Malicious Site Alert**  
 If the site is flagged as malicious, an alert popup will appear detailing the threat type and count of security vendors flagging it.

6. **Block or Unblock Site**  
 - To block the flagged site, click **BLOCK SITE** and authenticate with the admin password when prompted.  
 - To unblock a previously blocked site, select the site and click **UNBLOCK SITE**.

7. **View Scan History**  
 Click **VIEW SCAN HISTORY** to access the log of scanned URLs and their results. You can export this data as CSV.

8. **Change Admin Password**  
 Click **CHANGE PASSWORD** to update the admin credentials controlling blocking actions.

9. **Exit**  
 Close the application window when done.

## 📊 Screenshots
<img width="1916" height="1021" alt="image" src="https://github.com/user-attachments/assets/33f0c116-6bf1-4fd3-8427-57349b8936b7" />
<img width="641" height="482" alt="image" src="https://github.com/user-attachments/assets/cd13bf89-27b7-403e-a7fa-87dcf5abd591" />
<img width="506" height="293" alt="image" src="https://github.com/user-attachments/assets/408eae55-0598-4c75-bf3b-59a117b78bd8" />
<img width="419" height="208" alt="image" src="https://github.com/user-attachments/assets/2b60bcb4-8db9-4074-a589-95e368a34445" />
<img width="1355" height="879" alt="image" src="https://github.com/user-attachments/assets/8a1f2f60-e464-4513-915e-ddb5f3946706" />
<img width="495" height="434" alt="image" src="https://github.com/user-attachments/assets/21e75af0-9ee1-4c1d-a120-3a323f1788c3" />
<img width="1894" height="960" alt="image" src="https://github.com/user-attachments/assets/7bdbd534-6ee2-4d7e-be2c-d9e857318ae0" />
<img width="1873" height="899" alt="image" src="https://github.com/user-attachments/assets/da9720e6-cde0-4dee-acb6-ce9a3156b407" />


## 🧑‍💻 Developers
- K. Madhavi Priya  
- V. Hema  
- Sk. Nasrin Sultana  
- Ch. Bhavya  
- P. Preetham

## Organization
**Supraja Technologies**

**Enjoy safer browsing!**
A cybersecurity project to block malicious websites (Internship project).
