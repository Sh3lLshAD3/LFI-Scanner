# 🚀 Advanced LFI & RCE Scanner & Multi-Input Smart Link Scraper Studio Pro v7

A high-performance, automated **Vulnerability Scanner and Multi-Query Dork Scraper** built inside a fully interactive, non-blocking Tkinter Desktop Application Studio. 

This program integrates an advanced **Google Search Scraper** powered by Selenium alongside an asynchronous, multi-threaded **Local File Inclusion (LFI) & Remote Code Execution (RCE) payload testing engine**. It is engineered to process over 1,000+ targeted URLs simultaneously with zero UI freezes.

---

## ✨ Features Matrix

### 1. Multi-Query Smart Scraper Studio
* **Multi-Dork Query Input:** Batch executes multiple Google search queries sequentially.
* **Granular Target URL Filtering:** Automatically preserves only links containing user-defined path parameters (e.g., `home.php`) and target parameters (e.g., `page=`).
* **`about:blank` Bypass Architecture:** Embedded window handle tracking timers bypass hanging browser tabs, dropping stalled payloads instantly.
* **Auto-Pivot Scanning:** A toggleable pipeline triggers the LFI/RCE testing engine automatically as soon as the dork scraping operation finishes.

### 2. Multi-Threaded Vulnerability Scanner
* **Lazy Asynchronous Task Building:** Background tasks are queued progressively, ensuring the desktop UI remains responsive when handling massive target sets.
* **Robust Payload Profiles:** Packaged with comprehensive path traversals (`../../etc/passwd`, `..\windows\win.ini`), null-byte injection bypasses (`%00`), PHP stream wrappers (`php://filter`), and execution validation payloads (`data://`).
* **Smart Failure Fallbacks:** If a standard `GET` request yields an access blocked HTTP condition (`403` or `406`), the script executes a parallel `POST` fallback to confirm authorization boundaries.
* **Live CSV & JSON Exporting:** Flushes raw findings directly into localized spreadsheet streams (`lfi_lab_results.csv` and `lfi_lab_results.json`) instantly to secure tracking data.

### 3. Studio Interactive Utilities
* **Right-Click Analytical Context Menu:** Direct integration inside live results to *Copy URL*, *Open Rendered Response in Browser*, or *View Request/Res Mappings*.
* **Granular Log Searching:** Interactive lookup input fields filter terminal events dynamically based on custom warning levels (`VULN`, `ERROR`, `SUCCESS`).
* **Base64 Decoder Tool:** Integrated encoder utility to decrypt discovered source code extractions directly from the dashboard interface.

---

## 🛠️ System Prerequisites
Before running the studio application, ensure your machine satisfies the following baseline system dependencies:
* **Python Runtime Environment:** Version `3.8` or higher installed (v3.10+ highly recommended).
* **Google Chrome Web Browser:** Must be installed locally on your desktop machine (Selenium WebDriver Manager will automatically sync matching system drivers).

---

## 💻 Step-by-Step Installation by Operating System

First, download the project from GitHub and extract the ZIP file into a fresh folder on your computer. Then, open your terminal/command line **inside that extracted folder** and follow the specific instructions for your Operating System below:

### 🪟 1. Windows Installation Guide
You can install this using either the standard **Command Prompt (cmd)** or **PowerShell**.

#### Option A: Using Windows Command Prompt (cmd)
```cmd
# 1. Create a clean virtual environment space
python -m venv env

# 2. Activate the workspace environment session
.\env\Scripts\activate

# 3. Install all core application and package dependencies
pip install requests urllib3 selenium webdriver-manager pandas openpyxl pyautogui

# 4. Launch the GUI Application Studio
python main.py
```

#### Option B: Using Windows PowerShell
```powershell
# 1. Create a clean virtual environment space
python -m venv env

# 2. Activate the workspace environment session
.\env\Scripts\activate.ps1

# 3. Install all core application and package dependencies
pip install requests urllib3 selenium webdriver-manager pandas openpyxl pyautogui

# 4. Launch the GUI Application Studio
python main.py
```
*💡 **Note for PowerShell Users:** If you get an error saying "Running scripts is disabled on this system", open PowerShell as Administrator and run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force`, then try step 2 again.*

---

### 🍏 2. macOS Installation Guide
macOS requires explicit pathing for Python 3 and Tkinter graphics dependencies.

```bash
# 1. Install Tkinter system bindings (Required for macOS Tkinter GUI stability)
# (If you don't have Homebrew installed, visit brew.sh first)
brew install python-tk

# 2. Create a clean virtual environment space
python3 -m venv env

# 3. Activate the workspace environment session
source env/bin/activate

# 4. Install all core application and package dependencies
pip install requests urllib3 selenium webdriver-manager pandas openpyxl pyautogui

# 5. Launch the GUI Application Studio
python3 main.py
```

---

### 🐧 3. Linux Installation Guide (Ubuntu/Debian-based)
Most Linux distributions do not include Tkinter or standard screen capture utilities by default. You must install the system-level packages first to avoid `ImportError` or UI rendering failures.

```bash
# 1. Install required system dependencies for Tkinter GUI and PyAutoGUI mapping
sudo apt update
sudo apt install -y python3-tk python3-dev scrot xclip

# 2. Create a clean virtual environment space
python3 -m venv env

# 3. Activate the workspace environment session
source env/bin/activate

# 4. Upgrade pip tool to prevent setup packaging wheels bottlenecks
pip install --upgrade pip

# 5. Install all core application and package dependencies
pip install requests urllib3 selenium webdriver-manager pandas openpyxl pyautogui

# 6. Launch the GUI Application Studio
python3 main.py
```

---

### 🔍 Installation Troubleshooting Checklist
* **Tkinter / Tcl Errors:** If the app fails to start with a `ModuleNotFoundError: No module named '_tkinter'`, it means your system is missing the visual UI window drivers. Run `brew install python-tk` (on Mac) or `sudo apt install python3-tk` (on Linux) to fix it.
* **PyAutoGUI Scrot Failures (Linux):** If `pyautogui` throws an execution error, make sure you ran `sudo apt install scrot` so the application engine can cleanly clear and capture background window constraints.

---

## 🚀 Execution & Usage Blueprint

### Step A: Harvesting Links (Multi-Query Scraper Tab)
1. Navigate to the **Multi-Query Smart Scraper** tab inside the dashboard.
2. Enter your Google Search Dorks into the textbox (one per line, e.g., `"home.php?page=" site:.gov`).
3. Define your target filter rules under **Required Path** (e.g., `home.php`) and **Required Parameter** (e.g., `page`).
4. Click **Start Multi-Query Scraper**. A visual Chrome browser instance will spin up. 
5. Complete any manual verification puzzles if prompted, and the script will automatically harvest and pass compliant URLs directly into the Scanner.

### Step B: Testing Vulnerabilities (Scanner Studio Tab)
1. Switch to the **LFI & RCE Scanner Studio** tab. Your harvested links will appear inside the target input box (you can also manually add URLs or load external `.txt/.csv/.xlsx` files via the **Browse File** button).
2. Set your execution speed thread bounds by configuring the **Workers** adjustment spinner (Default is 4, max recommended is 16).
3. Click **START SCAN**.
4. Discovered vulnerabilities will be instantly highlighted in **Bright Red**. Right-click on any row item to inspect deep raw request payloads or view raw server tracking strings inside a new tab.

---

## 📂 Generated Artifacts
* `raw_scraped_links.csv` — An unstructured streaming repository recording every external link scraped prior to applying path validations.
* `lfi_lab_results.csv` — The core structured testing spreadsheet containing timestamps, parameters, responses, and vulnerability classifications.
* `lfi_lab_results.json` — A database object dictionary dump capturing full HTTP request/response headers for external API analysis integrations.

---
⚠️ **Disclaimer:** This studio toolkit is developed exclusively for authorized security research, educational simulation, and white-hat penetration benchmarking workflows. Ensure target server authorization guidelines (`robots.txt` compliance) are validated routinely before engaging remote instances.
