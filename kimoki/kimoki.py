#!/usr/bin/env python3
import sys
import socket
import requests
import psutil
import netifaces
import os
import requests
# Buradan sonra `requests` modülünü kullanabilirsiniz.

from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QLabel, QPushButton, 
                             QWidget, QListWidget, QTabWidget, QHBoxLayout, QMessageBox, 
                             QListWidgetItem, QProgressBar, QMenu, QAction)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QPixmap, QIcon
from scapy.all import ARP, Ether, srp
import platform
import ipaddress
import subprocess
os.environ['XDG_RUNTIME_DIR'] = '/tmp/runtime-root'

def get_logo_path():
    """Logo dosyasının yolunu döndürür."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "kimokilo.png")
    elif os.path.exists("/usr/share/icons/hicolor/48x48/apps/kimokilo.png"):
        return "/usr/share/icons/hicolor/48x48/apps/kimokilo.png"
    elif os.path.exists("kimokilo.png"):
        return "kimokilo.png"
    return None

def get_icon_path():
    """Simge dosyasının yolunu döndürür."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "kimokilo.png")
    elif os.path.exists("/usr/share/icons/hicolor/48x48/apps/kimokilo.png"):
        return "/usr/share/icons/hicolor/48x48/apps/kimokilo.png"
    return None

LOGO_PATH = get_logo_path()
ICON_PATH = get_icon_path()

def run_with_fakeroot(command):
    try:
        result = subprocess.run(['fakeroot'] + command, 
                                capture_output=True, 
                                text=True, 
                                check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")
        return ""

def get_network_interface():
    try:
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface.startswith('eth') or iface.startswith('wlan'):
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    ip_info = addresses[netifaces.AF_INET][0]
                    ip = ip_info['addr']
                    netmask = ip_info['netmask']
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
    except Exception as e:
        print(f"Ağ arayüzü tespit hatası: {e}")
    return "192.168.1.0/24"

def scan_lan():
    devices = []
    try:
        target_network = get_network_interface()
        arp = ARP(pdst=target_network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            device = {
                "IP": received.psrc,
                "MAC": received.hwsrc,
                "Vendor": get_device_vendor(received.hwsrc),
                "Hostname": get_hostname(received.psrc),
                "Local": f"{received.psrc}.local"
            }
            device["City"], device["Country"] = get_geo_info(received.psrc)
            devices.append(device)
    except Exception as e:
        print(f"LAN tarama hatası: {e}")
    return devices

def get_device_vendor(mac_address):
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=5)
        return response.text if response.status_code == 200 else "Bilinmiyor"
    except:
        return "Hata oluştu"

def get_geo_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        city = data.get('city', 'Bilinmiyor')
        country = data.get('country', 'Bilinmiyor')
        return city, country
    except:
        return "Bilinmiyor", "Bilinmiyor"

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = "Bilinmiyor"
    return hostname

def get_public_ip_info():
    try:
        public_ip = requests.get('https://api.ipify.org', timeout=5).text
        city, country = get_geo_info(public_ip)
        return public_ip, city, country
    except:
        return "Bilinmiyor", "Bilinmiyor", "Bilinmiyor"

class FetchIPThread(QThread):
    ip_fetched = pyqtSignal(dict)
    progress = pyqtSignal(int, str)

    def run(self):
        try:
            self.progress.emit(10, "Yerel IP adresi alınıyor...")
            local_ip = socket.gethostbyname(socket.gethostname())

            self.progress.emit(50, "Genel IP adresi alınıyor...")
            public_ip, city, country = get_public_ip_info()

            self.progress.emit(100, "IP adresleri alındı.")
            ip_info = {
                "Yerel IP": local_ip,
                "Genel IP": public_ip,
                "Şehir": city,
                "Ülke": country
            }
            self.ip_fetched.emit(ip_info)
        except Exception as e:
            self.ip_fetched.emit({"Hata": str(e)})

class ScanPortsThread(QThread):
    ports_scanned = pyqtSignal(list)
    progress = pyqtSignal(int, str)

    def run(self):
        open_ports = []
        try:
            for i, port in enumerate(range(1, 1025)):
                self.progress.emit(int((i + 1) / 1024 * 100), f"Port {port} taranıyor...")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    open_ports.append(port)
                sock.close()
        except Exception as e:
            print(f"Port tarama hatası: {e}")
        self.ports_scanned.emit(open_ports)

class ScanLANThread(QThread):
    lan_scanned = pyqtSignal(list)
    progress = pyqtSignal(int, str)

    def run(self):
        try:
            self.progress.emit(10, "LAN tarama başlatılıyor...")
            devices = scan_lan()
            self.progress.emit(100, "LAN tarama tamamlandı.")
            self.lan_scanned.emit(devices)
        except Exception as e:
            print(f"LAN tarama hatası: {e}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        if ICON_PATH:  # ICON_PATH önceden tanımlandı
            self.setWindowIcon(QIcon(ICON_PATH))
        
                 # Karanlık tema
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2e2e2e;
                color: #d3d3d3;
            }
            QPushButton {
                background-color: #444444;
                color: #ffffff;
                border-radius: 5px;
                padding: 10px;
                margin: 5px;
            }
            QPushButton:hover {
                background-color: #555555;
            }
            QLabel {
                color: #d3d3d3;
                font-size: 18px;
                margin-bottom: 5px;
            }
            QListWidget {
                background-color: #333333;
                color: #d3d3d3;
                border: 1px solid #555555;
                padding: 10px;
                margin-top: 10px;
            }
            QTabWidget::pane {
                border: none;
            }
            QTabBar::tab {
                background-color: #3a3a3a;
                color: #d3d3d3;
                padding: 10px;
                border-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #555555;
            }
            QTabBar::tab:hover {
                background-color: #444444;
            }
        """)

        self.setWindowTitle("Ağ Araçları")
        self.setGeometry(100, 100, 800, 600)
        self.setFixedSize(800, 600)

        if ICON_PATH:
            self.setWindowIcon(QIcon(ICON_PATH))

        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        
        layout = QVBoxLayout()
        self.tab_widget = QTabWidget()
        self.tab1, self.tab2, self.tab3, self.tab4 = QWidget(), QWidget(), QWidget(), QWidget()
 
        self.setup_tab1()
        self.setup_tab2()
        self.setup_tab3()
        self.setup_tab4()

        self.tab_widget.addTab(self.tab1, "IP Adresleri")
        self.tab_widget.addTab(self.tab2, "Açık Portlar")
        self.tab_widget.addTab(self.tab3, "LAN Cihazları")
        self.tab_widget.addTab(self.tab4, "Hakkında")

        layout.addWidget(self.tab_widget)
        layout.addWidget(self.progress_bar)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.clipboard = QApplication.clipboard()

    def setup_tab1(self):
        layout = QVBoxLayout()
        self.fetch_ip_button = QPushButton("IP Adreslerini Getir")
        self.fetch_ip_button.clicked.connect(self.fetch_ip)
        self.output_list1 = QListWidget()

        layout.addWidget(self.fetch_ip_button)
        layout.addWidget(self.output_list1)
        self.tab1.setLayout(layout)

    def setup_tab2(self):
        layout = QVBoxLayout()
        self.port_test_button = QPushButton("Açık Portları Listele")
        self.port_test_button.clicked.connect(self.test_ports)
        self.output_list2 = QListWidget()

        layout.addWidget(self.port_test_button)
        layout.addWidget(self.output_list2)
        self.tab2.setLayout(layout)

    def setup_tab3(self):
        layout = QVBoxLayout()
        self.lan_scan_button = QPushButton("LAN'deki Cihazları Tara")
        self.lan_scan_button.clicked.connect(self.scan_lan_devices)
        self.output_list3 = QListWidget()

        layout.addWidget(self.lan_scan_button)
        layout.addWidget(self.output_list3)
        self.tab3.setLayout(layout)

    def setup_tab4(self):
        layout = QVBoxLayout()

        logo = QLabel()
        if LOGO_PATH:
            pixmap = QPixmap(LOGO_PATH)
            scaled_pixmap = pixmap.scaled(150, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo.setPixmap(scaled_pixmap)
            logo.setAlignment(Qt.AlignCenter)

        about_label = QLabel()
        about_label.setText("""
        <h1 style="text-align:center;">KimOKi</h1>
        <p style="text-align:justify;">
        Bu uygulama, IP adreslerini almak, açık portları taramak ve LAN'deki cihazları listelemek için tasarlanmıştır.
        </p>
        <p>Sürüm: 1.0</p>
        <p>Geliştirici: ALG Yazılım Inc.©\n</p>
        <p>www.algyazilim.com | info@algyazilim.com\n\n</p>
        <p>Fatih ÖNDER (CekToR) | fatih@algyazilim.com\n</p>
        <p>GitHub: https://github.com/cektor\n\n</p>
        <p>ALG Yazılım Pardus'a Göç'ü Destekler.\n\n</p>
        <p>Telif Hakkı © 2024 GNU .</p>
        """)
        about_label.setAlignment(Qt.AlignCenter)
        about_label.setWordWrap(True)  # Kelime kaydırmayı etkinleştirir
        about_label.setTextInteractionFlags(Qt.TextSelectableByMouse) 

        layout.addWidget(logo)
        layout.addWidget(about_label)
        self.tab4.setLayout(layout)

    def fetch_ip(self):
        self.output_list1.clear()
        self.thread = FetchIPThread()
        self.thread.ip_fetched.connect(self.display_ip_info)
        self.thread.progress.connect(self.update_progress)
        self.thread.start()

    def test_ports(self):
        self.output_list2.clear()
        self.thread = ScanPortsThread()
        self.thread.ports_scanned.connect(self.display_ports)
        self.thread.progress.connect(self.update_progress)
        self.thread.start()

    def scan_lan_devices(self):
        self.output_list3.clear()
        self.thread = ScanLANThread()
        self.thread.lan_scanned.connect(self.display_lan_devices)
        self.thread.progress.connect(self.update_progress)
        self.thread.start()

    def display_ip_info(self, ip_info):
        self.progress_bar.setValue(100)
        if "Hata" in ip_info:
            self.output_list1.addItem(f"Hata: {ip_info['Hata']}")
            return
        for key, value in ip_info.items():
            self.output_list1.addItem(f"{key}: {value}")

    def display_ports(self, open_ports):
        self.progress_bar.setValue(100)
        if open_ports:
            self.output_list2.addItem("Açık Portlar:")
            for port in open_ports:
                self.output_list2.addItem(str(port))
        else:
            self.output_list2.addItem("Hiçbir açık port bulunamadı.")

    def display_lan_devices(self, devices):
        self.progress_bar.setValue(100)
        if devices:
            for device in devices:
                device_info = (f"IP: {device['IP']}\n"
                               f"MAC: {device['MAC']}\n"
                               f"Üretici: {device['Vendor']}\n"
                               f"Ana makine adı: {device['Hostname']}\n"
                               f"Yerel Alan Adı: {device['Local']}\n"
                               f"Şehir: {device['City']}\n"
                               f"Ülke: {device['Country']}")
                self.output_list3.addItem(device_info)
        else:
            self.output_list3.addItem("Hiçbir cihaz bulunamadı. (Yönetici Olarak Çalıştırın.)")
 
    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    if ICON_PATH:
        app.setWindowIcon(QIcon(ICON_PATH))
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
