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
                             QListWidgetItem, QProgressBar, QMenu, QAction, QFileDialog, 
                             QInputDialog, QSystemTrayIcon, QStatusBar, QToolTip, QSpinBox, 
                             QComboBox, QCheckBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QSettings
from PyQt5.QtGui import QPixmap, QIcon
from scapy.all import ARP, Ether, srp
import platform
import ipaddress
import subprocess
from datetime import datetime
os.environ['XDG_RUNTIME_DIR'] = '/tmp/runtime-root'

# Dil çevirilerini ekle (MainWindow sınıfından önce)
TRANSLATIONS = {
    'tr': {
        # Tab başlıkları
        'ip_addresses': "IP Adresleri",
        'open_ports': "Açık Portlar",
        'lan_devices': "LAN Cihazları",
        'settings': "Seçenekler",
        'about': "Hakkında",
        
        # Butonlar
        'get_ip': "IP Adreslerini Getir",
        'scan_ports': "Açık Portları Listele",
        'scan_lan': "LAN'deki Cihazları Tara",
        'scanning': "Taranıyor...",
        'save': "Kaydet",
        
        # Ayarlar
        'language': "Dil",
        'show_tray': "Sistem Tepsisinde Göster",
        'auto_scan': "Otomatik Tarama",
        'off': "Kapalı",
        'min_5': "5 dakika",
        'min_15': "15 dakika",
        'min_30': "30 dakika",
        
        # Sağ tık menüsü
        'copy_selected': "Seçileni Kopyala",
        'copy_all': "Tümünü Kopyala",
        'save_results': "Sonuçları Kaydet",
        
        # IP bilgileri
        'local_ip': "Yerel IP",
        'network_interface': "Ağ Arayüzü",
        'subnet_mask': "Alt Ağ Maskesi",
        'public_ip': "Genel IP",
        'city': "Şehir",
        'country': "Ülke",
        'computer_name': "Bilgisayar Adı",
        'hostname': "Ana Makine Adı",
        'mac_address': "MAC Adresi",
        'vendor': "Üretici",
        'local_domain': "Yerel Alan Adı",
        
        # Port tarama
        'port_info': "En yaygın kullanılan portlar (1-1024) ve bazı özel portlar taranacaktır.",
        'port': "Port",
        'service': "Servis",
        'unknown_service': "Bilinmeyen Servis",
        'open_ports_title': "=== Açık Portlar ===",
        'total_ports_found': "Toplam {} açık port bulundu.",
        
        # LAN tarama
        'no_devices': "Hiçbir cihaz bulunamadı. (Yönetici Olarak Çalıştırın.)",
        'scanning_network': "Ağ taranıyor...",
        'device_found': "Cihaz bulundu:",
        
        # Durum mesajları
        'scan_complete': "Tarama tamamlandı",
        'scan_started': "Tarama başlatılıyor...",
        'open_ports_found': "{} açık port bulundu",
        'no_open_ports': "Hiçbir açık port bulunamadı",
        'getting_ip': "IP adresleri alınıyor...",
        'ip_received': "IP adresleri alındı",
        
        # Sistem tepsisi
        'show': "Göster",
        'exit': "Çıkış",
        'tray_info': "Program sistem tepsisinde çalışmaya devam edecek.",
        'minimized_info': "Program küçültüldü",
        
        # Uyarılar ve hatalar
        'warning': "Uyarı",
        'error': "Hata",
        'no_results': "Kaydedilecek sonuç bulunamadı!",
        'save_error': "Dosya kaydedilirken hata oluştu: {}",
        'network_error': "Ağ hatası: {}",
        'permission_error': "Yetki hatası. Programı yönetici olarak çalıştırın.",
        
        # Kopyalama ve kaydetme
        'copied_selected': "Seçili öğe panoya kopyalandı!",
        'copied_all': "Tüm öğeler panoya kopyalandı!",
        'saved_to': "Sonuçlar {} dosyasına kaydedildi!",
        'save_dialog_title': "Sonuçları Kaydet",
        
        # Hakkında metni
        'about_text': """
<h1 style="text-align:center;">KimOKi</h1>
<p style="text-align:justify;">
Bu uygulama, IP adreslerini almak, açık portları taramak ve LAN'deki cihazları listelemek için tasarlanmıştır.
</p>
<p>Sürüm: 1.0</p>
<p>Geliştirici: ALG Yazılım Inc.©</p>
<p>www.algyazilim.com | info@algyazilim.com</p>
<p>Fatih ÖNDER (CekToR) | fatih@algyazilim.com</p>
<p>GitHub: https://github.com/cektor</p>
<p>ALG Yazılım Pardus'a Göç'ü Destekler.</p>
<p>Telif Hakkı © 2024 GNU</p>
""",
        
        # GUI elemanları
        'auto_scan_label': "Otomatik Tarama:",
        'auto_scan_off': "Kapalı",
        'auto_scan_5min': "5 dakika",
        'auto_scan_15min': "15 dakika",
        'auto_scan_30min': "30 dakika",
        'port_info_label': "En yaygın kullanılan portlar (1-1024) ve bazı özel portlar taranacaktır.",
        'scanning_port': "Port {} taranıyor...",
        'scanning_complete': "Tarama tamamlandı",
        'scanning_button': "Taranıyor...",
        'scan_button': "Açık Portları Listele",
        
        # IP bilgileri
        'getting_local_info': "Yerel ağ bilgileri alınıyor...",
        'getting_public_info': "Genel IP adresi alınıyor...",
        'ip_info_received': "IP adresleri alındı",
        'interface_not_found': "Bulunamadı",
        'unknown_vendor': "Bilinmeyen Üretici",
        'unknown_hostname': "Bilinmeyen Ana Makine",
        
        # LAN tarama
        'starting_lan_scan': "LAN taraması başlatılıyor...",
        'lan_scan_complete': "LAN taraması tamamlandı",
        'device_info': """IP: {}
MAC: {}
Üretici: {}
Ana makine adı: {}
Yerel Alan Adı: {}
Şehir: {}
Ülke: {}""",
        
        # Dosya işlemleri
        'file_name_template': "kimoki_sonuclar_{}.txt",
        'text_files': "Metin Dosyaları (*.txt)",
        
        # Sistem tepsisi
        'tray_tooltip': "KimOKi - Ağ Tarama Aracı",
        'minimized_tooltip': "KimOKi küçültüldü",
        
        # Genel mesajlar
        'initializing': "Başlatılıyor...",
        'ready': "Hazır",
        'processing': "İşleniyor...",
        'completed': "Tamamlandı",
        'canceled': "İptal edildi",
        'unknown': "Bilinmiyor",
        'not_available': "Mevcut değil",
        
        # Tema ayarları
        'theme_label': "Tema:",
        'theme_light': "Açık Tema",
        'theme_dark': "Koyu Tema",
        
        # Yeniden başlatma mesajları
        'restart_required': "Yeniden Başlatma Gerekli",
        'language_change_restart': "Dil değişikliğinin etkili olması için uygulama yeniden başlatılacak.",
        'theme_change_restart': "Tema değişikliğinin tam olarak uygulanması için uygulama yeniden başlatılacak.",
        'restart_now': "Şimdi Yeniden Başlat",
        
        # Progress bar mesajları
        'progress_getting_ip': "IP adresleri alınıyor... %{}",
        'progress_scanning_port': "Port %{} taranıyor...",
        'progress_scanning_lan': "LAN taranıyor... %{}",
        'progress_complete': "Tamamlandı",
        
        # IP adresleri çıktıları
        'output_local_ip': "Yerel IP: {}",
        'output_public_ip': "Genel IP: {}",
        'output_network_interface': "Ağ Arayüzü: {}",
        'output_mac_address': "MAC Adresi: {}",
        'output_subnet_mask': "Alt Ağ Maskesi: {}",
        'output_hostname': "Bilgisayar Adı: {}",
        'output_city': "Şehir: {}",
        'output_country': "Ülke: {}",
        'output_isp': "İnternet Servis Sağlayıcı: {}",
        'output_organization': "Organizasyon: {}",
        
        # Açık portlar çıktıları
        'output_port_header': "=== Açık Portlar ===",
        'output_port_entry': "Port {}: {} {}",  # Port numarası, servis adı, uygulama adı
        'output_port_count': "\nToplam {} açık port bulundu.",
        'output_no_ports': "Hiçbir açık port bulunamadı.",
        
        # LAN cihazları çıktıları
        'output_device_header': "=== Ağdaki Cihazlar ===",
        'output_device_entry': """
Cihaz {}:
  IP Adresi: {}
  MAC Adresi: {}
  Üretici: {}
  Ana Makine Adı: {}
  Yerel Alan Adı: {}""",
        'output_device_count': "\nToplam {} cihaz bulundu.",
        'output_no_devices': "Ağda hiçbir cihaz bulunamadı.",
        
        # Hakkında metni
        'about_title': "KimOKi - Ağ Tarama Aracı",
        'about_version': "Sürüm: 1.0",
        'about_description': """Bu uygulama, ağ güvenliği ve yönetimi için geliştirilmiş bir araçtır.

Özellikler:
• IP adreslerini görüntüleme
• Açık portları tarama
• LAN cihazlarını keşfetme
• Otomatik tarama
• Çoklu dil desteği
• Karanlık/Açık tema""",
        'about_developer': "Geliştirici: ALG Yazılım Inc.©",
        'about_contact': """İletişim:
www.algyazilim.com
info@algyazilim.com""",
        'about_author': "Fatih ÖNDER (CekToR)",
        'about_email': "fatih@algyazilim.com",
        'about_github': "GitHub: https://github.com/cektor",
        'about_support': "ALG Yazılım Pardus'a Göç'ü Destekler.",
        'about_copyright': "Telif Hakkı © 2024 GNU",
    },
    'en': {
        # Tab titles
        'ip_addresses': "IP Addresses",
        'open_ports': "Open Ports",
        'lan_devices': "LAN Devices",
        'settings': "Settings",
        'about': "About",
        
        # Buttons
        'get_ip': "Get IP Addresses",
        'scan_ports': "List Open Ports",
        'scan_lan': "Scan LAN Devices",
        'scanning': "Scanning...",
        'save': "Save",
        
        # Settings
        'language': "Language",
        'show_tray': "Show in System Tray",
        'auto_scan': "Auto Scan",
        'off': "Off",
        'min_5': "5 minutes",
        'min_15': "15 minutes",
        'min_30': "30 minutes",
        
        # Right-click menu
        'copy_selected': "Copy Selected",
        'copy_all': "Copy All",
        'save_results': "Save Results",
        
        # IP information
        'local_ip': "Local IP",
        'network_interface': "Network Interface",
        'subnet_mask': "Subnet Mask",
        'public_ip': "Public IP",
        'city': "City",
        'country': "Country",
        'computer_name': "Computer Name",
        'hostname': "Hostname",
        'mac_address': "MAC Address",
        'vendor': "Vendor",
        'local_domain': "Local Domain",
        
        # Port scanning
        'port_info': "Most common ports (1-1024) and some special ports will be scanned.",
        'port': "Port",
        'service': "Service",
        'unknown_service': "Unknown Service",
        'open_ports_title': "=== Open Ports ===",
        'total_ports_found': "Total {} open ports found.",
        
        # LAN scanning
        'no_devices': "No devices found. (Run as Administrator)",
        'scanning_network': "Scanning network...",
        'device_found': "Device found:",
        
        # Status messages
        'scan_complete': "Scan completed",
        'scan_started': "Starting scan...",
        'open_ports_found': "{} open ports found",
        'no_open_ports': "No open ports found",
        'getting_ip': "Getting IP addresses...",
        'ip_received': "IP addresses received",
        
        # System tray
        'show': "Show",
        'exit': "Exit",
        'tray_info': "Program will continue running in system tray.",
        'minimized_info': "Program minimized",
        
        # Warnings and errors
        'warning': "Warning",
        'error': "Error",
        'no_results': "No results to save!",
        'save_error': "Error saving file: {}",
        'network_error': "Network error: {}",
        'permission_error': "Permission error. Run the program as administrator.",
        
        # Copying and saving
        'copied_selected': "Selected item copied to clipboard!",
        'copied_all': "All items copied to clipboard!",
        'saved_to': "Results saved to {} file!",
        'save_dialog_title': "Save Results",
        
        # About text
        'about_text': """
<h1 style="text-align:center;">KimOKi</h1>
<p style="text-align:justify;">
This application is designed to get IP addresses, scan open ports and list devices on LAN.
</p>
<p>Version: 1.0</p>
<p>Developer: ALG Software Inc.©</p>
<p>www.algyazilim.com | info@algyazilim.com</p>
<p>Fatih ÖNDER (CekToR) | fatih@algyazilim.com</p>
<p>GitHub: https://github.com/cektor</p>
<p>ALG Software Supports Migration to Pardus.</p>
<p>Copyright © 2024 GNU</p>
""",
        
        # GUI elements
        'auto_scan_label': "Auto Scan:",
        'auto_scan_off': "Off",
        'auto_scan_5min': "5 minutes",
        'auto_scan_15min': "15 minutes",
        'auto_scan_30min': "30 minutes",
        'port_info_label': "Most common ports (1-1024) and some special ports will be scanned.",
        'scanning_port': "Scanning port {}...",
        'scanning_complete': "Scanning complete",
        'scanning_button': "Scanning...",
        'scan_button': "List Open Ports",
        
        # IP information
        'getting_local_info': "Getting local network information...",
        'getting_public_info': "Getting public IP address...",
        'ip_info_received': "IP addresses received",
        'interface_not_found': "Not Found",
        'unknown_vendor': "Unknown Vendor",
        'unknown_hostname': "Unknown Hostname",
        
        # LAN scanning
        'starting_lan_scan': "Starting LAN scan...",
        'lan_scan_complete': "LAN scan completed",
        'device_info': """IP: {}
MAC: {}
Vendor: {}
Hostname: {}
Local Domain: {}
City: {}
Country: {}""",
        
        # File operations
        'file_name_template': "kimoki_results_{}.txt",
        'text_files': "Text Files (*.txt)",
        
        # System tray
        'tray_tooltip': "KimOKi - Network Scanner",
        'minimized_tooltip': "KimOKi minimized",
        
        # General messages
        'initializing': "Initializing...",
        'ready': "Ready",
        'processing': "Processing...",
        'completed': "Completed",
        'canceled': "Canceled",
        'unknown': "Unknown",
        'not_available': "Not available",
        
        # Theme settings
        'theme_label': "Theme:",
        'theme_light': "Light Theme",
        'theme_dark': "Dark Theme",
        
        # Restart messages
        'restart_required': "Restart Required",
        'language_change_restart': "The application will restart for the language change to take effect.",
        'theme_change_restart': "The application will restart for the theme change to be fully applied.",
        'restart_now': "Restart Now",
        
        # Progress bar messages
        'progress_getting_ip': "Getting IP addresses... %{}",
        'progress_scanning_port': "Scanning port %{}...",
        'progress_scanning_lan': "Scanning LAN... %{}",
        'progress_complete': "Completed",
        
        # IP addresses outputs
        'output_local_ip': "Local IP: {}",
        'output_public_ip': "Public IP: {}",
        'output_network_interface': "Network Interface: {}",
        'output_mac_address': "MAC Address: {}",
        'output_subnet_mask': "Subnet Mask: {}",
        'output_hostname': "Computer Name: {}",
        'output_city': "City: {}",
        'output_country': "Country: {}",
        'output_isp': "Internet Service Provider: {}",
        'output_organization': "Organization: {}",
        
        # Open ports outputs
        'output_port_header': "=== Open Ports ===",
        'output_port_entry': "Port {}: {} {}",  # Port number, service name, application name
        'output_port_count': "\nTotal {} open ports found.",
        'output_no_ports': "No open ports found.",
        
        # LAN devices outputs
        'output_device_header': "=== Network Devices ===",
        'output_device_entry': """
Device {}:
  IP Address: {}
  MAC Address: {}
  Vendor: {}
  Hostname: {}
  Local Domain: {}""",
        'output_device_count': "\nTotal {} devices found.",
        'output_no_devices': "No devices found on the network.",
        
        # About text
        'about_title': "KimOKi - Network Scanner",
        'about_version': "Version: 1.0",
        'about_description': """This application is a tool developed for network security and management.

Features:
• View IP addresses
• Scan open ports
• Discover LAN devices
• Automatic scanning
• Multiple language support
• Dark/Light theme""",
        'about_developer': "Developer: ALG Software Inc.©",
        'about_contact': """Contact:
www.algyazilim.com
info@algyazilim.com""",
        'about_author': "Fatih ÖNDER (CekToR)",
        'about_email': "fatih@algyazilim.com",
        'about_github': "GitHub: https://github.com/cektor",
        'about_support': "ALG Software Supports Migration to Pardus.",
        'about_copyright': "Copyright © 2024 GNU",
    }
}

# MainWindow sınıfından önce tema stillerini tanımlayalım
THEMES = {
    'light': """
        QMainWindow, QWidget {
            background-color: #f0f0f0;
            color: #000000;
        }
        QPushButton {
            background-color: #e0e0e0;
            color: #000000;
            border: 1px solid #c0c0c0;
            border-radius: 5px;
            padding: 10px 20px;
            margin: 5px;
        }
        QPushButton:hover {
            background-color: #d0d0d0;
        }
        QPushButton:pressed {
            background-color: #c0c0c0;
        }
        QListWidget {
            background-color: #ffffff;
            color: #000000;
            border: 1px solid #c0c0c0;
            border-radius: 5px;
        }
        QLabel {
            color: #000000;
        }
        QComboBox, QSpinBox {
            background-color: #ffffff;
            color: #000000;
            border: 1px solid #c0c0c0;
            border-radius: 3px;
            padding: 5px;
        }
        QProgressBar {
            border: 1px solid #c0c0c0;
            border-radius: 5px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #0078d7;
        }
        QTabWidget::pane {
            border: 1px solid #c0c0c0;
        }
        QTabBar::tab {
            background-color: #e0e0e0;
            color: #000000;
            padding: 8px 20px;
        }
        QTabBar::tab:selected {
            background-color: #f0f0f0;
        }
        QStatusBar {
            background-color: #f0f0f0;
            color: #000000;
        }
    """,
    'dark': """
        QMainWindow, QWidget {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QPushButton {
            background-color: #3d3d3d;
            color: #ffffff;
            border: none;
            border-radius: 5px;
            padding: 10px 20px;
            margin: 5px;
        }
        QPushButton:hover {
            background-color: #4a4a4a;
        }
        QPushButton:pressed {
            background-color: #2d2d2d;
        }
        QListWidget {
            background-color: #333333;
            color: #ffffff;
            border: 1px solid #444444;
            border-radius: 5px;
        }
        QLabel {
            color: #ffffff;
        }
        QComboBox, QSpinBox {
            background-color: #3d3d3d;
            color: #ffffff;
            border: 1px solid #444444;
            border-radius: 3px;
            padding: 5px;
        }
        QProgressBar {
            border: 1px solid #444444;
            border-radius: 5px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #3d8ec9;
        }
        QTabWidget::pane {
            border: 1px solid #444444;
        }
        QTabBar::tab {
            background-color: #3d3d3d;
            color: #ffffff;
            padding: 8px 20px;
        }
        QTabBar::tab:selected {
            background-color: #4a4a4a;
        }
        QStatusBar {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QMessageBox {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QMessageBox QPushButton {
            min-width: 80px;
        }
    """
}

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

    def get_network_ip(self):
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                # Ethernet veya WiFi arayüzlerini kontrol et
                if iface.startswith(('eth', 'wlan', 'en', 'wl')):  # en ve wl Linux'taki yeni isimlendirmeler için
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:  # IPv4 adresi varsa
                        ip_info = addrs[netifaces.AF_INET][0]
                        return {
                            'ip': ip_info['addr'],
                            'interface': iface,
                            'netmask': ip_info.get('netmask', 'Bilinmiyor')
                        }
            return None
        except Exception as e:
            print(f"Ağ IP'si alınırken hata: {e}")
            return None

    def run(self):
        try:
            self.progress.emit(10, "Yerel ağ bilgileri alınıyor...")
            network_info = self.get_network_ip()
            
            self.progress.emit(50, "Genel IP adresi alınıyor...")
            public_ip, city, country = get_public_ip_info()

            self.progress.emit(100, "IP adresleri alındı.")
            
            ip_info = {
                "Yerel IP": network_info['ip'] if network_info else "Bulunamadı",
                "Ağ Arayüzü": network_info['interface'] if network_info else "Bulunamadı",
                "Alt Ağ Maskesi": network_info['netmask'] if network_info else "Bulunamadı",
                "Genel IP": public_ip,
                "Şehir": city,
                "Ülke": country
            }
            
            # Hostname bilgisini ekle
            try:
                hostname = socket.gethostname()
                ip_info["Bilgisayar Adı"] = hostname
            except:
                ip_info["Bilgisayar Adı"] = "Bulunamadı"

            self.ip_fetched.emit(ip_info)
            
        except Exception as e:
            self.ip_fetched.emit({"Hata": str(e)})

class ScanPortsThread(QThread):
    ports_scanned = pyqtSignal(list)
    progress = pyqtSignal(int, str)

    def __init__(self):
        super().__init__()
        self.is_running = True
        # Taranacak portların listesi
        self.ports_to_scan = list(range(1, 1025))  # Well-known portlar
        # Ek önemli portlar
        additional_ports = [
            1433,  # MSSQL
            1521,  # Oracle
            3306,  # MySQL
            5432,  # PostgreSQL
            8080,  # HTTP Alternate
            8443,  # HTTPS Alternate
            27017, # MongoDB
            6379,  # Redis
            5672,  # RabbitMQ
            9200,  # Elasticsearch
            3389,  # RDP
            22,    # SSH
            21,    # FTP
            25,    # SMTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            80,    # HTTP
            53     # DNS
        ]
        # Listeye ek portları ekle (tekrarları önle)
        self.ports_to_scan.extend(x for x in additional_ports if x not in self.ports_to_scan)
        # Portları sırala
        self.ports_to_scan.sort()

    def stop(self):
        self.is_running = False

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.1)
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Bilinmeyen Servis"
                    
                    # Çalışan uygulamayı bul
                    try:
                        for conn in psutil.net_connections(kind='inet'):
                            if conn.laddr.port == port:
                                try:
                                    process = psutil.Process(conn.pid)
                                    service += f" ({process.name()})"
                                except:
                                    pass
                                break
                    except:
                        pass
                    
                    return port, service
            return None
        except:
            return None

    def run(self):
        open_ports = []
        try:
            total_ports = len(self.ports_to_scan)
            scanned = 0
            
            for port in self.ports_to_scan:
                if not self.is_running:
                    break
                
                scanned += 1
                progress = int(scanned / total_ports * 100)
                self.progress.emit(progress, f"Port {port} taranıyor...")
                
                result = self.scan_port(port)
                if result:
                    open_ports.append(result)
                    
        except Exception as e:
            print(f"Port tarama hatası: {e}")
        finally:
            self.progress.emit(100, "Tarama tamamlandı")
            self.ports_scanned.emit(open_ports)

class ScanLANThread(QThread):
    lan_scanned = pyqtSignal(list)
    progress = pyqtSignal(int, str)

    def get_local_ip_and_network(self):
        try:
            # Aktif ağ arayüzünü bul
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:  # IPv4 adresi varsa
                    ip_info = addrs[netifaces.AF_INET][0]
                    if 'addr' in ip_info and not ip_info['addr'].startswith('127.'):
                        ip = ip_info['addr']
                        netmask = ip_info['netmask']
                        # IP ve alt ağı kullanarak ağ adresini hesapla
                        network = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
                        return ip, network
            return None, None
        except Exception as e:
            print(f"Ağ bilgisi alınamadı: {e}")
            return None, None

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Bilinmiyor"

    def get_vendor(self, mac):
        try:
            # MAC adresinin ilk 6 karakterini al (üretici kodu)
            oui = mac.replace(":", "").replace("-", "").upper()[:6]
            url = f"https://api.macvendors.com/{oui}"
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                return response.text
            return "Bilinmiyor"
        except:
            return "Bilinmiyor"

    def run(self):
        try:
            devices = []
            local_ip, network = self.get_local_ip_and_network()
            
            if not local_ip or not network:
                self.lan_scanned.emit([])
                return

            # ARP taraması yerine ping taraması yapalım
            network_obj = ipaddress.IPv4Network(network)
            total_ips = len(list(network_obj.hosts()))
            scanned = 0

            for ip in network_obj.hosts():
                ip_str = str(ip)
                if str(ip) == local_ip:  # Kendi IP'mizi atlayalım
                    continue

                scanned += 1
                progress = int((scanned / total_ips) * 100)
                self.progress.emit(progress, f"IP {ip_str} taranıyor...")

                # Ping kontrolü
                try:
                    if platform.system().lower() == "windows":
                        ping_cmd = ["ping", "-n", "1", "-w", "500", ip_str]
                    else:
                        ping_cmd = ["ping", "-c", "1", "-W", "1", ip_str]
                    
                    result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    if result.returncode == 0:  # Ping başarılı
                        # ARP tablosundan MAC adresini al
                        if platform.system().lower() == "windows":
                            arp_cmd = ["arp", "-a", ip_str]
                        else:
                            arp_cmd = ["arp", "-n", ip_str]
                        
                        arp_result = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        mac = "Bilinmiyor"
                        
                        if arp_result.returncode == 0:
                            # MAC adresini ARP çıktısından ayıkla
                            for line in arp_result.stdout.split('\n'):
                                if ip_str in line:
                                    parts = line.split()
                                    for part in parts:
                                        if ':' in part or '-' in part:
                                            mac = part
                                            break

                        hostname = self.get_hostname(ip_str)
                        vendor = self.get_vendor(mac) if mac != "Bilinmiyor" else "Bilinmiyor"
                        
                        device_info = {
                            'IP': ip_str,
                            'MAC': mac,
                            'Vendor': vendor,
                            'Hostname': hostname,
                            'Local': socket.getfqdn(ip_str),
                            'City': 'Yerel Ağ',
                            'Country': 'Yerel Ağ'
                        }
                        devices.append(device_info)

                except Exception as e:
                    print(f"Hata ({ip_str}): {e}")
                    continue

            self.progress.emit(100, "Tarama tamamlandı")
            self.lan_scanned.emit(devices)
            
        except Exception as e:
            print(f"LAN tarama hatası: {e}")
            self.lan_scanned.emit([])

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # QSettings nesnesini oluştur
        self.settings = QSettings('ALG Software', 'KimOKi')
        
        # Dil ve tema ayarlarını yükle
        self.current_language = self.settings.value('language', 'tr')
        self.current_theme = self.settings.value('theme', 'dark')
        self.show_in_tray = self.settings.value('show_in_tray', 'true').lower() == 'true'
        
        # Temayı uygula
        self.apply_theme(self.current_theme)
        
        # Pencere simgesi
        if ICON_PATH:
            self.setWindowIcon(QIcon(ICON_PATH))
        
        # Pencere başlığı ve boyutu
        self.setWindowTitle("KimOKi")
        self.setFixedSize(800, 600)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        
        # Ana layout
        layout = QVBoxLayout()
        
        # Tab widget'ı oluştur
        self.tab_widget = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()
        self.tab4 = QWidget()
        self.tab5 = QWidget()
        
        # Tabları ayarla
        self.setup_tab1()
        self.setup_tab2()
        self.setup_tab3()
        self.setup_tab4()
        self.setup_tab5()
        
        # Tab başlıklarını ayarla
        self.tab_widget.addTab(self.tab1, self.tr('ip_addresses'))
        self.tab_widget.addTab(self.tab2, self.tr('open_ports'))
        self.tab_widget.addTab(self.tab3, self.tr('lan_devices'))
        self.tab_widget.addTab(self.tab4, self.tr('settings'))
        self.tab_widget.addTab(self.tab5, self.tr('about'))
        
        # Layout'a widget'ları ekle
        layout.addWidget(self.tab_widget)
        layout.addWidget(self.progress_bar)
        
        # Ana container'ı ayarla
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
        # Clipboard'ı ayarla
        self.clipboard = QApplication.clipboard()
        
        # Status bar'ı ayarla
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        
        # Sistem tepsisi simgesini ayarla
        if self.show_in_tray:
            self.setup_system_tray()
        
        # Otomatik tarama için timer
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.auto_scan)
        
        # Tooltip stilleri
        QToolTip.setFont(QApplication.font())

    def setup_tab1(self):
        layout = QVBoxLayout()
        
        # IP tarama ayarları
        settings_layout = QHBoxLayout()
        self.auto_scan_cb = QComboBox()
        self.auto_scan_cb.addItems([
            self.tr('auto_scan_off'),
            self.tr('auto_scan_5min'),
            self.tr('auto_scan_15min'),
            self.tr('auto_scan_30min')
        ])
        self.auto_scan_cb.currentTextChanged.connect(self.set_auto_scan)
        settings_layout.addWidget(QLabel(self.tr('auto_scan_label')))
        settings_layout.addWidget(self.auto_scan_cb)
        
        self.fetch_ip_button = QPushButton(self.tr('get_ip'))
        self.fetch_ip_button.setToolTip(self.tr('getting_local_info'))
        self.fetch_ip_button.clicked.connect(self.fetch_ip)
        
        self.output_list1 = QListWidget()
        self.output_list1.setContextMenuPolicy(Qt.CustomContextMenu)
        self.output_list1.customContextMenuRequested.connect(self.show_context_menu)
        
        layout.addLayout(settings_layout)
        layout.addWidget(self.fetch_ip_button)
        layout.addWidget(self.output_list1)
        self.tab1.setLayout(layout)

    def setup_tab2(self):
        layout = QVBoxLayout()
        
        info_label = QLabel(self.tr('port_info_label'))
        info_label.setWordWrap(True)
        
        self.port_test_button = QPushButton(self.tr('scan_button'))
        self.port_test_button.setToolTip(self.tr('port_info'))
        self.port_test_button.clicked.connect(self.test_ports)
        
        self.output_list2 = QListWidget()
        self.output_list2.setContextMenuPolicy(Qt.CustomContextMenu)
        self.output_list2.customContextMenuRequested.connect(self.show_context_menu)
        
        layout.addWidget(info_label)
        layout.addWidget(self.port_test_button)
        layout.addWidget(self.output_list2)
        self.tab2.setLayout(layout)

    def setup_tab3(self):
        layout = QVBoxLayout()
        self.lan_scan_button = QPushButton(self.tr('scan_lan'))
        self.lan_scan_button.clicked.connect(self.scan_lan_devices)
        self.output_list3 = QListWidget()
        self.output_list3.setContextMenuPolicy(Qt.CustomContextMenu)
        self.output_list3.customContextMenuRequested.connect(self.show_context_menu)

        layout.addWidget(self.lan_scan_button)
        layout.addWidget(self.output_list3)
        self.tab3.setLayout(layout)

    def setup_tab4(self):
        layout = QVBoxLayout()
        
        # Dil seçimi
        lang_layout = QHBoxLayout()
        lang_label = QLabel(self.tr('language'))
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(['Türkçe', 'English'])
        self.lang_combo.setCurrentText('Türkçe' if self.current_language == 'tr' else 'English')
        self.lang_combo.currentTextChanged.connect(self.change_language)
        lang_layout.addWidget(lang_label)
        lang_layout.addWidget(self.lang_combo)
        
        # Tema seçimi
        theme_layout = QHBoxLayout()
        theme_label = QLabel(self.tr('theme_label'))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems([self.tr('theme_light'), self.tr('theme_dark')])
        self.theme_combo.setCurrentText(
            self.tr('theme_light') if self.current_theme == 'light' else self.tr('theme_dark')
        )
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        theme_layout.addWidget(theme_label)
        theme_layout.addWidget(self.theme_combo)
        
        # Sistem tepsisi seçeneği
        tray_layout = QHBoxLayout()
        self.tray_checkbox = QCheckBox(self.tr('show_tray'))
        self.tray_checkbox.setChecked(self.show_in_tray)
        self.tray_checkbox.stateChanged.connect(self.toggle_tray)
        tray_layout.addWidget(self.tray_checkbox)
        
        layout.addLayout(lang_layout)
        layout.addLayout(theme_layout)
        layout.addLayout(tray_layout)
        layout.addStretch()
        self.tab4.setLayout(layout)
        
    def tr(self, key):
        """Çeviri metni döndürür"""
        try:
            return TRANSLATIONS[self.current_language].get(key, key)
        except KeyError:
            print(f"Çeviri anahtarı bulunamadı: {key}")
            return key
        
    def change_language(self, language):
        """Dil değiştirme"""
        try:
            new_language = 'tr' if language == 'Türkçe' else 'en'
            if new_language != self.current_language:
                self.current_language = new_language
                self.settings.setValue('language', self.current_language)
                
                # Kullanıcıya bilgi ver ve yeniden başlat
                reply = QMessageBox.information(self,
                    self.tr('restart_required'),
                    self.tr('language_change_restart'),
                    QMessageBox.Ok)
                
                if reply == QMessageBox.Ok:
                    QApplication.quit()
                
        except Exception as e:
            QMessageBox.critical(self, self.tr('error'),
                f"Dil değiştirme hatası: {str(e)}")
        
    def toggle_tray(self, state):
        """Sistem tepsisi görünürlüğünü değiştir"""
        self.show_in_tray = bool(state)
        self.settings.setValue('show_in_tray', str(self.show_in_tray).lower())
        if hasattr(self, 'tray_icon'):
            self.tray_icon.setVisible(self.show_in_tray)
            
    def retranslate_ui(self):
        """Arayüz metinlerini güncelle"""
        # Tab başlıkları
        self.tab_widget.setTabText(0, self.tr('ip_addresses'))
        self.tab_widget.setTabText(1, self.tr('open_ports'))
        self.tab_widget.setTabText(2, self.tr('lan_devices'))
        self.tab_widget.setTabText(3, self.tr('settings'))
        self.tab_widget.setTabText(4, self.tr('about'))
        
        # Butonlar
        self.fetch_ip_button.setText(self.tr('get_ip'))
        self.port_test_button.setText(self.tr('scan_ports'))
        self.lan_scan_button.setText(self.tr('scan_lan'))
        
        # Diğer metinler
        self.tray_checkbox.setText(self.tr('show_tray'))
        
        # Sistem tepsisi menüsü
        if hasattr(self, 'tray_icon'):
            menu = self.tray_icon.contextMenu()
            menu.clear()
            show_action = menu.addAction(self.tr('show'))
            quit_action = menu.addAction(self.tr('exit'))
            show_action.triggered.connect(self.show)
            quit_action.triggered.connect(app.quit)

        # Tema combobox'ını güncelle
        if hasattr(self, 'theme_combo'):
            current_theme = self.theme_combo.currentText()
            self.theme_combo.clear()
            self.theme_combo.addItems([self.tr('theme_light'), self.tr('theme_dark')])
            # Tema seçimini koru
            self.theme_combo.setCurrentText(
                self.tr('theme_light') if self.current_theme == 'light' else self.tr('theme_dark')
            )
        
        # Hakkında metnini güncelle
        if hasattr(self, 'tab5'):
            about_text = self.tr('about_text')
            for widget in self.tab5.findChildren(QLabel):
                if widget.text() and "KimOKi" in widget.text():
                    widget.setText(about_text)

    def fetch_ip(self):
        self.output_list1.clear()
        self.thread = FetchIPThread()
        self.thread.ip_fetched.connect(self.display_ip_info)
        self.thread.progress.connect(self.update_progress)
        self.thread.start()

    def test_ports(self):
        self.output_list2.clear()
        
        # Önceki tarama varsa durduralım
        if hasattr(self, 'port_thread') and self.port_thread.isRunning():
            self.port_thread.stop()
            self.port_thread.wait()
        
        self.statusBar.showMessage("Port taraması başlatılıyor...")
        self.port_thread = ScanPortsThread()
        self.port_thread.ports_scanned.connect(self.display_ports)
        self.port_thread.progress.connect(self.update_progress)
        
        # Buton durumunu güncelle
        self.port_test_button.setEnabled(False)
        self.port_test_button.setText("Taranıyor...")
        
        def on_finished():
            self.port_test_button.setEnabled(True)
            self.port_test_button.setText("Açık Portları Listele")
        
        self.port_thread.finished.connect(on_finished)
        self.port_thread.start()

    def scan_lan_devices(self):
        self.output_list3.clear()
        self.thread = ScanLANThread()
        self.thread.lan_scanned.connect(self.display_lan_devices)
        self.thread.progress.connect(self.update_progress)
        self.thread.start()

    def display_ip_info(self, ip_info):
        """IP bilgilerini görüntüleme"""
        self.progress_bar.setValue(100)
        self.output_list1.clear()
        
        if "Hata" in ip_info:
            self.output_list1.addItem(self.tr('error') + f": {ip_info['Hata']}")
            return
        
        output_map = {
            'Yerel IP': 'output_local_ip',
            'Genel IP': 'output_public_ip',
            'Ağ Arayüzü': 'output_network_interface',
            'MAC Adresi': 'output_mac_address',
            'Alt Ağ Maskesi': 'output_subnet_mask',
            'Bilgisayar Adı': 'output_hostname',
            'Şehir': 'output_city',
            'Ülke': 'output_country',
            'ISP': 'output_isp',
            'Organizasyon': 'output_organization'
        }
        
        for key, value in ip_info.items():
            if key in output_map:
                self.output_list1.addItem(self.tr(output_map[key]).format(value))

    def display_ports(self, open_ports):
        self.progress_bar.setValue(100)
        self.output_list2.clear()
        
        if open_ports:
            self.output_list2.addItem("=== Açık Portlar ===")
            for port, service in sorted(open_ports, key=lambda x: x[0]):  # Port numarasına göre sırala
                self.output_list2.addItem(f"Port {port}: {service}")
            self.output_list2.addItem("")  # Boş satır
            self.output_list2.addItem(f"Toplam {len(open_ports)} açık port bulundu.")
            
            self.statusBar.showMessage(f"Port taraması tamamlandı. {len(open_ports)} açık port bulundu.", 3000)
        else:
            self.output_list2.addItem("Hiçbir açık port bulunamadı.")
            self.statusBar.showMessage("Port taraması tamamlandı. Açık port bulunamadı.", 3000)

    def display_lan_devices(self, devices):
        self.progress_bar.setValue(100)
        self.output_list3.clear()
        
        if devices:
            self.output_list3.addItem(self.tr('output_device_header'))
            for i, device in enumerate(devices, 1):
                device_info = self.tr('output_device_entry').format(
                    i,
                    device['IP'],
                    device['MAC'],
                    device['Vendor'],
                    device['Hostname'],
                    device['Local']
                )
                self.output_list3.addItem(device_info)
            self.output_list3.addItem("")  # Boş satır
            self.output_list3.addItem(self.tr('output_device_count').format(len(devices)))
            
            self.statusBar.showMessage(
                self.tr('lan_scan_complete') + f" ({len(devices)} " + 
                self.tr('device_found').lower() + ")", 3000
            )
        else:
            self.output_list3.addItem(self.tr('output_no_devices'))
            self.statusBar.showMessage(self.tr('lan_scan_complete') + " (0)", 3000)

    def update_progress(self, value, message):
        """Progress bar güncelleme"""
        self.progress_bar.setValue(value)
        if 'IP' in message:
            message = self.tr('progress_getting_ip').format(value)
        elif 'Port' in message:
            message = self.tr('progress_scanning_port').format(value)
        elif 'LAN' in message:
            message = self.tr('progress_scanning_lan').format(value)
        elif 'tamamlandı' in message.lower() or 'complete' in message.lower():
            message = self.tr('progress_complete')
        self.progress_bar.setFormat(message)

    def show_context_menu(self, position):
        menu = QMenu()
        copy_action = menu.addAction("Seçileni Kopyala")
        copy_all_action = menu.addAction("Tümünü Kopyala")
        save_action = menu.addAction("Kaydet")
        
        current_list = self.sender()
        action = menu.exec_(current_list.mapToGlobal(position))
        
        if action == copy_action:
            if current_list.currentItem():
                self.clipboard.setText(current_list.currentItem().text())
                self.statusBar.showMessage("Seçili öğe panoya kopyalandı!", 2000)
        elif action == copy_all_action:
            all_items = []
            for i in range(current_list.count()):
                all_items.append(current_list.item(i).text())
            self.clipboard.setText('\n'.join(all_items))
            self.statusBar.showMessage("Tüm öğeler panoya kopyalandı!", 2000)
        elif action == save_action:
            self.save_results(current_list)

    def save_results(self, list_widget):
        items = []
        for i in range(list_widget.count()):
            items.append(list_widget.item(i).text())
            
        if not items:
            QMessageBox.warning(self, "Uyarı", "Kaydedilecek sonuç bulunamadı!")
            return
            
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Sonuçları Kaydet",
            f"kimoki_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        
        if file_name:
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(items))
                self.statusBar.showMessage(f"Sonuçlar {file_name} dosyasına kaydedildi!", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Dosya kaydedilirken hata oluştu: {str(e)}")

    def setup_system_tray(self):
        """Sistem tepsisi simgesini ayarla"""
        try:
            if ICON_PATH:
                self.tray_icon = QSystemTrayIcon(QIcon(ICON_PATH), self)
                tray_menu = QMenu()
                show_action = tray_menu.addAction(self.tr('show'))
                quit_action = tray_menu.addAction(self.tr('exit'))
                
                show_action.triggered.connect(self.show)
                quit_action.triggered.connect(QApplication.quit)
                
                self.tray_icon.setContextMenu(tray_menu)
                self.tray_icon.setToolTip(self.tr('tray_tooltip'))
                self.tray_icon.show()
        except Exception as e:
            print(f"Sistem tepsisi hatası: {str(e)}")

    def set_auto_scan(self, interval):
        if interval == "Kapalı":
            self.scan_timer.stop()
        else:
            minutes = int(interval.split()[0])
            self.scan_timer.start(minutes * 60 * 1000)

    def auto_scan(self):
        current_tab = self.tab_widget.currentIndex()
        if current_tab == 0:
            self.fetch_ip()
        elif current_tab == 1:
            self.test_ports()
        elif current_tab == 2:
            self.scan_lan_devices()

    def closeEvent(self, event):
        if self.show_in_tray and self.tray_icon.isVisible():
            QMessageBox.information(self, "KimOKi",
                self.tr('tray_info'))
            self.hide()
            event.ignore()

    def setup_tab5(self):
        """Hakkında sekmesini oluşturur"""
        layout = QVBoxLayout()
        
        # Logo
        logo = QLabel()
        if LOGO_PATH:
            pixmap = QPixmap(LOGO_PATH)
            scaled_pixmap = pixmap.scaled(150, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo.setPixmap(scaled_pixmap)
            logo.setAlignment(Qt.AlignCenter)
        
        # Hakkında metni
        about_label = QLabel()
        about_text = f"""
        <h1 style="text-align:center;">{self.tr('about_title')}</h1>
        <p><b>{self.tr('about_version')}</b></p>
        <p style="text-align:justify;">{self.tr('about_description')}</p>
        <p><b>{self.tr('about_developer')}</b></p>
        <p>{self.tr('about_contact')}</p>
        <p>{self.tr('about_author')}<br>
        {self.tr('about_email')}<br>
        {self.tr('about_github')}</p>
        <p><i>{self.tr('about_support')}</i></p>
        <p>{self.tr('about_copyright')}</p>
        """
        about_label.setText(about_text)
        about_label.setAlignment(Qt.AlignCenter)
        about_label.setWordWrap(True)
        about_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        
        layout.addWidget(logo)
        layout.addWidget(about_label)
        layout.addStretch()
        self.tab5.setLayout(layout)

    def apply_theme(self, theme_name):
        """Temayı uygula"""
        self.current_theme = theme_name
        self.settings.setValue('theme', theme_name)
        app.setStyleSheet(THEMES[theme_name])

    def change_theme(self, theme_text):
        """Tema değiştirme"""
        try:
            new_theme = 'light' if theme_text == self.tr('theme_light') else 'dark'
            if new_theme != self.current_theme:
                self.current_theme = new_theme
                self.settings.setValue('theme', new_theme)
                
                # Kullanıcıya bilgi ver ve yeniden başlat
                reply = QMessageBox.information(self,
                    self.tr('restart_required'),
                    self.tr('theme_change_restart'),
                    QMessageBox.Ok)
                
                if reply == QMessageBox.Ok:
                    QApplication.quit()
                
        except Exception as e:
            QMessageBox.critical(self, self.tr('error'),
                f"Tema değiştirme hatası: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    if ICON_PATH:
        app.setWindowIcon(QIcon(ICON_PATH))
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
