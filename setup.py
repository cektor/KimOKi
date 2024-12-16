from setuptools import setup, find_packages

setup(
    name="kimoki",  # Paket adı
    version="1.0",  # Paket sürümü
    description="This application is designed to retrieve IP addresses, scan open ports, and list devices on the LAN.",  # Paket açıklaması
    author="Fatih Önder",  # Paket sahibi adı
    author_email="fatih@algyazilim.com",  # Paket sahibi e-posta adresi
    url="https://github.com/cektor/KimOKi",  # Paket deposu URL'si
    packages=find_packages(),  # Otomatik olarak tüm alt paketleri bulur
    install_requires=[
        'PyQt5>=5.15.0',  # PyQt5 bağımlılığı
        'requests>=2.0.0',  # requests bağımlılığı
        'psutil>=5.0.0',  # psutil bağımlılığı
        'netifaces>=0.10.0',  # netifaces bağımlılığı
        'scapy>=2.4.0',  # scapy bağımlılığı
    ],
    package_data={
        'kimoki': ['*.png', '*.desktop'],  # 'kimoki' paketine dahil dosyalar
    },
    data_files=[
        ('share/applications', ['kimoki.desktop']),  # Uygulama menüsüne .desktop dosyasını ekler
        ('share/icons/hicolor/48x48/apps', ['kimokilo.png']),  # Simgeyi uygun yere ekler
    ],
    entry_points={
        'gui_scripts': [
            'kimoki=kimoki:main',  # `kimoki` modülündeki `main` fonksiyonu çalıştırılır
        ]
    },
)
