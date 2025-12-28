# GLİTCH - Gelişmiş Ağ Analiz ve Güvenlik Tarama Aracı

## Tanım
GLİTCH, ağ güvenliği testleri ve ağ analizi için geliştirilmiş kapsamlı bir Python tabanlı güvenlik aracıdır. Port tarama, zafiyet tespiti, proxy tespiti ve ağ keşfi gibi birçok fonksiyonu bünyesinde barındırır.

## Özellikler

### 1. Port Tarama
- TCP Connect taraması
- SYN taraması (gizli tarama için)
- UDP taraması
- Belirlenen port aralığında tarama
- Belirli portlarda tarama (örnek: 22,80,443)

### 2. Proxy Tespiti
- Açık portlarda çalışan proxy servislerini tespit eder
- HTTP proxy tespiti
- Proxy servislerini doğrular ve raporlar

### 3. Ağ Keşfi
- Hedef IP adresinin ait olduğu ağ aralığını belirler
- Ağda aktif olan diğer IP adreslerini keşfeder
- Ağ geçidini tahmin eder
- DNS bilgilerini gösterir

### 4. Zafiyet Taraması
- Açık portlarda çalışan servisler için güvenlik açıklarını tespit eder
- SSH, FTP, Web servisleri gibi yaygın servislerdeki açıkları tarar
- Anonymous FTP erişimi gibi yaygın zafiyetleri bulur

### 5. Web Taraması
- Web sitelerinde güvenlik açıklarını tespit eder
- Eksik güvenlik başlıklarını bulur
- Hassas dizinleri ve dosyaları tarar

### 6. Paket Analizi
- PCAP dosyaları üzerinden ağ trafiğini analiz eder
- Şüpheli aktiviteleri tespit eder
- Ağ protokolleri ve IP istatistiklerini gösterir

### 7. Kablosuz Ağ Taraması
- WiFi ağlarını tarar
- SSID, BSSID, kanal ve şifreleme bilgilerini gösterir

### 8. Ağ Keşfi ve Analizi
- Hedef IP'nin ait olduğu ağ aralığını otomatik olarak belirler
- Ağda aktif olan diğer IP adreslerini keşfeder
- Ağ geçidini tahmin eder
- DNS bilgilerini gösterir

### 9. Proxy Tespiti
- Port taraması sırasında otomatik olarak proxy servislerini tespit eder
- HTTP proxy taraması yapar
- Proxy servislerini doğrular ve raporlara ekler

## Kullanım

### Temel Kullanım
```bash
python glitch.py <hedef>
```

### Port Tarama
```bash
# Belirli port aralığında tarama
python glitch.py 192.168.1.1 -p 1-1000

# Belirli portlarda tarama
python glitch.py 192.168.1.1 -p 22,80,443

# SYN taraması
python glitch.py 192.168.1.1 -p 1-1000 -t syn

# UDP taraması
python glitch.py 192.168.1.1 -p 53,137 -t udp
```

### Gelişmiş Tarama
```bash
# Tüm tarama türlerini çalıştır
python glitch.py --advanced 192.168.1.1

# Ağ taraması
python glitch.py --network-scan 192.168.1.0/24

# Web taraması
python glitch.py --web-scan example.com

# Kablosuz ağ taraması
python glitch.py --wireless-scan
```

## Örnek Kullanım ve Sonuçlar

### Örnek 1: Temel Port Taraması
```bash
python glitch.py 192.168.1.1 -p 22,80,443
```

**Çıktı:**
```
GLITCH TARAMA RAPORU
===========================================================

Hedef: 192.168.1.1
Tarama Zamani: 2025-12-28T12:54:42.326329
Hostname: ADSL
OS Tahmini: Linux/Unix

Istatistikler:
  Taranan Port: 3
  Acik Port: 1
  Sure: 7.74 seconds
  Tespit Edilen Guvenlik Aciklari: 4

AĞ ANALİZİ:
  Ağ Aralığı: 192.168.1.0/24
  Ağ Geçidi: 192.168.1.1
  Keşfedilen Hostlar: 7
    - 192.168.1.1
    - 192.168.1.110
    - 192.168.1.102
    - 192.168.1.108
    - 192.168.1.109
    - 192.168.1.103
    - 192.168.1.107

ACIK PORTLAR:
Port    Protokol        Servis          Banner              Proxy
---------------------------------------------------------
80      tcp             http            HTTP/1.1 400 Bad    HTTP Proxy: 192.168.1.1:80
Request
Cont...
```

### Örnek 2: Proxy Tespiti
Açık portlarda çalışan proxy servisleri otomatik olarak tespit edilir ve raporda "Proxy" sütununda gösterilir.

### Örnek 3: Ağ Keşfi
Hedef IP adresi verildiğinde, program o IP'nin ait olduğu ağ aralığını belirler ve ağda aktif olan diğer IP adreslerini tarar.

## Raporlama

### Metin Dosyası Raporu
Program, tarama sonuçlarını otomatik olarak metin dosyasına kaydeder. Dosya adı formatı:
```
glitch_scan_<hedef>_<tarih_saat>.txt
```

### Rapor İçeriği
- Hedef bilgileri
- Ağ analiz sonuçları
- Açık portlar ve servis bilgileri
- Banner bilgileri
- Proxy bilgileri
- Tespit edilen güvenlik açıkları
- Ağ keşfi sonuçları

## Komut Satırı Argümanları

| Argüman | Açıklama |
|---------|----------|
| `target` | Hedef IP, hostname veya ağ |
| `-p, --ports` | Taranacak port aralığı (varsayılan: 1-1000) |
| `-t, --scan-type` | Tarama tipi (tcp, syn, udp, all) |
| `--threads` | Thread sayısı (varsayılan: 200) |
| `--timeout` | Zaman aşımı (varsayılan: 1) |
| `--ping` | Ping taraması yap |
| `--sniff` | Paket dinleme modu |
| `-i, --interface` | Ağ arayüzü |
| `-c, --count` | Dinlenecek paket sayısı |
| `--vuln-scan` | Güvenlik açığı taraması yap |
| `-o, --output` | Çıktı dosyası |
| `--json` | JSON formatında çıktı |
| `--csv` | CSV formatında çıktı |
| `--advanced` | Gelişmiş tarama |
| `--network-scan` | Ağ taraması |
| `--web-scan` | Web taraması |
| `--wireless-scan` | Kablosuz tarama |
| `--packet-analysis` | Paket analizi |
| `--pcap-file` | PCAP dosyası analizi |

## Gereksinimler

- Python 3.6 veya üzeri
- Aşağıdaki Python kütüphaneleri:
  - scapy
  - paramiko
  - dnspython
  - requests
  - netifaces

## Kurulum

```bash
pip install scapy paramiko dnspython requests netifaces
```

## Lisans
Bu proje açık kaynaklıdır ve eğitim amaçlı kullanılabilir.