# Laporan Analisis Lanjutan (Advanced Payload Decoding)
**Game:** Granam Multiplayer

Berdasarkan analisis *advanced* pada file *pcap*, kita dapat mendekode isi paket biner (*proprietary UDP payload*) yang dipertukarkan. Protokol game mentransmisikan data *game state* dalam bentuk *raw bytes* menggunakan tipe data C/C++ standar (seperti Float 32-bit *Little Endian* dan ASCII string).

---

## 1. Decoding Data Klien -> Server (`0xb9` header)
Dari arah klien menuju server, selain data pergerakan, klien juga mengirimkan dua jenis data ASCII yang bisa dibaca tanpa perlu dienkripsi (*plaintext*):

### A. Identifier Pemain / Sesi (*UUID*)
Saat pertama kali melakukan *handshake* atau login, klien akan mengirimkan sebuah UUID unik untuk mengidentifikasi akun/perangkat yang digunakan, contohnya:
- `01225c38-89b4-43a9-ae25-e1f1e548fa7c` (Ditemukan di Paket #9, Panjang: 175 bytes)

### B. Fitur *In-game Chat* (Pesan Teks)
Sebuah temuan kritis adalah fitur *chat* yang diketik oleh pengguna selama di pertandingan dikirim secara *plaintext* tanpa di-*hash* atau dienkripsi.
Beberapa pesan yang dikirim klien `192.168.1.8` ke server yang berhasil disadap:
- Paket #257: `"lagi makan gua"`
- Paket #1107: `"jawa tengah"`
- Paket #2263: `"apa untad "`

**Implikasi Keamanan:** Mengirim pesan teks secara telanjang (*plaintext*) via UDP berarti siapa pun di dalam jaringan lokal (misalnya di jaringan Wi-Fi publik/kafe) bisa melihat seluruh isi percakapan (*eavesdropping* / penyadapan jaringan).

---

## 2. Decoding Data Server -> Klien (`0x00` header)
Server mengirimkan status permainan (pembaruan lokasi pemain musuh/teman, skor, atau nyawa) yang diserialisasikan sebagai *Float 32-bit (Little-Endian)*.

Dengan mem-parsing blok data biner pada rentang offset tertentu (sekitar offset ke-16), kita bisa mendapatkan koordinat seperti `(X, Y, Z)` in-game dari karakter, misalnya:
- Pkt #93: `X: -2.20`, `Y: -27.52`, `Z: 4.63`
- Pkt #100: `X: -2.20`, `Y: -10.79`, `Z: 4.66`
- Pkt #145: `X: -2.20`, `Y: -22.54`, `Z: 4.66`

Sebanyak **674 paket balasan** dari server teridentifikasi membawa pembaruan posisi *float* ini.

**Implikasi Keamanan:** Pola data yang tidak tersandikan (hanya diserialisasi) memungkinkan orang untuk melakukan *Radar Hack* (membaca koordinat musuh secara otomatis dari jaringan) atau melakukan *Packet Injection* untuk teleportasi/merubah posisi jika mereka berhasil meniru header pengiriman.

---

## 3. Script Referensi (Python)
Jika Anda ingin mengekstrak data ini dari *pcap* lain secara otomatis (atau bahkan digunakan *live* via *sniffing* `scapy`), Anda bisa menggunakan *script* Python berikut. *Script* ini akan mencari koordinat dan *chat strings*:

```python
from scapy.all import rdpcap, IP, UDP, Raw
import struct

packets = rdpcap("PCAPdroid_09_Mar_03_22_03.pcap")

server_ip = '45.135.228.80'
client_ip = '192.168.1.8'

def decode_server_payload(payload):
    # Coba decode data Float (4 bytes, Little Endian)
    floats = []
    if len(payload) > 32:
        for i in range(16, len(payload) - 3, 4):
            try:
                # '<f' = little-endian, float 32 bit
                val = struct.unpack('<f', payload[i:i+4])[0]
                if 0.01 < abs(val) < 10000.0:
                   floats.append(round(val, 2))
            except Exception:
                pass
    return floats

def extract_chat_strings(payload):
    # Cari string yang bisa dibaca (printable) minimal panjang 10 karakter
    strings = []
    current_str = ""
    for b in payload:
        if 32 <= b <= 126:
            current_str += chr(b)
        else:
            if len(current_str) >= 10:
                strings.append(current_str)
            current_str = ""
    if len(current_str) >= 10: strings.append(current_str)
    return strings

for pkt in packets:
    if IP in pkt and UDP in pkt and Raw in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        payload = bytes(pkt[Raw].load)

        if src == server_ip and dst == client_ip:
            floats = decode_server_payload(payload)
            if len(floats) >= 3:
                print(f"[Server] Coordinate update: {floats[:3]}")

        elif src == client_ip and dst == server_ip:
            strings = extract_chat_strings(payload)
            if strings:
                print(f"[Client] In-game message/UUID sent: {strings}")
```
*(Catatan: Anda cukup menyesuaikan nama pcap-nya. File ini berdiri sendiri dan cukup memakai module `scapy`).*