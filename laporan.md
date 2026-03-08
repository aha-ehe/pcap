# Analisis Trafik PCAP Game Granam Multiplayer

**File PCAP:** `PCAPdroid_09_Mar_03_22_03.pcap`
**Tanggal Analisis:** 9 Maret (Berdasarkan nama file PCAP)
**Fokus:** Pemetaan protokol aplikasi client dengan server game.

## 1. Ringkasan Keseluruhan (General Overview)

Dari analisis file pcap, berikut adalah ringkasan lalu lintas jaringan yang ditemukan:

- **Total Paket:** 2644 paket.
- **Protokol Dominan:**
  - UDP: 2553 paket.
  - TCP: 91 paket.

### Resolusi DNS yang Tercatat:
1. `rt.applovin.com` (Iklan / Monetisasi)
2. `cdp.cloud.unity3d.com` (Telemetri / Analitik dari Unity Engine)
3. `web.facebook.com` (Kemungkinan untuk login/sosial)

### Alur Data Teratas (Top Flows):

| IP Sumber | IP Tujuan | Protokol | Port Tujuan | Jumlah Paket |
| :--- | :--- | :--- | :--- | :--- |
| `192.168.1.8` (Client) | `45.135.228.80` (Server) | UDP | `5056` | 1458 |
| `45.135.228.80` (Server) | `192.168.1.8` (Client) | UDP | `49800` | 1077 |
| `10.215.173.1` | `34.107.172.168` | TCP | `443` | 21 |
| `10.215.173.1` | `34.117.147.68` | TCP | `443` | 14 |
| `10.215.173.1` | `57.144.192.141` | TCP | `443` | 12 |

---

## 2. Pemetaan Protokol Game (Aplikasi <-> Server)

Berdasarkan *Top Flows* di atas, aplikasi **Granam Multiplayer** menggunakan protokol kustom di atas **UDP** untuk komunikasi *real-time* selama bermain (gameplay). Hal ini merupakan standar umum dalam industri game karena UDP memiliki latensi yang lebih rendah dibandingkan TCP, mengorbankan keandalan (reliability) demi kecepatan.

- **IP Klien (Pemain):** `192.168.1.8`
- **Port Klien:** `49800` (Port Dinamis)
- **IP Server Game:** `45.135.228.80`
- **Port Server Game:** `5056` (Kemungkinan besar ini adalah port *listening* default dari game server, seperti Photon Engine yang menggunakan range port 5055-5058 untuk komunikasi UDP).

Total terdapat **2535 paket UDP** dengan *payload* yang dipertukarkan antara klien dan server.

---

## 3. Analisis Payload (Protokol Kustom)

Berikut adalah analisis mendalam terhadap struktur payload (isi paket) yang dipertukarkan.

Terdapat pola (pattern) khusus di awal setiap paket, di mana *byte* pertama (Header Byte) sering digunakan untuk mengidentifikasi "Tipe Pesan" (Message Type).

### A. Trafik Klien ke Server (`192.168.1.8` -> `45.135.228.80`)

Seluruh lalu lintas klien menuju server selalu diawali dengan byte identifikasi: `0xb9`.

**Contoh Payload Klien (Hex & ASCII):**

1. **Paket Setup / Keep-Alive (Ukuran: 32 bytes)**
   ```text
   b9 45 00 01 00 00 1c e5 05 b2 1c 50 01 ff 00 04  | .E.........P....
   00 00 00 14 00 00 00 00 00 00 00 03 e2 25 74 33  | .............%t3
   ```
   *Catatan:* Byte pertama `b9`. Banyak nilai `00` (null bytes), kemungkinan ini paket *ping* / sinkronisasi.

2. **Paket Identifikasi / Login Sesi (Ukuran: 175 bytes)**
   ```text
   b9 45 00 03 00 00 1f 54 05 b2 1c 50 06 00 01 04  | .E.....T...P....
   00 00 00 4c 00 00 00 07 f3 02 fd 03 f6 03 02 f4  | ...L............
   03 ad f5 13 e7 32 8b c7 04 01 00 00 07 80 00 00  | .....2..........
   bb 80 00 25 30 31 32 32 35 63 38 2d 38 39 62 34  | ...%01225c38-89b4
   2d 34 33 61 39 2d 61 65 32 35 2d 65 31 66 31 65  | -43a9-ae25-e1f1e
   35 34 38 66 61 37 63 06 00 01 04 00 00 00 4b 00  | 548fa7c.......K.
   ... (Terpotong untuk laporan ringkas, referensi penuh di payload_dump.md)
   ```
   *Catatan:* Terlihat ada string berformat UUID (`01225c38-89b4-43a9-ae25-e1f1e548fa7c`) yang ditransmisikan dalam format ASCII teks murni (plain-text). String ini kemungkinan merupakan *Player ID*, *Session ID*, atau *Device ID* klien yang digunakan server untuk membedakan pemain tersebut.

### B. Trafik Server ke Klien (`45.135.228.80` -> `192.168.1.8`)

Berbeda dengan klien, paket balasan yang dikirim server menuju klien hampir semuanya diawali dengan *byte* `0x00`.

**Contoh Payload Server (Hex & ASCII):**

1. **Paket Balasan Ringkas (Ukuran: 32 bytes)**
   ```text
   00 00 00 01 e2 25 79 06 05 b2 1c 50 01 00 00 00  | .....%y....P....
   00 00 00 14 00 00 00 00 00 00 00 09 00 00 20 32  | .............. 2
   ```

2. **Paket Data / Pembaruan State (Ukuran: 309 bytes)**
   ```text
   00 00 00 04 e2 25 79 54 05 b2 1c 50 06 00 01 00  | .....%yT...P....
   00 00 00 26 00 00 00 11 f3 04 ae 02 f5 13 e7 0f  | ...&............
   8d df e2 15 2b 45 42 d9 c8 fb 25 d3 d6 a0 ca 5a  | ....+EB...%....Z
   41 c5 55 24 db df df df 00 00 a0 41 8c b1 d1 42  | A.U$.......A...B
   96 fb c4 40 d7 a3 a3 41 5f 7f 7f bf ca a6 fb c1  | ...@...A_.......
   ...
   ```
   *Catatan:* Paket-paket berukuran lebih dari 100 byte dari arah server seringkali mengandung pembaruan *game state* (seperti posisi pemain lain (X, Y, Z), status nyawa (HP), dan lain-lain). Nilai biner ini kemungkinan dikodekan menggunakan tipe data *Float* untuk perhitungan *physics engine* di Unity.

---

## 4. Kesimpulan dan Temuan Penting

1. **Game Engine:** Resolusi DNS untuk `cdp.cloud.unity3d.com` serta rentang port (Port Server: 5056) dan format header menyiratkan kuat bahwa aplikasi ini dibuat dengan **Unity3D** dan kemungkinan besar menggunakan **Photon Realtime (PUN / Photon Quantum)** atau solusi *multiplayer networking* serupa sebagai *backend multiplayer* nya.
2. **Kerahasiaan Data (Enkripsi):**
   - Protokol **TIDAK sepenuhnya dienkripsi secara end-to-end** dalam level transport (*Plain UDP* alih-alih *DTLS*). Hal ini terbukti dengan ditemukannya Player ID (UUID) yang ditransmisikan dalam bentuk *plaintext* (teks yang bisa dibaca).
   - Akan tetapi, paket data game/posisi (payload utama) sepertinya diserialisasi menjadi format biner berpemilik (proprietary binary format) milik game engine tersebut. Ini berarti *cheater* mungkin saja bisa membaca atau memodifikasi nilai float/integer tertentu di memori paket (Packet Spoofing/Manipulation) jika ia mengetahui struktur serialisasi paketnya.
3. **Stabilitas Sesi:** Klien secara konstan mengirimkan paket yang diawali dengan header `b9` yang berukuran kecil (`32 bytes`), kemungkinan ini digunakan sebagai *Heartbeat* (jantung) agar server tidak memutus sesi pemain (timeout).

---

> **Catatan Lampiran:** Untuk keperluan rekayasa balik (reverse-engineering) yang lebih rinci atau analisis payload paket secara utuh (bytes demi bytes), saya telah mengekstrak seluruh paket UDP game ini ke dalam satu file dump terpisah bernama `payload_dump.md`. Anda bisa merujuk ke file tersebut.
