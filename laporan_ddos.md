# Laporan Analisis Kerentanan DDoS (Denial of Service)
**Aplikasi/Game:** Granam Multiplayer
**File Analisis:** `PCAPdroid_09_Mar_03_22_03.pcap`
**Protokol Utama:** UDP (Client Port: 49800 -> Server Port: 5056)

Berdasarkan analisis lalu lintas (*traffic baseline*) yang terekam pada file PCAP, kami menemukan beberapa arsitektur komunikasi yang secara bawaan (*by design*) rentan terhadap eksploitasi serangan **Denial of Service (DoS)** atau **Distributed Denial of Service (DDoS)**.

*(Catatan: PCAP ini berisi trafik game normal, namun parameter-parameter di bawah ini mengungkapkan celah arsitektur server jika dieksploitasi oleh penyerang).*

---

## 1. Kerentanan UDP Reflection / Amplification Attack
Serangan amplifikasi terjadi ketika seorang penyerang memalsukan IP sumber (*IP Spoofing*) menjadi IP korban, kemudian mengirimkan *request* kecil ke server game, lalu server membalas dengan paket yang ukurannya jauh lebih besar menuju IP korban.

**Temuan Analisis:**
- **Rata-rata Ukuran Paket Klien (Request):** ~78 bytes
- **Rata-rata Ukuran Paket Server (Response):** ~69 bytes
- **Paket Handshake Awal (Setup):** Klien mengirim 32 bytes, Server merespon dengan 72 bytes. (Rasio 2,25x)
- **Paket Response Maksimal:** Server sesekali mengirimkan paket *game state* hingga **309 bytes**.

**Risiko (Amplification Factor):**
Berdasarkan pcap, jika penyerang mengirim paket *dummy* sekecil `32 byte` dan berhasil memicu *response* server berukuran maksimal `309 byte`, maka server memiliki **Faktor Amplifikasi maksimal ~9,66x**.
- **Kesimpulan:** Server ini **RENTAN** dijadikan reflektor (*DDoS Reflector*) dalam skala kecil-menengah jika tidak ada mekanisme mitigasi IP Spoofing dan validasi sesi (*session token*) yang ketat sebelum server membalas paket besar.

---

## 2. Kerentanan UDP Flooding / Session Exhaustion
Serangan *flooding* terjadi ketika penyerang membanjiri port `5056` server dengan ribuan paket secara acak, menghabiskan *bandwidth* atau kapasitas CPU server untuk memproses paket.

**Temuan Baseline Trafik Normal (Gameplay):**
- **Interval Rata-rata:** Klien sah (*legitimate*) mengirimkan data setiap ~`0.16` detik.
- **Normal Rate:** ~`6.21` Packets Per Second (PPS) per pemain.
- **Interval Tercepat:** `0.01` detik (burst sesaat).

**Risiko:**
Protokol UDP bersifat *connectionless*. Jika *engine* server game memproses setiap paket yang masuk ke port `5056` (misal untuk mencocokkan UUID atau dekripsi) *sebelum* membuangnya, maka *resource* CPU akan cepat habis (*Exhaustion*) saat dihantam 10.000+ PPS.

---

## 3. Rekomendasi Mitigasi
Untuk menutup celah DDoS ini pada level infrastruktur dan aplikasi, disarankan untuk mengimplementasikan langkah-langkah berikut:

1. **Implementasi Anti-Spoofing & Handshake Validasi:**
   - Karena game berbasis UDP, gunakan protokol handshake ala DTLS (Datagram Transport Layer Security) atau mekanisme *Cookie/Token Challenge*. Server jangan pernah membalas dengan paket besar sebelum klien memvalidasi bahwa mereka benar-benar memiliki IP tersebut (misal membalas paket *ping* kecil dengan *token/cookie* sementara).
2. **Strict Rate Limiting per IP:**
   - Berdasarkan *baseline* di atas, klien normal hanya mengirim sekitar 6-10 PPS. Terapkan konfigurasi *Rate Limit* atau `iptables` di sisi server untuk langsung membuang (DROP) paket (tanpa masuk ke pemrosesan *game engine*) jika satu IP mengirimkan lebih dari **20 - 30 Packets Per Second**.
3. **Penggunaan Padding Simetris:**
   - Cegah vektor *amplification* dengan mendesain protokol sedemikian rupa agar ukuran paket *response* server **tidak pernah** melebihi ukuran paket *request* dari klien di masa *handshake* awal.
4. **Deploy UDP Proxy/Filter (DDoS Protection):**
   - Gunakan layanan perlindungan DDoS spesifik game (seperti Cloudflare Spectrum, AWS Shield, atau Arbor Networks) yang bisa menyaring paket "sampah" UDP (*garbage payload*) sebelum mencapai port 5056 server game.