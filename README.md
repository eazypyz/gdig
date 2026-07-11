# gdig 🕵️‍♂️

Utilitas Command-Line Interface (CLI) berkinerja tinggi untuk mempercepat fase reconnaissance dalam Bug Bounty. Dibangun sepenuhnya menggunakan Go dengan fokus pada kecepatan, portabilitas, dan kemudahan integrasi.

## 🚀 Fitur Utama

- **Deep JS Crawling**: Mengunduh dan menganalisis aset `.js` dari target secara asinkron
- **Engine Deteksi Berbasis Layanan**: Memanfaatkan ruleset regex terstruktur (terinspirasi dari Keyhacks) untuk mengidentifikasi kredensial AWS, Stripe, GitHub, Slack, dan layanan lainnya
- **Konkurensi (Goroutines)**: Memproses puluhan tautan secara paralel dengan kontrol penuh atas jumlah threads untuk mencegah rate-limiting
- **Integrasi Pipeline**: Mode Silent (`-s`) untuk membuang log yang tidak perlu, sehingga output dapat dirangkai (piping) ke utilitas fuzzer atau filter teks
- **Portabilitas Ekstrem**: Statically linked binary tanpa dependensi C Runtime (CGO), ideal untuk ARM64 dan mobile security lab

## 🛠️ Instalasi & Kompilasi

### Prerequisites
Pastikan Anda telah menginstal **Go**. gdig tidak bergantung pada modul eksternal, sehingga kompilasi berjalan instan.

### Kompilasi Standar (Linux/Windows/macOS x86_64)

```bash
go mod init gdig
go build -o gdig main.go
```

### Kompilasi untuk ARM64 / Termux / Mobile

Untuk menghindari error resolusi socket yang sering terjadi pada lingkungan bionic libc, gunakan Pure-Go compilation:

```bash
CGO_ENABLED=0 go build -o gdig main.go
```

## 📖 Panduan Penggunaan

### Penggunaan Dasar

```bash
# Default: 5 threads
./gdig -u https://target.com

# Mode Agresif: 20 threads
./gdig -u https://target.com -t 20

# Silent Mode: Sembunyikan banner & error (cocok untuk output redirection)
./gdig -u https://target.com -s > results.txt

# Ekstraksi Secrets Otomatis
./gdig -u https://target.com -s | grep "\[SECRET\]" > leaked_keys.txt
```

### Flags yang Tersedia

| Flag | Deskripsi |
|------|-----------|
| `-u` | Target URL (required) |
| `-t` | Jumlah threads/goroutines (default: 5) |
| `-s` | Silent mode - sembunyikan banner dan error |
| `-a` | Add User-Agent |
| `-c` | Add Cookie |

## 🔗 Output Format

Hasil deteksi secrets telah diklasifikasikan berdasarkan layanan untuk mempermudah validasi.

### Contoh Output

```
[ENDPOINT] https://target.com/assets/app.js -> /api/v1/users
[SECRET] [AWS Access Key] https://target.com/assets/app.js -> AKIAIOSFODNN7EXAMPLE
```

## 📚 Layanan yang Didukung

- AWS
- Stripe
- GitHub
- Slack
- Dan banyak layanan lainnya (lihat Keyhacks ruleset)

## 📄 Lisensi

[Tambahkan informasi lisensi jika ada]

## 🤝 Kontribusi

Contributions are welcome! Silakan buka issue atau pull request untuk perbaikan dan fitur baru.
