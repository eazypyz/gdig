gdig 🕵️‍♂️
gdig adalah utilitas Command-Line Interface (CLI) berkinerja tinggi yang dirancang khusus untuk mempercepat fase reconnaissance dalam Bug Bounty. Dibangun sepenuhnya menggunakan ekosistem standar Golang (zero-dependency), tool ini secara otomatis menelusuri target, mengekstrak tautan JavaScript, dan memindai hardcoded secrets serta endpoints API secara konkuren.

🚀 Fitur Utama
Deep JS Crawling: Mengunduh dan menganalisis aset .js dari target secara asinkron.

Engine Deteksi Berbasis Layanan: Memanfaatkan ruleset regex terstruktur (terinspirasi dari Keyhacks) untuk mengidentifikasi kredensial AWS, Stripe, GitHub, Slack, hingga mendeteksi single-value format seperti HackerOne API Token.

Konkurensi (Goroutines): Memproses puluhan tautan secara paralel dengan kontrol penuh atas jumlah threads untuk mencegah rate-limiting.

Integrasi Pipeline: Mendukung Silent Mode (-s) untuk membuang log yang tidak perlu, sehingga output dapat dirangkai (piping) dengan mudah ke utilitas fuzzer atau filter teks.

Portabilitas Ekstrem: Statically linked binary. Dapat dikompilasi tanpa C Runtime (CGO) sehingga sangat ideal dieksekusi di environment berarsitektur ARM64 maupun mobile security lab.

🛠️ Instalasi & Kompilasi
Pastikan Anda telah menginstal Go. Karena gdig tidak bergantung pada modul eksternal, proses kompilasinya berjalan instan.

Kompilasi Standar (Linux/Windows/macOS x86_64):
go mod init gdig
go build -o gdig main.go

Kompilasi Khusus (Mobile/Termux/ARM64 Environment):
Untuk menghindari error resolusi socket (_Ctype_socklen_t) yang sering terjadi pada lingkungan bionic libc, gunakan kompilasi Pure-Go berikut:

CGO_ENABLED=0 go build -o gdig main.go

📖 Panduan Penggunaan
Gunakan flags bawaan untuk mengonfigurasi crawling.

# Penggunaan dasar (menggunakan default 5 threads)
./gdig -u https://target.com

# Eksekusi agresif dengan 20 threads
./gdig -u https://target.com -t 20

# Silent Mode: Sembunyikan banner & error, cocok untuk output redirection
./gdig -u https://target.com -s > results.txt

# Ekstraksi otomatis: Hanya mengambil secrets dan simpan ke file terpisah
./gdig -u https://target.com -s | grep "\[SECRET\]" > leaked_keys.txt

🔗 Integrasi dengan Keyhacks
Hasil deteksi secrets pada gdig telah diklasifikasikan berdasarkan layanan untuk mempermudah validasi.

contoh output
[ENDPOINT] https://target.com/assets/app.js -> /api/v1/users
[SECRET] [AWS Access Key] https://target.com/assets/app.js -> AKIAIOSFODNN7EXAMPLE
