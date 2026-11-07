# FIN-WS-047 Lab – IP IOC Checker

## Fungsi
Menerima IPv4/IPv6 dari terminal, memvalidasi input, lalu melakukan lookup ke AbuseIPDB API v2, VirusTotal API v3, dan Hybrid Analysis API v2. Hasil ditampilkan di terminal dan disimpan sebagai JSON + CSV di folder `output/`.

Script hanya melakukan lookup reputasi. Tidak mengirim file, membuat abuse report, atau memblokir IP.

## Instalasi di Mac
Pindahkan isi folder ini ke:
`/Users/ZMY9656/Downloads/FIN-WS-047_lab/IOC`

Lalu jalankan:

```bash
cd /Users/ZMY9656/Downloads/FIN-WS-047_lab/IOC
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env
```

Isi `.env` dengan API key BARU yang valid. Jangan taruh key di source code atau upload `.env` ke Git.

## Menjalankan
```bash
python ip_ioc_checker.py
```
Contoh input:
```text
IOC IP > 198.51.100.37 203.0.113.9
```

Output otomatis tersimpan di `output/ip_enrichment_<timestamp>.json` dan `.csv`.

## Asumsi dan batasan
- Versi ini khusus pengecekan IP (IPv4/IPv6); domain/hash akan ditambahkan pada tahap berikutnya.
- Rate limit HTTP 429 ditangani dengan retry; error satu provider tidak menghentikan keseluruhan proses.
- Hybrid Analysis memerlukan hak akses endpoint search pada akun. Hasil search hit harus ditinjau, bukan langsung dianggap malicious.
- `clean_or_no_hit` bukan bukti IP aman.
- IP private (10.x.x.x) dan TEST-NET (198.51.100.x / 203.0.113.x) bukan IP publik untuk penilaian reputasi normal; provider bisa menolak atau tidak memiliki data.
- HuntingAbuse belum dimasukkan karena nama layanan/endpoint API yang tepat belum terverifikasi. Jangan kirim key ke endpoint yang belum dipastikan.


