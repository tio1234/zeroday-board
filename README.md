# Zero-Day Board

Website yang menampilkan kerentanan zero-day dan kerentanan yang sedang aktif dieksploitasi selama 30 hari terakhir. Datanya diperbarui otomatis tiap sekitar 10 menit, dan tidak memakai database maupun server.

## Cara kerja
1. **GitHub Actions** menjalankan `collector/collect.py` tiap 10 menit.
2. Collector mengambil:
   - **CISA KEV**: kerentanan yang terkonfirmasi dieksploitasi. Langsung berstatus `CONFIRMED`.
   - **Feed berita/vendor** (`collector/sources.json`): artikel yang menyebut zero-day atau eksploitasi aktif dianalisis lebih dulu.
3. Analisis artikel:
   - Kalau ada secret `ANTHROPIC_API_KEY`, artikel dianalisis AI (Claude). Hasilnya `confirmed`, `likely`, atau `rejected`.
   - Kalau tidak ada, dipakai aturan kata kunci: harus ada CVE ID dan frasa eksploitasi aktif.
   - CVE yang juga tercatat di KEV otomatis naik menjadi `CONFIRMED`.
   - Artikel PoC, webinar, Pwn2Own, atau yang tidak punya bukti eksploitasi dibuang.
4. Hasilnya ditulis ke `docs/data.json`. Halaman `docs/index.html` membacanya dan memuat ulang data tiap 2 menit.

## Cara pasang (sekitar 15 menit)
1. Buat repository baru di GitHub, lalu upload seluruh isi folder ini (termasuk folder `.github`).
2. **Settings → Pages**: Source = *Deploy from a branch*, Branch = `main`, folder = `/docs`. Simpan.
3. **Settings → Actions → General → Workflow permissions**: pilih *Read and write permissions*. Simpan.
4. (Opsional, disarankan) **Settings → Secrets and variables → Actions → New repository secret**:
   nama `ANTHROPIC_API_KEY`, isi API key dari console.anthropic.com.
5. Buka tab **Actions → Update zero-day data → Run workflow** untuk menjalankan pertama kali.
6. Buka `https://<username>.github.io/<nama-repo>/`.

## Pengaturan
- **Tambah atau kurangi sumber**: edit `collector/sources.json`. `primary: true` dipakai untuk sumber resmi vendor/peneliti. Artikel dari sumber ini yang lolos analisis AI dianggap `confirmed`.
- **Jendela waktu**: ubah env `WINDOW_DAYS` (default 30).
- **Batas biaya AI**: env `MAX_AI_CALLS` per run (default 30). Artikel yang sudah dianalisis disimpan di cache dan tidak dianalisis ulang.
- **Model AI**: env `CLAUDE_MODEL` (default `claude-haiku-5-5`, yang paling murah).

## Catatan penting
- **Privasi**: GitHub Pages bersifat publik. Isinya hanya data publik, jadi aman, tapi jangan tambahkan daftar aset internal ke repo ini. Kalau perlu privat, jalankan `collect.py` dengan cron di server internal lalu sajikan folder `docs/` dengan web server apa saja.
- **Jadwal GitHub** kadang telat 5–15 menit saat ramai. Kalau butuh lebih cepat, jalankan di server sendiri: `*/5 * * * * python3 collect.py`.
- **Commit otomatis**: karena waktu update selalu berubah, bot membuat commit tiap run. Itu normal.
- Verdict AI bisa keliru. Setiap entri menampilkan alasan dan link sumber supaya bisa dicek.

## Uji lokal
```bash
SOURCES_FILE=tests/sources.test.json OUTPUT_FILE=/tmp/out.json python3 collector/collect.py
cd docs && python3 -m http.server 8000   # buka http://localhost:8000
```
(`tests/sources.test.json` memakai path absolut. Sesuaikan path-nya dengan lokasi folder di komputermu.)
