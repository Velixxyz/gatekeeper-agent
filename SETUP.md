# SETUP — Proof Gatekeeper Agent (Agent Games zkVerify)

Jalanin agent ini di komputer sendiri, lalu daftarkan URL publiknya di dashboard Agent Games.

## Yang perlu diinstall dulu

1. **Node.js 20 atau lebih baru (versi LTS)** — https://nodejs.org
   Cek sesudah install: `node --version` (harus 20.x / 22.x / 24.x).
2. **cloudflared** (buat URL HTTPS publik gratis):
   - Windows (PowerShell): `winget install --id Cloudflare.cloudflared`
   - macOS: `brew install cloudflare/cloudflare/cloudflared`
   - Linux: unduh paket .deb/.rpm dari https://developers.cloudflare.com/cloudflare-one/connections/connect/downloads/
   Cek: `cloudflared --version`. Kalau habis install command tidak ketemu, tutup lalu buka lagi terminalnya.

## Langkah 1 — Install & tes lokal

Buka terminal di folder ini, lalu:

```
npm install
npm test
```

`npm test` harus berakhir **11/11 checks passed**. Kalau gagal, jangan lanjut — kirim pesan errornya.

## Langkah 2 — Jalankan server

```
npm start
```

Biarkan terminal ini tetap terbuka. Cek dari browser: http://localhost:3000/health — harus tampil `{"ok":true,...}`.

Server baca setting dari file `.env` (dibuat di langkah 4). Tanpa `.env`, server jalan dengan secret placeholder dan akan memperingatkan — itu normal sebelum registrasi, TAPI jangan daftarkan URL selagi secret masih placeholder.

## Langkah 3 — Buka tunnel (terminal KEDUA)

Di terminal kedua, di folder mana saja:

```
cloudflared tunnel --url http://localhost:3000
```

Tunggu sampai muncul baris berisi URL seperti:

```
https://nama-acak.trycloudflare.com
```

Itu URL publik agent kamu. **Salin URL itu.** Jangan tutup terminal ini selama ronde jalan — kalau tunnel mati/restart, URL-nya ganti dan pendaftaran harus diulang (pendaftaran terkunci selama ronde buka, jadi jangan restart tunnel di tengah ronde).

## Langkah 4 — Daftarkan agent di dashboard

1. Buka https://agentgames.zkverify.io/dashboard (login sebagai @velix-xyz).
2. **Register agent**, isi endpoint dengan URL trycloudflare.com dari langkah 3.
3. Dashboard akan menampilkan **HMAC secret 32-byte SEKALI saja**. Salin secret itu.
4. Di folder agent ini, salin `.env.example` menjadi `.env`, lalu isi:
   ```
   AGENT_GAMES_HMAC_SECRET=<secret dari dashboard, tempel di sini>
   ```
   Jangan beri tanda kutip, jangan ada spasi di ujung. **Jangan pernah kirim secret ini ke siapa pun / chat mana pun.**
5. Restart server: di terminal pertama tekan `Ctrl+C`, lalu `npm start` lagi. Log awal harus menulis `hmac: env-secret` (bukan PLACEHOLDER).
6. Kembali ke dashboard: jalankan **health check + preflight**, lalu **practice task**. Kalau practice lolos, agent siap ikut ronde.

## Selama ronde (17:30–03:30 WIB)

- Kedua terminal (server + tunnel) harus tetap terbuka dan komputer tetap nyala + tersambung internet.
- Jangan tutup laptop (sleep = agent offline = task gagal).
- Log server menampilkan tiap task yang masuk (decision + reason_code). Tidak ada secret yang tercatat di log.

## Kalau ada masalah

- **Port 3000 sudah dipakai**: ubah `PORT=3000` di `.env` ke angka lain (mis. 3001), sesuaikan juga URL di perintah cloudflared.
- **401 / signature gagal di practice**: secret di `.env` tidak cocok dengan yang di dashboard. Periksa ulang tempelannya, restart server, ulangi practice.
- **Tunnel URL berubah**: daftarkan ulang endpoint di dashboard (hanya bisa di luar ronde).
- **npm install gagal**: pastikan Node 20+, lalu hapus folder `node_modules` dan ulangi `npm install`.

File penting: `server.js` (endpoint), `decide.js` (logika 7 keputusan), `prove.js` (proof Groth16), `seen.js` (anti-replay), `circuits/` (artifact circuit). Detail teknis: `README.md`, `CIRCUIT.md`.
