# ECC CSR Assistant + PKI Decoder Hybrid

This project keeps the **ECC CSR Generate Assistant** as the main page and moves the wider **PKI Decoder** into the **Decoder** tab.

## What changed

- The landing workflow is now the CSR generation assistant.
- The Decoder tab contains:
  - **PKI Decoder** with **Local Mode** and **Edge Mode**
  - **SSL Checker** backed by a Cloudflare Pages Function
- The build remains a **hybrid Cloudflare Pages** project.

## Features

### Main assistant
- Environment and stack guidance
- ECC P-384 CSR input form
- Linux OpenSSL script output with server-aware deployment notes
- Windows PowerShell + certreq output with SAN-aware INF generation
- Windows IIS GUI guidance with provider and binding reminders
- Readiness summary and post-deployment checklist

### Decoder tab
- Paste or upload PEM / DER / Base64 input
- Decode certificates, CSRs, PKCS#7 bundles, CRLs, and CMS objects
- Local browser decode for privacy-sensitive data
- Edge decode through `/api/decode`
- SSL hostname checker through `/api/ssl-check`

## Run locally

```bash
npm install
npm run dev
```

## Deploy

```bash
npm install
npm run deploy
```

## Notes

- `nodejs_compat` is enabled for the SSL checker Worker path.
- The assistant is focused on ECC P-384 CSR generation.
- The broader PKI decoder is available only inside the Decoder tab.
