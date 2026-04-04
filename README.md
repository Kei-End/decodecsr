# ECC CSR Assistant + CSR Decoder

This build keeps the ECC CSR generation assistant as the main page and simplifies the Decoder tab into a local-only CSR decoder.

## What changed

- Removed **SSL Checker**
- Removed **Edge Mode**
- Renamed **PKI Decoder** to **CSR Decoder**
- Decoder now runs **fully in the browser**
- Fixed ECC CSR key size handling so **P-384** requests display as **384 bits**
- Added a clearer CSR summary, checks table, and CSR properties panel inspired by the validation view you shared

## Main assistant

- Environment and stack guidance
- ECC P-384 CSR input form
- Linux OpenSSL script output with server-aware notes
- Windows PowerShell + certreq output with SAN-aware INF generation
- Windows IIS GUI guidance with provider and binding reminders
- Readiness summary and post-deployment checklist

## Decoder tab

- Local browser decoding only
- PEM and DER CSR upload support
- CSR summary and checks
- Subject, key size, key algorithm, signature algorithm, fingerprints, and SAN output

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
