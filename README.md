# PKI Decoder — Cloudflare-ready Edition

This version is designed for **Cloudflare Pages** and **GitHub-based deployment**.

## Architecture choice

Instead of a Python or Node backend, this edition decodes input **entirely in the browser** using:

- `PKI.js`
- `asn1js`
- `WebCrypto`
- `node-forge` (loaded for future compatibility work)

That makes it suitable for static hosting while still keeping the core decoding experience intact.

## Why this design

GitHub Pages is static-only, and Cloudflare Pages is a very good fit for a browser-side decoder. It can deploy straight from GitHub, and Cloudflare Pages also supports Functions later if you want to add a server-side SSL checker or hostname fetcher.

## Features in this edition

- PEM, Base64, and DER input handling
- File upload for `.pem`, `.crt`, `.cer`, `.csr`, `.p7b`, `.p7c`, `.der`, `.crl`
- Browser-side decode for:
  - X.509 certificates
  - PKCS#10 CSRs
  - CRLs
  - PKCS#7 / CMS signed-data bundles
- Validation badges
- JSON export
- Dark mode toggle
- Cloudflare Pages config with `wrangler.toml`
- Security headers via `_headers`

## Deployment to Cloudflare Pages

### Option 1: GitHub integration

1. Push this folder to a GitHub repository.
2. In Cloudflare, create a new **Pages** project.
3. Connect the repository.
4. Use these settings:
   - **Framework preset:** None
   - **Build command:** leave blank
   - **Build output directory:** `.`
5. Deploy.

### Option 2: Wrangler

```bash
npm install -g wrangler
wrangler pages deploy .
```

## Local preview

You can open `index.html` directly in the browser, or serve it with a small local server:

```bash
python -m http.server 8080
```

Then open `http://localhost:8080`.

## Honest gaps

- CMS and PKCS#7 parsing is still best-effort, especially for unusual signed-data variants.
- The weak-key check is only a light heuristic.
- This edition does **not** yet include a live hostname SSL checker, because that is cleaner to add later with a Cloudflare Function or Worker.

## Next sensible step

If you want a full companion **SSL Checker**, the clean path is:

- keep this decoder browser-side on Pages
- add a Pages Function or Worker only for remote hostname certificate retrieval

That keeps the private decode flow local while using server-side code only where it is truly needed.
