import * as asn1js from 'asn1js';
import { setEngine, CryptoEngine, Certificate, CertificationRequest, CertificateRevocationList, ContentInfo, SignedData, getAlgorithmByOID } from 'pkijs';

const webcrypto = crypto;
setEngine('cf-worker', webcrypto, new CryptoEngine({ name: 'cf-worker', crypto: webcrypto, subtle: webcrypto.subtle }));

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'POST,OPTIONS',
      'access-control-allow-headers': 'content-type'
    }
  });
}

function base64ToArrayBuffer(base64) {
  const cleaned = base64.replace(/\s+/g, '');
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function pemBlocks(text) {
  const re = /-----BEGIN ([A-Z0-9 #\-]+)-----([\s\S]*?)-----END \1-----/g;
  const blocks = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    blocks.push({ label: m[1].trim(), der: base64ToArrayBuffer(m[2].replace(/\s+/g, '')) });
  }
  return blocks;
}

function hex(buffer) { return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase(); }
async function digestHex(buffer, alg) { return hex(await crypto.subtle.digest(alg, buffer.slice(0))); }
function parseAsn1(der) { const ber = asn1js.fromBER(der); if (ber.offset === -1) throw new Error('ASN.1 parse failed.'); return ber.result; }
function oidName(oid) { try { return getAlgorithmByOID(oid)?.name || oid; } catch { return oid; } }
function nameToRows(name) { const map = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.6': 'C', '1.2.840.113549.1.9.1': 'emailAddress' }; return (name.typesAndValues || []).map(tv => ({ field: map[tv.type] || tv.type, oid: tv.type, value: tv.value.valueBlock.value || tv.value.valueBlock.valueDec || String(tv.value.valueBlock.valueHex || '') })); }
function formatName(name) { return nameToRows(name).map(x => `${x.field}=${x.value}`).join(', '); }
function extName(oid) { const map = { '2.5.29.17': 'Subject Alternative Name', '2.5.29.15': 'Key Usage', '2.5.29.37': 'Extended Key Usage', '2.5.29.19': 'Basic Constraints', '2.5.29.35': 'Authority Key Identifier', '2.5.29.14': 'Subject Key Identifier', '2.5.29.31': 'CRL Distribution Points', '1.3.6.1.5.5.7.1.1': 'Authority Information Access', '2.5.29.32': 'Certificate Policies' }; return map[oid] || oid; }
function simpleExtensionValue(ext) { try { if (ext.parsedValue) { if (Array.isArray(ext.parsedValue.altNames)) return ext.parsedValue.altNames.map(x => ({ type: x.type, value: x.value })); return JSON.parse(JSON.stringify(ext.parsedValue)); } } catch {} return { raw_hex: hex(ext.extnValue.valueBlock.valueHex) }; }
function validityChecks(notBefore, notAfter) { const now = new Date(); if (now < notBefore) return { expired: false, notYetValid: true }; if (now > notAfter) return { expired: true, notYetValid: false }; return { expired: false, notYetValid: false }; }
function weakSig(sig) { const s = String(sig).toLowerCase(); return s.includes('sha-1') || s.includes('sha1') || s.includes('md5'); }
function extractPublicKeyInfo(spki) { const algorithm = spki.algorithm.algorithmId; const curve = spki.algorithm.algorithmParams?.valueBlock?.toString?.() || spki.algorithm.algorithmParams?.valueBlock?.value || null; let keySize = null; try { if (algorithm === '1.2.840.113549.1.1.1') { const rsa = asn1js.fromBER(spki.subjectPublicKey.valueBlock.valueHexView.slice().buffer); keySize = rsa.result.valueBlock.value[0].valueBlock.valueHex.byteLength * 8; } else if (algorithm === '1.2.840.10045.2.1') { keySize = spki.subjectPublicKey.valueBlock.valueHex.byteLength * 8; } else if (algorithm === '1.3.101.112') { keySize = 256; } else if (algorithm === '1.3.101.113') { keySize = 456; } } catch {} return { algorithm_oid: algorithm, algorithm: oidName(algorithm), key_size: keySize, curve }; }
function weakKeyHeuristic(spki) { try { if (spki.algorithm.algorithmId !== '1.2.840.113549.1.1.1') return { status: 'warning', detail: 'Weak-key screening in this build is RSA-focused only.' }; const rsa = asn1js.fromBER(spki.subjectPublicKey.valueBlock.valueHexView.slice().buffer); const prefix = hex(rsa.result.valueBlock.value[0].valueBlock.valueHex).slice(0, 4).toLowerCase(); const bad = new Set(['0002','0003','0005','0006','0007','0008','0009','000b','000d','000f']); return bad.has(prefix) ? { status: 'warning', detail: 'RSA modulus matches a weak-key prefix heuristic. Confirm independently.' } : { status: 'pass', detail: 'No match against a simple Debian weak-key prefix heuristic.' }; } catch { return { status: 'warning', detail: 'Weak-key screening could not be completed.' }; } }

async function decodeCertificate(der) {
  const cert = new Certificate({ schema: parseAsn1(der) });
  const pub = extractPublicKeyInfo(cert.subjectPublicKeyInfo);
  const sig = oidName(cert.signatureAlgorithm.algorithmId);
  const state = validityChecks(cert.notBefore.value, cert.notAfter.value);
  const validations = [
    { label: 'Validity window', status: state.expired || state.notYetValid ? 'fail' : 'pass', detail: state.expired ? 'Certificate has expired.' : state.notYetValid ? 'Certificate is not yet valid.' : 'Certificate is currently valid.' },
    { label: pub.algorithm.toLowerCase().includes('rsa') ? 'RSA key size' : 'Key size', status: !pub.key_size ? 'warning' : (pub.algorithm.toLowerCase().includes('rsa') ? pub.key_size >= 2048 : pub.key_size >= 256) ? 'pass' : 'fail', detail: pub.key_size ? `${pub.algorithm} key size is ${pub.key_size} bits.` : 'Key size could not be derived.' },
    { label: 'Signature algorithm', status: weakSig(sig) ? 'fail' : 'pass', detail: weakSig(sig) ? `Weak signature algorithm detected: ${sig}.` : `Signature algorithm is ${sig}.` },
  ];
  const weak = weakKeyHeuristic(cert.subjectPublicKeyInfo); validations.push({ label: 'Known weak key screen', status: weak.status, detail: weak.detail });
  return { type: 'certificate', subject: nameToRows(cert.subject), issuer: nameToRows(cert.issuer), subject_display: formatName(cert.subject), issuer_display: formatName(cert.issuer), serial_number: hex(cert.serialNumber.valueBlock.valueHex), validity: { not_before: cert.notBefore.value.toISOString(), not_after: cert.notAfter.value.toISOString(), expired: state.expired, not_yet_valid: state.notYetValid }, public_key: pub, signature_algorithm: sig, fingerprints: { sha256: await digestHex(der,'SHA-256'), sha1: await digestHex(der,'SHA-1') }, extensions: (cert.extensions || []).map(ext => ({ oid: ext.extnID, name: extName(ext.extnID), critical: ext.critical, value: simpleExtensionValue(ext) })), validations };
}

async function decodeCSR(der) {
  const csr = new CertificationRequest({ schema: parseAsn1(der) });
  const pub = extractPublicKeyInfo(csr.subjectPublicKeyInfo);
  const sig = oidName(csr.signatureAlgorithm.algorithmId);
  let valid = false; try { valid = await csr.verify(); } catch {}
  const empty = nameToRows(csr.subject).filter(x => !String(x.value || '').trim()).map(x => x.field);
  const validations = [
    { label: 'CSR self-signature', status: valid ? 'pass' : 'fail', detail: valid ? 'CSR self-signature is valid.' : 'CSR self-signature is invalid.' },
    { label: pub.algorithm.toLowerCase().includes('rsa') ? 'RSA key size' : 'Key size', status: !pub.key_size ? 'warning' : (pub.algorithm.toLowerCase().includes('rsa') ? pub.key_size >= 2048 : pub.key_size >= 256) ? 'pass' : 'fail', detail: pub.key_size ? `${pub.algorithm} key size is ${pub.key_size} bits.` : 'Key size could not be derived.' },
    { label: 'Subject completeness', status: empty.length ? 'fail' : 'pass', detail: empty.length ? `Empty subject values found in: ${empty.join(', ')}.` : 'No empty subject values found.' },
  ];
  const weak = weakKeyHeuristic(csr.subjectPublicKeyInfo); validations.push({ label: 'Known weak key screen', status: weak.status, detail: weak.detail });
  let requested_extensions = [];
  for (const attr of (csr.attributes || [])) {
    if (attr.type === '1.2.840.113549.1.9.14' && attr.values?.[0]) requested_extensions = (attr.values[0].extensions || []).map(ext => ({ oid: ext.extnID, name: extName(ext.extnID), critical: ext.critical, value: simpleExtensionValue(ext) }));
  }
  return { type: 'csr', subject: nameToRows(csr.subject), subject_display: formatName(csr.subject), public_key: pub, signature_algorithm: sig, requested_extensions, signature_valid: valid, validations };
}

async function decodeCRL(der) {
  const crl = new CertificateRevocationList({ schema: parseAsn1(der) });
  return { type: 'crl', issuer: nameToRows(crl.issuer), this_update: crl.thisUpdate.value.toISOString(), next_update: crl.nextUpdate?.value?.toISOString?.() || null, signature_algorithm: oidName(crl.signature.algorithmId), revoked_certificates: (crl.revokedCertificates || []).map(entry => ({ serial_number: hex(entry.userCertificate.valueBlock.valueHex), revocation_date: entry.revocationDate.value.toISOString(), reason: entry.crlEntryExtensions?.extensions?.find(x => x.extnID === '2.5.29.21')?.parsedValue?.valueBlock?.toString?.() || null })) };
}

async function decodePKCS7orCMS(der) {
  const contentInfo = new ContentInfo({ schema: parseAsn1(der) });
  const out = { type: 'cms', content_type: contentInfo.contentType, certificates: [] };
  if (contentInfo.contentType === '1.2.840.113549.1.7.2') {
    const signed = new SignedData({ schema: contentInfo.content });
    for (const cert of (signed.certificates || [])) {
      try { out.certificates.push(await decodeCertificate(cert.toSchema().toBER(false))); } catch {}
    }
    out.type = 'pkcs7';
    const issuers = new Set(out.certificates.map(c => c.issuer_display));
    for (const cert of out.certificates) {
      if (cert.subject_display === cert.issuer_display) cert.chain_role = 'root';
      else if (!issuers.has(cert.subject_display)) cert.chain_role = 'end-entity';
      else cert.chain_role = 'intermediate';
    }
  }
  return out;
}

async function decodeOne(der) {
  const list = [decodeCertificate, decodeCSR, decodeCRL, decodePKCS7orCMS];
  const errors = [];
  for (const fn of list) {
    try { return await fn(der); } catch (e) { errors.push(`${fn.name}: ${e.message}`); }
  }
  throw new Error(`Unable to decode object. ${errors.join(' | ')}`);
}

export async function onRequestOptions() { return json({ ok: true }); }

export async function onRequestPost(context) {
  try {
    const { data } = await context.request.json();
    if (!data || !String(data).trim()) return json({ detail: 'Input is empty.' }, 400);
    const text = String(data).trim();
    const blocks = pemBlocks(text);
    const items = blocks.length ? blocks : [{ label: 'BASE64_OR_DER', der: base64ToArrayBuffer(text) }];
    const objects = [], errors = [];
    for (const item of items) {
      try { const obj = await decodeOne(item.der); obj.input_label = item.label; objects.push(obj); } catch (e) { errors.push(`${item.label}: ${e.message}`); }
    }
    if (!objects.length) return json({ detail: errors[0] || 'No supported PKI objects found.' }, 400);
    return json({ objects, errors, mode: 'edge' });
  } catch (e) {
    return json({ detail: `Unable to decode — ${e.message}` }, 400);
  }
}
