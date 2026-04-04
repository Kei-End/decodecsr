import { connect } from 'node:tls';
import * as asn1js from 'asn1js';
import { setEngine, CryptoEngine, Certificate, OCSPRequest, OCSPResponse, BasicOCSPResponse, getAlgorithmByOID } from 'pkijs';

const webcrypto = crypto;
setEngine('cf-worker-ssl', webcrypto, new CryptoEngine({ name: 'cf-worker-ssl', crypto: webcrypto, subtle: webcrypto.subtle }));

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

function toArrayBuffer(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function hex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function digestHex(buffer, alg) {
  return hex(await crypto.subtle.digest(alg, buffer.slice(0)));
}

function parseAsn1(der) {
  const ber = asn1js.fromBER(der);
  if (ber.offset === -1) throw new Error('ASN.1 parse failed.');
  return ber.result;
}

function oidName(oid) {
  try {
    return getAlgorithmByOID(oid)?.name || oid;
  } catch {
    return oid;
  }
}

function nameToRows(name) {
  const map = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.6': 'C', '1.2.840.113549.1.9.1': 'emailAddress' };
  return (name.typesAndValues || []).map(tv => ({ field: map[tv.type] || tv.type, oid: tv.type, value: tv.value.valueBlock.value || tv.value.valueBlock.valueDec || String(tv.value.valueBlock.valueHex || '') }));
}

function formatName(name) {
  return nameToRows(name).map(x => `${x.field}=${x.value}`).join(', ');
}

function extName(oid) {
  const map = {
    '2.5.29.17': 'Subject Alternative Name',
    '2.5.29.15': 'Key Usage',
    '2.5.29.37': 'Extended Key Usage',
    '2.5.29.19': 'Basic Constraints',
    '2.5.29.35': 'Authority Key Identifier',
    '2.5.29.14': 'Subject Key Identifier',
    '2.5.29.31': 'CRL Distribution Points',
    '1.3.6.1.5.5.7.1.1': 'Authority Information Access',
    '2.5.29.32': 'Certificate Policies',
  };
  return map[oid] || oid;
}

function simpleExtensionValue(ext) {
  try {
    if (ext.parsedValue) {
      if (Array.isArray(ext.parsedValue.altNames)) return ext.parsedValue.altNames.map(x => ({ type: x.type, value: x.value }));
      return JSON.parse(JSON.stringify(ext.parsedValue));
    }
  } catch {}
  return { raw_hex: hex(ext.extnValue.valueBlock.valueHex) };
}

function validityChecks(notBefore, notAfter) {
  const now = new Date();
  if (now < notBefore) return { expired: false, notYetValid: true };
  if (now > notAfter) return { expired: true, notYetValid: false };
  return { expired: false, notYetValid: false };
}

function weakSig(sig) {
  const s = String(sig).toLowerCase();
  return s.includes('sha-1') || s.includes('sha1') || s.includes('md5');
}

function extractPublicKeyInfo(spki) {
  const algorithm = spki.algorithm.algorithmId;
  const curve = spki.algorithm.algorithmParams?.valueBlock?.toString?.() || spki.algorithm.algorithmParams?.valueBlock?.value || null;
  let keySize = null;
  try {
    if (algorithm === '1.2.840.113549.1.1.1') {
      const rsa = asn1js.fromBER(spki.subjectPublicKey.valueBlock.valueHexView.slice().buffer);
      keySize = rsa.result.valueBlock.value[0].valueBlock.valueHex.byteLength * 8;
    } else if (algorithm === '1.2.840.10045.2.1') {
      keySize = spki.subjectPublicKey.valueBlock.valueHex.byteLength * 8;
    } else if (algorithm === '1.3.101.112') {
      keySize = 256;
    } else if (algorithm === '1.3.101.113') {
      keySize = 456;
    }
  } catch {}
  return { algorithm_oid: algorithm, algorithm: oidName(algorithm), key_size: keySize, curve };
}

function weakKeyHeuristic(spki) {
  try {
    if (spki.algorithm.algorithmId !== '1.2.840.113549.1.1.1') return { status: 'warning', detail: 'Weak-key screening in this build is RSA-focused only.' };
    const rsa = asn1js.fromBER(spki.subjectPublicKey.valueBlock.valueHexView.slice().buffer);
    const prefix = hex(rsa.result.valueBlock.value[0].valueBlock.valueHex).slice(0, 4).toLowerCase();
    const bad = new Set(['0002','0003','0005','0006','0007','0008','0009','000b','000d','000f']);
    return bad.has(prefix) ? { status: 'warning', detail: 'RSA modulus matches a weak-key prefix heuristic. Confirm independently.' } : { status: 'pass', detail: 'No match against a simple Debian weak-key prefix heuristic.' };
  } catch {
    return { status: 'warning', detail: 'Weak-key screening could not be completed.' };
  }
}

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
  const weak = weakKeyHeuristic(cert.subjectPublicKeyInfo);
  validations.push({ label: 'Known weak key screen', status: weak.status, detail: weak.detail });
  return {
    type: 'certificate',
    subject: nameToRows(cert.subject),
    issuer: nameToRows(cert.issuer),
    subject_display: formatName(cert.subject),
    issuer_display: formatName(cert.issuer),
    serial_number: hex(cert.serialNumber.valueBlock.valueHex),
    validity: {
      not_before: cert.notBefore.value.toISOString(),
      not_after: cert.notAfter.value.toISOString(),
      expired: state.expired,
      not_yet_valid: state.notYetValid,
    },
    public_key: pub,
    signature_algorithm: sig,
    fingerprints: {
      sha256: await digestHex(der, 'SHA-256'),
      sha1: await digestHex(der, 'SHA-1'),
    },
    extensions: (cert.extensions || []).map(ext => ({ oid: ext.extnID, name: extName(ext.extnID), critical: ext.critical, value: simpleExtensionValue(ext) })),
    validations,
  };
}

function classifyChain(certs) {
  const issuers = new Set(certs.map(c => c.issuer_display));
  for (const cert of certs) {
    if (cert.subject_display === cert.issuer_display) cert.chain_role = 'root';
    else if (!issuers.has(cert.subject_display)) cert.chain_role = 'end-entity';
    else cert.chain_role = 'intermediate';
  }
}


function extractAiaUrls(infoAccess) {
  const result = { ocsp: [], caIssuers: [] };
  if (!infoAccess) return result;
  if (typeof infoAccess === 'string') {
    const ocspMatches = [...infoAccess.matchAll(/OCSP\s*-\s*URI:([^\n]+)/gi)].map(m => m[1].trim());
    const caMatches = [...infoAccess.matchAll(/CA\s*Issuers\s*-\s*URI:([^\n]+)/gi)].map(m => m[1].trim());
    result.ocsp.push(...ocspMatches);
    result.caIssuers.push(...caMatches);
    return result;
  }
  for (const [key, value] of Object.entries(infoAccess)) {
    const values = Array.isArray(value) ? value : [value];
    if (/ocsp/i.test(key)) result.ocsp.push(...values.map(v => String(v).trim()));
    if (/ca issuers/i.test(key)) result.caIssuers.push(...values.map(v => String(v).trim()));
  }
  result.ocsp = [...new Set(result.ocsp.filter(Boolean))];
  result.caIssuers = [...new Set(result.caIssuers.filter(Boolean))];
  return result;
}

async function probeUrl(url, method = 'GET') {
  try {
    const res = await fetch(url, { method, redirect: 'follow' });
    try { await res.body?.cancel?.(); } catch {}
    return {
      url,
      ok: res.ok,
      status: res.status,
      content_type: res.headers.get('content-type'),
      content_length: res.headers.get('content-length'),
      note: method === 'HEAD' ? 'header probe' : 'fetch probe'
    };
  } catch (error) {
    return { url, ok: false, status: null, content_type: null, content_length: null, note: error.message };
  }
}

function firstPemDerFromText(text) {
  const match = text.match(/-----BEGIN [A-Z0-9 #\-]+-----([\s\S]*?)-----END [A-Z0-9 #\-]+-----/);
  if (!match) return null;
  return base64ToArrayBuffer(match[1].replace(/\s+/g, ''));
}

async function fetchIssuerCertificateRaw(url) {
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow' });
    const buf = await res.arrayBuffer();
    try {
      new Certificate({ schema: parseAsn1(buf) });
      return buf;
    } catch {}
    const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
    const pemDer = firstPemDerFromText(text);
    if (pemDer) {
      new Certificate({ schema: parseAsn1(pemDer) });
      return pemDer;
    }
    return null;
  } catch {
    return null;
  }
}

async function parseOcspResponseRaw({ raw, issuerRaw, url = null, httpStatus = null, source = 'ocsp' }) {
  const issuerCert = issuerRaw ? new Certificate({ schema: parseAsn1(issuerRaw) }) : null;
  const ocspResp = new OCSPResponse({ schema: parseAsn1(raw) });
  const responseStatus = ocspResp.responseStatus?.valueBlock?.valueDec ?? ocspResp.responseStatus?.valueDec ?? null;
  const result = {
    source,
    url,
    http_status: httpStatus,
    response_status: responseStatus,
    revocation_status: 'unknown',
    produced_at: null,
    this_update: null,
    next_update: null,
    revocation_time: null,
    signature_valid: null,
    note: null,
  };
  if (!ocspResp.responseBytes) {
    result.note = 'No OCSP responseBytes present.';
    return result;
  }
  const basicAsn1 = asn1js.fromBER(ocspResp.responseBytes.response.valueBlock.valueHex);
  const basic = new BasicOCSPResponse({ schema: basicAsn1.result });
  if (issuerCert) {
    try { result.signature_valid = await basic.verify({ trustedCerts: [issuerCert] }); } catch { result.signature_valid = null; }
  }
  result.produced_at = basic.tbsResponseData?.producedAt?.toISOString?.() || basic.tbsResponseData?.producedAt?.value?.toISOString?.() || null;
  const single = basic.tbsResponseData?.responses?.[0];
  if (single) {
    result.this_update = single.thisUpdate?.toISOString?.() || single.thisUpdate?.value?.toISOString?.() || null;
    result.next_update = single.nextUpdate?.toISOString?.() || single.nextUpdate?.value?.toISOString?.() || null;
    const tag = single.certStatus?.idBlock?.tagNumber;
    if (tag === 0) result.revocation_status = 'good';
    else if (tag === 1) {
      result.revocation_status = 'revoked';
      result.revocation_time = single.certStatus?.valueBlock?.value?.[0]?.toISOString?.() || null;
    } else if (tag === 2) result.revocation_status = 'unknown';
  }
  return result;
}

function parseEmbeddedSctList(buffer) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < 2) return { count: 0, entries: [] };
  let offset = 0;
  const totalLength = (bytes[offset] << 8) | bytes[offset + 1];
  offset += 2;
  const entries = [];
  while (offset + 2 <= bytes.length) {
    const sctLen = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    if (offset + sctLen > bytes.length) break;
    const sct = bytes.slice(offset, offset + sctLen);
    offset += sctLen;
    const logId = sct.length >= 33 ? Array.from(sct.slice(1, 33)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase() : null;
    entries.push({ version: sct[0] ?? null, log_id: logId, raw_length: sctLen });
  }
  return { total_length: totalLength, count: entries.length, entries };
}

function analyseCtSignals(leafRaw) {
  try {
    const cert = new Certificate({ schema: parseAsn1(leafRaw) });
    const ext = (cert.extensions || []).find(x => x.extnID === '1.3.6.1.4.1.11129.2.4.2');
    if (!ext) {
      return { status: 'warning', detail: 'No embedded SCT extension found in the leaf certificate.', embedded_sct_extension: false, sct_count: 0, entries: [] };
    }
    const parsed = parseEmbeddedSctList(ext.extnValue.valueBlock.valueHex);
    return {
      status: parsed.count > 0 ? 'pass' : 'warning',
      detail: parsed.count > 0 ? `Embedded SCT extension present with ${parsed.count} SCT entr${parsed.count === 1 ? 'y' : 'ies'}.` : 'Embedded SCT extension present but no SCT entries were parsed.',
      embedded_sct_extension: true,
      sct_count: parsed.count,
      entries: parsed.entries,
    };
  } catch (error) {
    return { status: 'warning', detail: `Could not analyse SCT data: ${error.message}`, embedded_sct_extension: false, sct_count: 0, entries: [] };
  }
}

function buildVerdicts({ tls, chain, stapledOcsp, followUp, ctSignals }) {
  const leaf = chain?.[0] || null;
  const validity = leaf?.validations?.find(v => v.label === 'Validity window');
  const cert_validity = validity ? validity.status : 'warning';
  const chain_quality = tls?.authorized ? 'pass' : 'warning';
  const chain_detail = tls?.authorized ? 'TLS handshake reports the chain as authorised.' : (tls?.authorizationError || 'TLS handshake did not report an authorised chain.');
  const revocationStatus = stapledOcsp?.revocation_status && stapledOcsp.revocation_status !== 'not_available' ? stapledOcsp.revocation_status : (followUp?.ocsp?.revocation_status || 'not_available');
  let revocation = 'warning';
  if (revocationStatus === 'good') revocation = 'pass';
  if (revocationStatus === 'revoked') revocation = 'fail';
  return {
    certificate_validity: { status: cert_validity, detail: validity?.detail || 'No validity result available.' },
    chain_quality: { status: chain_quality, detail: chain_detail },
    revocation: { status: revocation, detail: `Revocation result: ${revocationStatus}.` },
    certificate_transparency: { status: ctSignals?.status || 'warning', detail: ctSignals?.detail || 'No CT signal available.' }
  };
}

async function performOcspRequest({ responderUrl, leafRaw, issuerRaw }) {
  const leafCert = new Certificate({ schema: parseAsn1(leafRaw) });
  const issuerCert = new Certificate({ schema: parseAsn1(issuerRaw) });
  const ocspReq = new OCSPRequest();
  await ocspReq.createForCertificate(leafCert, {
    hashAlgorithm: 'SHA-256',
    issuerCertificate: issuerCert,
  });
  const ocspReqRaw = ocspReq.toSchema().toBER(false);
  const res = await fetch(responderUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/ocsp-request',
      'accept': 'application/ocsp-response, application/octet-stream'
    },
    body: ocspReqRaw,
    redirect: 'follow'
  });
  const raw = await res.arrayBuffer();
  return parseOcspResponseRaw({ raw, issuerRaw, url: responderUrl, httpStatus: res.status, source: 'ocsp' });
}

async function buildFollowUpChecks(leafMeta, issuerMeta) {
  const aia = extractAiaUrls(leafMeta?.infoAccess);
  const aiaChecks = [];
  for (const url of aia.caIssuers) {
    aiaChecks.push(await probeUrl(url, 'GET'));
  }

  let issuerRaw = issuerMeta?.raw || null;
  if (!issuerRaw) {
    for (const url of aia.caIssuers) {
      issuerRaw = await fetchIssuerCertificateRaw(url);
      if (issuerRaw) break;
    }
  }

  const ocspChecks = [];
  for (const url of aia.ocsp) {
    if (issuerRaw && leafMeta?.raw) {
      try {
        ocspChecks.push(await performOcspRequest({ responderUrl: url, leafRaw: leafMeta.raw, issuerRaw }));
        continue;
      } catch (error) {
        ocspChecks.push({ url, revocation_status: 'unknown', signature_valid: null, note: `OCSP request failed: ${error.message}` });
        continue;
      }
    }
    let probe = await probeUrl(url, 'HEAD');
    if (probe.status === 405 || probe.status === 501 || probe.status === null) probe = await probeUrl(url, 'GET');
    ocspChecks.push({ ...probe, revocation_status: 'not_performed', signature_valid: null, note: 'Issuer certificate unavailable, so only endpoint reachability was checked.' });
  }

  const finalStatus = ocspChecks.find(x => x.revocation_status === 'revoked')?.revocation_status || ocspChecks.find(x => x.revocation_status === 'good')?.revocation_status || (ocspChecks.length ? ocspChecks[0].revocation_status : 'not_available');

  return {
    aia: {
      ca_issuers_urls: aia.caIssuers,
      fetch_checks: aiaChecks,
    },
    ocsp: {
      responder_urls: aia.ocsp,
      responder_checks: ocspChecks,
      revocation_status: finalStatus,
    }
  };
}

function normaliseHost(input) {
  const value = String(input || '').trim();
  if (!value) throw new Error('Hostname is empty.');
  if (value.includes('://')) return new URL(value).hostname;
  return value.replace(/^\[|\]$/g, '').split('/')[0].split(':')[0];
}

function fetchChain(hostname, port = 443, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    let stapledOcsp = null;
    const socket = connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, requestOCSP: true }, () => {
      try {
        const peer = socket.getPeerCertificate(true);
        const chain = [];
        const seen = new Set();
        let current = peer;
        while (current && current.raw) {
          const marker = current.fingerprint256 || current.serialNumber || `${current.subject?.CN || 'unknown'}-${chain.length}`;
          if (seen.has(marker)) break;
          seen.add(marker);
          chain.push({
            subject: current.subject,
            issuer: current.issuer,
            valid_from: current.valid_from,
            valid_to: current.valid_to,
            subjectaltname: current.subjectaltname,
            infoAccess: current.infoAccess || null,
            serialNumber: current.serialNumber,
            fingerprint256: current.fingerprint256,
            raw: toArrayBuffer(current.raw),
          });
          if (!current.issuerCertificate || current.issuerCertificate === current) break;
          current = current.issuerCertificate;
        }
        const summary = {
          protocol: socket.getProtocol?.() || null,
          cipher: socket.getCipher?.() || null,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError || null,
        };
        socket.end();
        resolve({ summary, chain, stapledOcsp });
      } catch (error) {
        socket.destroy();
        reject(error);
      }
    });

    socket.on('OCSPResponse', (response) => { try { stapledOcsp = toArrayBuffer(response); } catch {} });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error('TLS connection timed out.'));
    });
    socket.on('error', reject);
  });
}

export async function onRequestOptions() {
  return json({ ok: true });
}

export async function onRequestPost(context) {
  try {
    const { hostname, port } = await context.request.json();
    const host = normaliseHost(hostname);
    const numericPort = Number(port || 443);
    const { summary, chain, stapledOcsp } = await fetchChain(host, numericPort);
    const decodedChain = [];
    for (const item of chain) {
      try {
        decodedChain.push(await decodeCertificate(item.raw));
      } catch {
        decodedChain.push({
          type: 'certificate',
          subject_display: item.subject?.CN || host,
          issuer_display: item.issuer?.CN || '',
          source: 'raw-node-tls',
          raw_summary: item,
          validations: [],
          extensions: [],
        });
      }
    }
    classifyChain(decodedChain);
    const follow_up = await buildFollowUpChecks(chain[0] || null, chain[1] || null);
    const stapled_ocsp = stapledOcsp ? await parseOcspResponseRaw({ raw: stapledOcsp, issuerRaw: chain[1]?.raw || null, source: 'stapled' }).catch(() => ({ source: 'stapled', revocation_status: 'unknown', note: 'Stapled OCSP could not be parsed.' })) : { source: 'stapled', revocation_status: 'not_available', note: 'No stapled OCSP response received.' };
    const ct_signals = chain[0]?.raw ? analyseCtSignals(chain[0].raw) : { status: 'warning', detail: 'Leaf certificate raw data unavailable.', embedded_sct_extension: false, sct_count: 0, entries: [] };
    const verdicts = buildVerdicts({ tls: summary, chain: decodedChain, stapledOcsp: stapled_ocsp, followUp: follow_up, ctSignals: ct_signals });
    return json({ hostname: host, port: numericPort, tls: summary, chain: decodedChain, follow_up, stapled_ocsp, ct_signals, verdicts });
  } catch (error) {
    return json({ detail: `SSL check failed — ${error.message}` }, 400);
  }
}
