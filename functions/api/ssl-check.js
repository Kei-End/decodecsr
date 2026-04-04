import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';

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

function parseDnString(text = '') {
  return String(text)
    .split(/,(?=(?:[^\\]|\\.)*$)/)
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => {
      const idx = part.indexOf('=');
      return idx === -1 ? { field: part, value: '' } : { field: part.slice(0, idx), value: part.slice(idx + 1) };
    });
}

function parseSanString(text = '') {
  return String(text)
    .split(/,\s*/)
    .map(v => v.trim())
    .filter(Boolean)
    .map(v => {
      if (v.startsWith('DNS:')) return { type: 'DNS', value: v.slice(4) };
      if (v.startsWith('IP Address:')) return { type: 'IP', value: v.slice(11) };
      if (v.startsWith('IP:')) return { type: 'IP', value: v.slice(3) };
      if (v.startsWith('email:')) return { type: 'email', value: v.slice(6) };
      return { type: 'General', value: v };
    });
}

function validityChecks(validFrom, validTo) {
  const now = Date.now();
  const notBefore = new Date(validFrom).getTime();
  const notAfter = new Date(validTo).getTime();
  return {
    expired: Number.isFinite(notAfter) ? now > notAfter : false,
    not_yet_valid: Number.isFinite(notBefore) ? now < notBefore : false,
  };
}

function weakSig(sig = '') {
  const s = String(sig).toLowerCase();
  return s.includes('sha1') || s.includes('sha-1') || s.includes('md5');
}

function certValidation(pub, sig, state) {
  const keyType = String(pub.algorithm || '').toLowerCase();
  const keySize = pub.key_size;
  return [
    {
      label: 'Validity window',
      status: state.expired || state.not_yet_valid ? 'fail' : 'pass',
      detail: state.expired ? 'Certificate has expired.' : state.not_yet_valid ? 'Certificate is not yet valid.' : 'Certificate is currently valid.'
    },
    {
      label: keyType.includes('rsa') ? 'RSA key size' : 'Key size',
      status: !keySize ? 'warning' : (keyType.includes('rsa') ? keySize >= 2048 : keySize >= 256) ? 'pass' : 'fail',
      detail: keySize ? `${pub.algorithm} key size is ${keySize} bits.` : 'Key size could not be derived from the live edge parser.'
    },
    {
      label: 'Signature algorithm',
      status: weakSig(sig) ? 'fail' : 'pass',
      detail: sig ? (weakSig(sig) ? `Weak signature algorithm detected: ${sig}.` : `Signature algorithm is ${sig}.`) : 'Signature algorithm detail is limited in the live checker.'
    }
  ];
}

function x509ToObject(rawPemOrDer) {
  const cert = new X509Certificate(rawPemOrDer);
  const key = cert.publicKey;
  const keyType = key?.asymmetricKeyType || 'unknown';
  const keyDetails = key?.asymmetricKeyDetails || {};
  const keySize = keyDetails.modulusLength || (keyDetails.namedCurve?.includes('521') ? 521 : keyDetails.namedCurve?.includes('384') ? 384 : keyDetails.namedCurve?.includes('256') ? 256 : null);
  const validity = validityChecks(cert.validFrom, cert.validTo);
  const sig = cert.signatureAlgorithm || null;
  return {
    type: 'certificate',
    subject: parseDnString(cert.subject),
    issuer: parseDnString(cert.issuer),
    subject_display: cert.subject,
    issuer_display: cert.issuer,
    serial_number: cert.serialNumber,
    validity: {
      not_before: new Date(cert.validFrom).toISOString(),
      not_after: new Date(cert.validTo).toISOString(),
      expired: validity.expired,
      not_yet_valid: validity.not_yet_valid,
    },
    public_key: {
      algorithm: keyType,
      key_size: keySize,
      curve: keyDetails.namedCurve || null,
    },
    signature_algorithm: sig,
    fingerprints: {
      sha256: cert.fingerprint256 || null,
      sha1: cert.fingerprint || null,
    },
    extensions: [
      ...(cert.subjectAltName ? [{ oid: '2.5.29.17', name: 'Subject Alternative Name', critical: false, value: parseSanString(cert.subjectAltName) }] : []),
    ],
    validations: certValidation({ algorithm: keyType, key_size: keySize }, sig, validity),
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

function buildChainFromPeer(peer) {
  const chain = [];
  let current = peer;
  const seen = new Set();
  while (current && current.raw) {
    const pem = new X509Certificate(current.raw).toString();
    const obj = x509ToObject(pem);
    const key = `${obj.serial_number}:${obj.subject_display}`;
    if (seen.has(key)) break;
    seen.add(key);
    chain.push(obj);
    if (!current.issuerCertificate || current.issuerCertificate === current) break;
    current = current.issuerCertificate;
  }
  classifyChain(chain);
  return chain;
}

function connectTls(hostname, port) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
      try {
        const peer = socket.getPeerCertificate(true);
        const session = {
          protocol: socket.getProtocol?.() || null,
          cipher: socket.getCipher?.() || null,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError || null,
        };
        socket.end();
        resolve({ peer, session });
      } catch (error) {
        socket.destroy();
        reject(error);
      }
    });
    socket.setTimeout(15000, () => {
      socket.destroy(new Error('TLS connection timed out.'));
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
    const host = String(hostname || '').trim();
    const targetPort = Number(port || 443);
    if (!host) return json({ detail: 'Hostname is empty.' }, 400);
    const { peer, session } = await connectTls(host, targetPort);
    if (!peer?.raw) return json({ detail: 'No peer certificate was returned.' }, 502);
    const chain = buildChainFromPeer(peer);
    return json({ hostname: host, port: targetPort, tls: session, chain });
  } catch (error) {
    return json({ detail: `SSL check failed — ${error.message}` }, 502);
  }
}
