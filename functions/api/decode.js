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

function pemBlocks(text) {
  const re = /-----BEGIN ([A-Z0-9 #\-]+)-----([\s\S]*?)-----END \1-----/g;
  const blocks = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    blocks.push({ label: m[1].trim(), pem: m[0].trim() });
  }
  return blocks;
}

function parseDnString(text = '') {
  return String(text)
    .split(/,(?=(?:[^\\]|\\.)*$)/)
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => {
      const idx = part.indexOf('=');
      return idx === -1
        ? { field: part, value: '' }
        : { field: part.slice(0, idx), value: part.slice(idx + 1) };
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
      detail: keySize ? `${pub.algorithm} key size is ${keySize} bits.` : 'Key size could not be derived from the edge parser.'
    },
    {
      label: 'Signature algorithm',
      status: weakSig(sig) ? 'fail' : 'pass',
      detail: sig ? (weakSig(sig) ? `Weak signature algorithm detected: ${sig}.` : `Signature algorithm is ${sig}.`) : 'Signature algorithm detail is limited in edge mode.'
    }
  ];
}

function fromX509(pem) {
  const cert = new X509Certificate(pem);
  const key = cert.publicKey;
  const keyType = key?.asymmetricKeyType || 'unknown';
  const keyDetails = key?.asymmetricKeyDetails || {};
  const keySize = keyDetails.modulusLength || keyDetails.namedCurve ? (keyDetails.modulusLength || (keyDetails.namedCurve?.includes('521') ? 521 : keyDetails.namedCurve?.includes('384') ? 384 : keyDetails.namedCurve?.includes('256') ? 256 : null)) : null;
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

function decodeBlock(block) {
  const label = block.label.toUpperCase();
  if (label.includes('CERTIFICATE') && !label.includes('REQUEST')) {
    return { ...fromX509(block.pem), input_label: block.label };
  }
  if (label.includes('REQUEST')) {
    return {
      type: 'csr',
      input_label: block.label,
      subject: [],
      subject_display: 'Edge mode currently gives full CSR parsing through Local Mode only.',
      public_key: { algorithm: null, key_size: null, curve: null },
      signature_algorithm: null,
      requested_extensions: [],
      signature_valid: null,
      validations: [
        {
          label: 'Edge parser coverage',
          status: 'warning',
          detail: 'CSR parsing in Edge Mode is intentionally limited in this dependency-free build. Use Local Mode for full CSR inspection.'
        }
      ]
    };
  }
  return {
    type: 'cms',
    input_label: block.label,
    content_type: block.label,
    certificates: [],
    note: 'This object type is not fully decoded in Edge Mode. Use Local Mode for deeper parsing.'
  };
}

export async function onRequestOptions() {
  return json({ ok: true });
}

export async function onRequestPost(context) {
  try {
    const { data } = await context.request.json();
    const text = String(data || '').trim();
    if (!text) return json({ detail: 'Input is empty.' }, 400);
    const blocks = pemBlocks(text);
    if (!blocks.length) {
      return json({ detail: 'Edge Mode in this build expects PEM input. Use Local Mode for DER or Base64 objects.' }, 400);
    }
    const objects = [];
    const errors = [];
    for (const block of blocks) {
      try {
        objects.push(decodeBlock(block));
      } catch (error) {
        errors.push(`${block.label}: ${error.message}`);
      }
    }
    if (!objects.length) return json({ detail: errors[0] || 'No supported PKI objects found.' }, 400);
    return json({ objects, errors, mode: 'edge' });
  } catch (error) {
    return json({ detail: `Unable to decode — ${error.message}` }, 400);
  }
}
