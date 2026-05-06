'use strict';

const express = require('express');
const forge   = require('node-forge');
const axios   = require('axios');
const xml2js  = require('xml2js');
const { v4: uuidv4 } = require('uuid');
const https   = require('https');
const { execFile } = require('child_process');
const fs      = require('fs');
const path    = require('path');
const os      = require('os');

const app = express();
app.use(express.json({ limit: '4mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory session store: sessionId -> { privateKeyPem, requestId, cesUrl, username, password, allowSelfSigned, createdAt }
const sessions = new Map();

// ─── CSR Generation ───────────────────────────────────────────────────────────

function generateCSR(subject, keySize) {
  const keys = forge.pki.rsa.generateKeyPair(keySize);
  const csr  = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;

  const attrs = [];
  if (subject.cn)       attrs.push({ name: 'commonName',             value: subject.cn });
  if (subject.org)      attrs.push({ name: 'organizationName',       value: subject.org });
  if (subject.ou)       attrs.push({ name: 'organizationalUnitName', value: subject.ou });
  if (subject.country)  attrs.push({ name: 'countryName',            value: subject.country });
  if (subject.state)    attrs.push({ name: 'stateOrProvinceName',    value: subject.state });
  if (subject.locality) attrs.push({ name: 'localityName',           value: subject.locality });
  csr.setSubject(attrs);

  if (subject.sans && subject.sans.length > 0) {
    const altNames = subject.sans.map(san => {
      if (/^[\d.]+$/.test(san)) return { type: 7, ip: san };
      if (san.includes('@'))    return { type: 1, value: san };
      return { type: 2, value: san };
    });
    csr.setAttributes([{ name: 'extensionRequest', extensions: [{ name: 'subjectAltName', altNames }] }]);
  }

  csr.sign(keys.privateKey, forge.md.sha256.create());

  const csrDer    = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr));
  const csrBase64 = forge.util.encode64(csrDer.data);
  return { privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey), csrBase64 };
}

// ─── DNS Suffix ───────────────────────────────────────────────────────────────

function getDnsSuffix() {
  return new Promise(resolve => {
    // IPGlobalProperties.DomainName reads the primary DNS suffix from the registry
    // (HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain).
    // This works on workgroup computers; USERDNSDOMAIN is domain-joined only.
    const script = [
      '$ip = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()',
      '$s  = $ip.DomainName',
      'if (-not $s) { $s = (Get-DnsClientGlobalSetting).SuffixSearchList | Select-Object -First 1 }',
      'if ($s) { $s } else { "" }',
    ].join('; ');
    execFile('powershell.exe',
      ['-NonInteractive', '-Command', script],
      { timeout: 10000 },
      (err, stdout) => resolve(stdout.trim())
    );
  });
}

// ─── SOAP builders ────────────────────────────────────────────────────────────

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function soapHeader(cesUrl, username, password) {
  const messageId = `urn:uuid:${uuidv4()}`;
  const now     = new Date();
  const expires = new Date(now.getTime() + 5 * 60 * 1000);
  const created = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const exp     = expires.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const tokenId = `uuid-${uuidv4()}`;

  return `<s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
    <a:MessageID>${messageId}</a:MessageID>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
    <a:To s:mustUnderstand="1">${xmlEscape(cesUrl)}</a:To>
    <o:Security s:mustUnderstand="1"
        xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <u:Timestamp u:Id="_0">
        <u:Created>${created}</u:Created>
        <u:Expires>${exp}</u:Expires>
      </u:Timestamp>
      <o:UsernameToken u:Id="${tokenId}">
        <o:Username>${xmlEscape(username)}</o:Username>
        <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${xmlEscape(password)}</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>`;
}

function soapEnvelope(header, body) {
  return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  ${header}
  <s:Body>${body}</s:Body>
</s:Envelope>`;
}

function buildEnrollSoap(cesUrl, username, password, csrBase64, templateName) {
  const body = `
    <rst:RequestSecurityToken xmlns:rst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <rst:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</rst:TokenType>
      <rst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</rst:RequestType>
      <wsse:BinarySecurityToken
          xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
          ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
          EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${csrBase64}</wsse:BinarySecurityToken>
      <rst:AdditionalContext xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
        <ac:ClaimType Uri="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#CertificateTemplate">
          <ac:Value>${xmlEscape(templateName)}</ac:Value>
        </ac:ClaimType>
      </rst:AdditionalContext>
    </rst:RequestSecurityToken>`;
  return soapEnvelope(soapHeader(cesUrl, username, password), body);
}

function buildRetrieveSoap(cesUrl, username, password, requestId) {
  const body = `
    <rst:RequestSecurityToken xmlns:rst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <rst:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</rst:TokenType>
      <rst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</rst:RequestType>
      <rst:RequestID>${xmlEscape(String(requestId))}</rst:RequestID>
    </rst:RequestSecurityToken>`;
  return soapEnvelope(soapHeader(cesUrl, username, password), body);
}

// ─── SOAP Response Parser ─────────────────────────────────────────────────────

async function parseCesResponse(xmlText) {
  const parser = new xml2js.Parser({
    explicitArray: false,
    ignoreAttrs: false,
    tagNameProcessors: [xml2js.processors.stripPrefix],
  });

  let doc;
  try {
    doc = await parser.parseStringPromise(xmlText);
  } catch {
    throw new Error('Failed to parse CES SOAP response');
  }

  const body = doc?.Envelope?.Body;
  if (!body) throw new Error('Malformed SOAP envelope');

  // SOAP Fault
  if (body.Fault) {
    const f = body.Fault;
    const code   = f.Code?.Value   || f.faultcode   || 'Unknown';
    const reason = f.Reason?.Text?._ || f.Reason?.Text || f.faultstring || 'Unknown fault';
    throw new Error(`SOAP Fault [${code}]: ${reason}`);
  }

  const rstrCollection = body.RequestSecurityTokenResponseCollection;
  const rstr = rstrCollection?.RequestSecurityTokenResponse || body.RequestSecurityTokenResponse;
  if (!rstr) throw new Error('No RequestSecurityTokenResponse in SOAP body');

  const disposition = (rstr.DispositionMessage?._ || rstr.DispositionMessage || '').trim();
  const requestId   = String(rstr.RequestID?._ || rstr.RequestID || '').trim();

  // Certificate issued — look for BinarySecurityToken inside RequestedSecurityToken
  const reqToken = rstr.RequestedSecurityToken;
  if (reqToken) {
    const bst    = reqToken.BinarySecurityToken;
    const raw    = bst?._ || (typeof bst === 'string' ? bst : null);
    if (raw) {
      return { status: 'issued', certificate: raw.replace(/\s+/g, ''), requestId, disposition };
    }
  }

  const dl = disposition.toLowerCase();
  if (dl.includes('issued'))                       return { status: 'issued',  requestId, disposition };
  if (dl.includes('pending') || dl.includes('submission')) return { status: 'pending', requestId, disposition };
  if (dl.includes('denied')  || dl.includes('rejected'))  return { status: 'denied',  requestId, disposition };

  return { status: 'unknown', requestId, disposition };
}

// ─── CEP SOAP Builder ─────────────────────────────────────────────────────────

function buildGetPoliciesSoap(cepUrl, username, password) {
  const messageId = `urn:uuid:${uuidv4()}`;
  const now     = new Date();
  const expires = new Date(now.getTime() + 5 * 60 * 1000);
  const created = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const exp     = expires.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const tokenId = `uuid-${uuidv4()}`;

  return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/IPolicy/GetPolicies</a:Action>
    <a:MessageID>${messageId}</a:MessageID>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
    <a:To s:mustUnderstand="1">${xmlEscape(cepUrl)}</a:To>
    <o:Security s:mustUnderstand="1"
        xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <u:Timestamp u:Id="_0">
        <u:Created>${created}</u:Created>
        <u:Expires>${exp}</u:Expires>
      </u:Timestamp>
      <o:UsernameToken u:Id="${tokenId}">
        <o:Username>${xmlEscape(username)}</o:Username>
        <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${xmlEscape(password)}</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
      <client>
        <lastUpdate xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
        <preferredLanguage xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
      </client>
      <requestFilter>
        <policyOIDs xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
        <clientVersion>0</clientVersion>
        <serverVersion>0</serverVersion>
      </requestFilter>
    </GetPolicies>
  </s:Body>
</s:Envelope>`;
}

// ─── CEP Response Parser ──────────────────────────────────────────────────────

async function parseCepResponse(xmlText) {
  const parser = new xml2js.Parser({
    explicitArray: true,
    ignoreAttrs: false,
    tagNameProcessors: [xml2js.processors.stripPrefix],
  });

  let doc;
  try {
    doc = await parser.parseStringPromise(xmlText);
  } catch {
    throw new Error('Failed to parse CEP SOAP response');
  }

  const body = doc?.Envelope?.[0]?.Body?.[0];
  if (!body) throw new Error('Malformed SOAP envelope');

  if (body.Fault) {
    const f = body.Fault[0];
    const reason = f.Reason?.[0]?.Text?.[0]?._ || f.Reason?.[0]?.Text?.[0] || f.faultstring?.[0] || 'Unknown fault';
    throw new Error(`SOAP Fault: ${reason}`);
  }

  const gpResp = body.GetPoliciesResponse?.[0];
  if (!gpResp) throw new Error('No GetPoliciesResponse in SOAP body');

  // Build map: oIDReferenceID -> defaultName (friendly display name)
  const oidMap = {};
  for (const oid of (gpResp.oids?.[0]?.oid ?? [])) {
    const ref  = oid.oIDReferenceID?.[0];
    const name = oid.defaultName?.[0];
    if (ref !== undefined && name) oidMap[String(ref)] = name;
  }

  // Extract templates the user has enroll permission for
  const templates = [];
  for (const policy of (gpResp.response?.[0]?.policies?.[0]?.policy ?? [])) {
    const attrs = policy.attributes?.[0];
    if (!attrs) continue;

    const commonName = attrs.commonName?.[0];
    if (!commonName) continue;

    const canEnroll = (attrs.permission?.[0]?.enroll?.[0] || '').toLowerCase() !== 'false';
    if (!canEnroll) continue;

    const oidRef      = String(policy.policyOIDReference?.[0] ?? '');
    const friendlyName = oidMap[oidRef] || commonName;

    templates.push({ commonName, friendlyName });
  }

  // Extract CES URIs (clientAuthentication 3 = Username/Password)
  // clientAuthentication: 1=Anonymous, 2=Kerberos, 3=UsernamePassword, 4=Certificate
  const cesUris = [];
  for (const ca of (gpResp.cAs?.[0]?.cA ?? [])) {
    for (const caUri of (ca.uris?.[0]?.cAUri ?? [])) {
      const authType = String(caUri.clientAuthentication?.[0] ?? '');
      const uri      = caUri.uri?.[0];
      if (uri) cesUris.push({ uri, authType });
    }
  }

  return { templates, cesUris };
}

// ─── HTTP Helper (shared by CES and CEP) ─────────────────────────────────────

async function postSoap(url, soapBody, allowSelfSigned) {
  const agent = new https.Agent({ rejectUnauthorized: !allowSelfSigned });
  const response = await axios.post(url, soapBody, {
    headers: { 'Content-Type': 'application/soap+xml; charset=utf-8' },
    httpsAgent: agent,
    timeout: 30000,
    validateStatus: null,
  });

  if (response.status === 401) throw new Error('Authentication failed (401). Check credentials.');
  if (response.status === 403) throw new Error('Access denied (403). Insufficient permissions.');
  if (response.status >= 400)  throw new Error(`Server returned HTTP ${response.status}`);

  return response.data;
}

// Keep backward-compatible alias used by enroll/status routes
const postCes = postSoap;

// ─── Certificate Installation ────────────────────────────────────────────────

function installCertificate(certBase64, privateKeyPem, storeLocation, storeName) {
  return new Promise((resolve, reject) => {
    const tmp         = os.tmpdir();
    const pfxPath     = path.join(tmp, `enroll_${Date.now()}.pfx`);
    const psPath      = path.join(tmp, `enroll_${Date.now()}.ps1`);
    const pfxPassword = uuidv4().replace(/-/g, '');

    try {
      // Decode the certificate (PKCS#7 or raw DER)
      const certBin = Buffer.from(certBase64, 'base64');
      const certBuf = forge.util.createBuffer(certBin.toString('binary'));

      let certs;
      try {
        // Try PKCS#7 (most common CES response)
        const p7 = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(certBuf));
        certs = p7.certificates;
      } catch {
        // Fall back to raw X.509 DER
        certs = [forge.pki.certificateFromAsn1(forge.asn1.fromDer(certBuf))];
      }

      if (!certs || certs.length === 0) throw new Error('No certificates found in response');

      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

      const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, certs, pfxPassword, {
        algorithm: '3des',
        friendlyName: certs[0].subject.getField('CN')?.value || 'ADCS Certificate',
      });
      fs.writeFileSync(pfxPath, Buffer.from(forge.asn1.toDer(p12Asn1).getBytes(), 'binary'));

      // PowerShell install script — written to temp file to avoid argument quoting issues
      const ps = [
        `$pw = ConvertTo-SecureString -String '${pfxPassword.replace(/'/g, "''")}' -Force -AsPlainText`,
        `$cert = Import-PfxCertificate -FilePath '${pfxPath.replace(/'/g, "''")}' -CertStoreLocation 'Cert:\\${storeLocation}\\${storeName}' -Password $pw`,
        `Write-Output $cert.Thumbprint`,
      ].join('\r\n');
      fs.writeFileSync(psPath, ps, 'utf8');

      execFile('powershell.exe',
        ['-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', psPath],
        { timeout: 30000 },
        (err, stdout, stderr) => {
          cleanup();
          if (err) return reject(new Error(stderr.trim() || err.message));
          const thumbprint = stdout.trim().split(/\r?\n/).pop();
          resolve(thumbprint);
        }
      );
    } catch (err) {
      cleanup();
      reject(err);
    }

    function cleanup() {
      for (const f of [pfxPath, psPath]) try { fs.unlinkSync(f); } catch {}
    }
  });
}

// ─── Session Cleanup ─────────────────────────────────────────────────────────

function pruneSessions() {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [id, s] of sessions.entries()) {
    if (s.createdAt < cutoff) sessions.delete(id);
  }
}

// ─── API Routes ───────────────────────────────────────────────────────────────

// Return machine DNS suffix so the frontend can pre-fill the CEP/CES URL
app.get('/api/config', async (_req, res) => {
  const dnsSuffix = await getDnsSuffix();
  res.json({ dnsSuffix });
});

// Query CEP for available templates and CES URIs
app.post('/api/templates', async (req, res) => {
  try {
    const { cepUrl, username, password, allowSelfSigned } = req.body;
    if (!cepUrl || !username || !password) {
      return res.status(400).json({ error: 'cepUrl, username, and password are required.' });
    }
    const soap = buildGetPoliciesSoap(cepUrl, username, password);
    const xml  = await postSoap(cepUrl, soap, !!allowSelfSigned);
    const { templates, cesUris } = await parseCepResponse(xml);
    return res.json({ templates, cesUris });
  } catch (err) {
    console.error('[templates]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// Submit a new certificate request
app.post('/api/enroll', async (req, res) => {
  try {
    const { cesUrl, username, password, templateName, subject, keySize, allowSelfSigned } = req.body;

    if (!cesUrl || !username || !password || !templateName || !subject?.cn) {
      return res.status(400).json({ error: 'cesUrl, username, password, templateName, and subject.cn are required.' });
    }

    const { privateKeyPem, csrBase64 } = generateCSR(subject, Number(keySize) || 2048);
    const soap = buildEnrollSoap(cesUrl, username, password, csrBase64, templateName);
    const xml  = await postCes(cesUrl, soap, !!allowSelfSigned);
    const result = await parseCesResponse(xml);

    pruneSessions();
    const sessionId = uuidv4();
    sessions.set(sessionId, { privateKeyPem, requestId: result.requestId, cesUrl, username, password, allowSelfSigned: !!allowSelfSigned, createdAt: Date.now() });

    return res.json({ sessionId, ...result });
  } catch (err) {
    console.error('[enroll]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// Poll for pending request status
app.get('/api/status/:sessionId', async (req, res) => {
  try {
    const session = sessions.get(req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found or expired.' });

    const { requestId, cesUrl, username, password, allowSelfSigned } = session;
    const soap = buildRetrieveSoap(cesUrl, username, password, requestId);
    const xml  = await postCes(cesUrl, soap, allowSelfSigned);
    const result = await parseCesResponse(xml);

    return res.json({ sessionId: req.params.sessionId, ...result });
  } catch (err) {
    console.error('[status]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// Install certificate to the local machine store
app.post('/api/install', async (req, res) => {
  try {
    const { sessionId, certificate, storeLocation = 'LocalMachine', storeName = 'My' } = req.body;

    const session = sessions.get(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found. The private key is no longer available.' });
    if (!certificate) return res.status(400).json({ error: 'No certificate provided.' });

    const validLocations = ['LocalMachine', 'CurrentUser'];
    const validStores    = ['My', 'WebHosting', 'TrustedPeople', 'Root', 'CA'];
    if (!validLocations.includes(storeLocation)) return res.status(400).json({ error: 'Invalid storeLocation.' });
    if (!validStores.includes(storeName))        return res.status(400).json({ error: 'Invalid storeName.' });

    const thumbprint = await installCertificate(certificate, session.privateKeyPem, storeLocation, storeName);
    sessions.delete(sessionId);

    return res.json({ success: true, thumbprint });
  } catch (err) {
    console.error('[install]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, '127.0.0.1', () => {
  console.log(`ADCS Certificate Enrollment  →  http://localhost:${PORT}`);
  console.log('NOTE: Installing to LocalMachine requires running as Administrator.');
});
