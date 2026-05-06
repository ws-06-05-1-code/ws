# ADCS Certificate Enrollment

A native PowerShell WinForms GUI for requesting certificates from an
**Active Directory Certificate Services (ADCS)** Certificate Enrollment Service
using the Microsoft WS-Trust enrollment protocols. No `certreq`, no PFX
files, no external modules — the certificate is installed directly into the
Windows certificate store via .NET crypto APIs.

## Features

- Discovers available certificate templates from the **Certificate Enrollment
  Policy** service (CEP / `MS-XCEP`)
- Submits a CSR to the **Certificate Enrollment Service** (CES / `MS-WSTEP`)
  over SOAP with WS-Security `UsernameToken` authentication
- Generates the RSA keypair and CSR in-process — the private key never touches
  disk
- Handles `issued`, `pending`, and `denied` dispositions; auto-polls every 30 s
  while a request is awaiting CA-administrator approval
- Installs the issued certificate to **LocalMachine** or **CurrentUser**
  stores, attaching the in-memory private key with
  `RSACertificateExtensions.CopyWithPrivateKey`
- Accepts PKCS#7 chains or raw DER from the CA and selects the end-entity cert

## Requirements

- Windows 10 1803+ / Windows 11 / Windows Server 2019+
- Windows PowerShell **5.1** (PowerShell 7 also works)
- .NET Framework **4.7.2+** (standard on supported Windows versions)
- An ADCS deployment with **CEP** and **CES** roles configured for
  *Username and password* authentication
- **Administrator** rights only if installing to the **LocalMachine** store

## Usage

```powershell
.\Enroll-Certificate.ps1
```

The wizard walks through four steps:

| # | Step          | What you do |
|---|---------------|-------------|
| 1 | CES Config    | Enter username/password, click **Load Templates** to query CEP, pick a template, confirm the CES URL |
| 2 | Certificate   | Fill in the Subject DN (CN required), key size, and any SANs |
| 3 | Submit        | The script generates the keypair, builds the CSR, and submits it; if pending, polls every 30 s |
| 4 | Install       | Choose store location/name and install the issued cert |

### Endpoint defaults

On startup the form auto-fills the CEP and CES URLs from the machine's
primary DNS suffix:

```
https://<dns-suffix>/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP
https://<dns-suffix>/CertSrv/CES/service.svc/CES
```

After **Load Templates**, the CES URL is replaced with the one returned by
the policy response (preferring `clientAuthentication=3`, i.e.
Username/Password).

### Subject Alternative Names

The SAN textbox accepts one entry per line. Format is auto-detected:

- `192.168.1.10` → IP address
- `admin@corp.local` → email
- anything else → DNS name

### Key sizes

`3072` (default) or `4096`. Anything below 3072 is rejected by
`New-CertificateSigningRequest`.

## Security notes

- TLS 1.2 is enabled additively via
  `[ServicePointManager]::SecurityProtocol -bor Tls12`, so any newer
  protocols already enabled (e.g. TLS 1.3) are preserved.
- The system's default `ServerCertificateValidationCallback` is always used
  — there is no opt-in for self-signed/untrusted TLS. Bootstrap CA trust at
  the OS level before running the script.
- Subject DN attributes are escaped per **RFC 2253** (`ConvertTo-RdnSafe`)
  before being concatenated into the X.500 name, so user input cannot inject
  extra RDNs.
- Username/password is sent via `wsse:UsernameToken` with `PasswordText` —
  the security of the password depends entirely on the TLS layer, so always
  use HTTPS to a trusted endpoint.
- The RSA private key lives only in the script's memory. It is attached to
  the issued cert at install time and cleared from `$script:RsaKey` once the
  cert is in the store.

## Protocol details

- **CEP** request: `IPolicy/GetPolicies` → returns templates, OID friendly
  names, and CES URIs with their `clientAuthentication` modes.
- **CES** request: `RST/wstep` with a base64 PKCS#10 CSR carried in a
  `wsse:BinarySecurityToken`, plus a `ClaimType` element specifying the
  template Common Name.
- **CES** retrieve (polling): same `RST/wstep` action with a `RequestID`
  body and no CSR.
- Response parsing extracts the certificate from
  `wst:RequestSecurityTokenResponse/wsse:BinarySecurityToken` (base64),
  along with `DispositionMessage` and `RequestID`.

## Files

```
Enroll-Certificate.ps1   # entire application — single file
.gitignore               # logs and Windows temp artifacts
```

## Troubleshooting

- **"SOAP Fault: ..."** — surfaced from the server's `s:Fault/s:Reason/Text`.
  Most commonly a permission, template, or authentication problem.
- **"HTTP 401"** — the credentials were rejected at the IIS layer; verify the
  CEP/CES virtual directories are configured for Basic over TLS.
- **Pending forever** — the CA template requires manager approval; the auto-
  poller will pick up the issued cert once a CA admin approves it in
  `certsrv.msc`. You can leave the window open.
- **"Installing to LocalMachine requires Administrator…"** — relaunch
  PowerShell as Administrator, or switch the destination to **CurrentUser**.

## Why a single script?

The file is self-contained on purpose: easy to drop onto a jump box, no
modules to import, no signed-package distribution to worry about. The
trade-off is a ~1000-line file; sections are separated with banner comments
to keep navigation manageable.
