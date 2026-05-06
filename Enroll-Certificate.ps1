#Requires -Version 5.1
<#
.SYNOPSIS
    ADCS Certificate Enrollment — native PowerShell WinForms GUI

.DESCRIPTION
    Requests a certificate from an ADCS Certificate Enrollment Service (CES)
    using the MS-WSTEP (WS-Trust) SOAP protocol. Discovers available templates
    via the Certificate Enrollment Policy service (CEP / MS-XCEP). Installs the
    issued certificate directly into the Windows certificate store using .NET
    crypto APIs — no certreq, no PFX files, no external modules.

.NOTES
    Requires .NET Framework 4.7.2+ (standard on Windows 10 1803+ / Windows 11).
    Installing to LocalMachine store requires Administrator.
#>
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# ═══════════════════════════════════════════════════════════════════════════════
#  Theme
# ═══════════════════════════════════════════════════════════════════════════════
$script:Clr = @{
    Blue    = [System.Drawing.Color]::FromArgb(26, 115, 232)
    BlueDk  = [System.Drawing.Color]::FromArgb(21,  87, 176)
    Green   = [System.Drawing.Color]::FromArgb(52, 168,  83)
    Red     = [System.Drawing.Color]::FromArgb(217, 48,  37)
    Amber   = [System.Drawing.Color]::FromArgb(249,171,   0)
    White   = [System.Drawing.Color]::White
    BgGray  = [System.Drawing.Color]::FromArgb(245, 247, 250)
    LtGray  = [System.Drawing.Color]::FromArgb(240, 242, 245)
    Border  = [System.Drawing.Color]::FromArgb(209, 213, 219)
    Text    = [System.Drawing.Color]::FromArgb( 17,  24,  39)
    Muted   = [System.Drawing.Color]::FromArgb(107, 114, 128)
    BgBlue  = [System.Drawing.Color]::FromArgb( 26,  93, 173)
}
$script:Fnt = @{
    Body    = [System.Drawing.Font]::new('Segoe UI',  9)
    Bold    = [System.Drawing.Font]::new('Segoe UI',  9, [System.Drawing.FontStyle]::Bold)
    Title   = [System.Drawing.Font]::new('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
    H2      = [System.Drawing.Font]::new('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    Small   = [System.Drawing.Font]::new('Segoe UI',  8)
    SmBold  = [System.Drawing.Font]::new('Segoe UI',  8, [System.Drawing.FontStyle]::Bold)
    Mono    = [System.Drawing.Font]::new('Consolas',  9)
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Script-level state
# ═══════════════════════════════════════════════════════════════════════════════
$script:CurrentStep   = 1
$script:RsaKey        = $null   # [System.Security.Cryptography.RSA] — kept in memory
$script:EnrollCtx     = $null   # hashtable: RequestId, CesUrl, Username, Password, AllowSelfSigned
$script:IssuedCert64  = $null   # base64 certificate bytes from CES
$script:PollTimer     = $null   # System.Windows.Forms.Timer

# ═══════════════════════════════════════════════════════════════════════════════
#  Utility
# ═══════════════════════════════════════════════════════════════════════════════
function Get-PrimaryDnsSuffix {
    try {
        $s = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
        if (-not $s) {
            $s = (Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue).SuffixSearchList |
                 Select-Object -First 1
        }
        return [string]$s
    } catch { return '' }
}

function ConvertTo-XmlSafe ([string]$s) {
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' `
       -replace '"','&quot;' -replace "'","&apos;"
}

function New-Uuid { [System.Guid]::NewGuid().ToString() }

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return ([System.Security.Principal.WindowsPrincipal]$id).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Cryptography — CSR generation
# ═══════════════════════════════════════════════════════════════════════════════
function New-CertificateSigningRequest {
    param([hashtable]$Subject, [int]$KeyBits = 2048)

    $rsa = [System.Security.Cryptography.RSA]::Create($KeyBits)
    $script:RsaKey = $rsa

    # Build DN
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($pair in @(('CN',$Subject.CN),('OU',$Subject.OU),('O',$Subject.O),
                        ('L',$Subject.L),('ST',$Subject.ST),('C',$Subject.C))) {
        if ($pair[1]) { $parts.Add("$($pair[0])=$($pair[1])") }
    }
    $dn = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new(
              ($parts -join ', '))

    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
               $dn, $rsa,
               [System.Security.Cryptography.HashAlgorithmName]::SHA256,
               [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    if ($Subject.SANs -and $Subject.SANs.Count -gt 0) {
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        foreach ($entry in $Subject.SANs) {
            $entry = $entry.Trim()
            if (-not $entry) { continue }
            if ($entry -match '^\d{1,3}(\.\d{1,3}){3}$') {
                $san.AddIpAddress([System.Net.IPAddress]::Parse($entry))
            } elseif ($entry -match '@') {
                $san.AddEmailAddress($entry)
            } else {
                $san.AddDnsName($entry)
            }
        }
        $req.CertificateExtensions.Add($san.Build())
    }

    return [Convert]::ToBase64String($req.CreateSigningRequest())
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Cryptography — certificate store installation
# ═══════════════════════════════════════════════════════════════════════════════
function Install-IssuedCertificate {
    param(
        [string]$CertBase64,
        [System.Security.Cryptography.RSA]$PrivateKey,
        [string]$StoreLocation = 'LocalMachine',
        [string]$StoreName     = 'My'
    )

    $bytes = [Convert]::FromBase64String($CertBase64)

    # Accept PKCS#7 (P7B chain) or raw DER
    $col = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    try   { $col.Import($bytes) }
    catch { $col.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)) | Out-Null }

    # Find end-entity (non-CA) certificate
    $leaf = $null
    foreach ($cert in $col) {
        $bc = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
        if (-not $bc -or -not ([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$bc).CertificateAuthority) {
            $leaf = $cert; break
        }
    }
    if (-not $leaf) { $leaf = $col[0] }

    # Attach the in-memory private key — no PFX or temp files needed
    $certWithKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($leaf, $PrivateKey)

    $loc   = [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $loc)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try   { $store.Add($certWithKey) }
    finally { $store.Close() }

    return $certWithKey.Thumbprint
}

# ═══════════════════════════════════════════════════════════════════════════════
#  SOAP builders
# ═══════════════════════════════════════════════════════════════════════════════
function New-WsSecHeader ([string]$To, [string]$Action, [string]$Username, [string]$Password) {
    $mid = "urn:uuid:$(New-Uuid)";  $tid = "uuid-$(New-Uuid)"
    $now = [DateTime]::UtcNow
    $cr  = $now.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $ex  = $now.AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $u   = ConvertTo-XmlSafe $Username;   $p  = ConvertTo-XmlSafe $Password
    $t   = ConvertTo-XmlSafe $To;         $a  = ConvertTo-XmlSafe $Action
    return @"
  <s:Header>
    <a:Action s:mustUnderstand="1">$a</a:Action>
    <a:MessageID>$mid</a:MessageID>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
    <a:To s:mustUnderstand="1">$t</a:To>
    <o:Security s:mustUnderstand="1"
        xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <u:Timestamp u:Id="_0"><u:Created>$cr</u:Created><u:Expires>$ex</u:Expires></u:Timestamp>
      <o:UsernameToken u:Id="$tid">
        <o:Username>$u</o:Username>
        <o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">$p</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
"@
}

function New-SoapEnvelope ([string]$Header, [string]$Body) {
    return @"
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
$Header
  <s:Body>$Body</s:Body>
</s:Envelope>
"@
}

function New-GetPoliciesSoap ([string]$CepUrl, [string]$Username, [string]$Password) {
    $hdr = New-WsSecHeader $CepUrl 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment/IPolicy/GetPolicies' $Username $Password
    return New-SoapEnvelope $hdr @"

    <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
      <client>
        <lastUpdate xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
        <preferredLanguage xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
      </client>
      <requestFilter>
        <policyOIDs xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
        <clientVersion>0</clientVersion><serverVersion>0</serverVersion>
      </requestFilter>
    </GetPolicies>
"@
}

function New-EnrollSoap ([string]$CesUrl, [string]$Username, [string]$Password, [string]$Csr64, [string]$Template) {
    $hdr  = New-WsSecHeader $CesUrl 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep' $Username $Password
    $tmpl = ConvertTo-XmlSafe $Template
    return New-SoapEnvelope $hdr @"

    <rst:RequestSecurityToken xmlns:rst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <rst:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</rst:TokenType>
      <rst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</rst:RequestType>
      <wsse:BinarySecurityToken
          xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
          ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
          EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">$Csr64</wsse:BinarySecurityToken>
      <rst:AdditionalContext xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
        <ac:ClaimType Uri="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#CertificateTemplate">
          <ac:Value>$tmpl</ac:Value>
        </ac:ClaimType>
      </rst:AdditionalContext>
    </rst:RequestSecurityToken>
"@
}

function New-RetrieveSoap ([string]$CesUrl, [string]$Username, [string]$Password, [string]$RequestId) {
    $hdr = New-WsSecHeader $CesUrl 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep' $Username $Password
    $rid = ConvertTo-XmlSafe $RequestId
    return New-SoapEnvelope $hdr @"

    <rst:RequestSecurityToken xmlns:rst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <rst:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</rst:TokenType>
      <rst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</rst:RequestType>
      <rst:RequestID>$rid</rst:RequestID>
    </rst:RequestSecurityToken>
"@
}

# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP / SOAP invocation
# ═══════════════════════════════════════════════════════════════════════════════
function Invoke-SoapRequest ([string]$Url, [string]$Xml, [bool]$AllowSelfSigned) {
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11

    $prevCb = $null
    if ($AllowSelfSigned) {
        $prevCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Xml)
        $req   = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method        = 'POST'
        $req.ContentType   = 'application/soap+xml; charset=utf-8'
        $req.ContentLength = $bytes.Length
        $req.Timeout       = 30000
        $s = $req.GetRequestStream(); $s.Write($bytes,0,$bytes.Length); $s.Dispose()
        $resp = $req.GetResponse()
        try {
            $rdr = [System.IO.StreamReader]::new($resp.GetResponseStream())
            return $rdr.ReadToEnd()
        } finally { $resp.Dispose() }
    } catch [System.Net.WebException] {
        $ex = $_.Exception
        if ($ex.Response) {
            try {
                $rdr = [System.IO.StreamReader]::new($ex.Response.GetResponseStream())
                $body = $rdr.ReadToEnd()
                $errXml = [xml]$body
                $ns = Get-XmlNsManager $errXml
                $msg = $errXml.SelectSingleNode('//s:Fault/s:Reason/s:Text',$ns)?.InnerText
                if (-not $msg) { $msg = $errXml.SelectSingleNode('//*[local-name()="faultstring"]')?.InnerText }
                if ($msg) { throw "SOAP Fault: $msg" }
            } catch [System.Management.Automation.RuntimeException] { throw }
            catch { }
            throw "HTTP $([int]$ex.Response.StatusCode) — $($ex.Response.StatusDescription)"
        }
        throw $ex.Message
    } finally {
        if ($AllowSelfSigned) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb
        }
    }
}

function Get-XmlNsManager ([xml]$Doc) {
    $ns = [System.Xml.XmlNamespaceManager]::new($Doc.NameTable)
    $ns.AddNamespace('s',   'http://www.w3.org/2003/05/soap-envelope')
    $ns.AddNamespace('wst', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512')
    $ns.AddNamespace('wsse','http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd')
    $ns.AddNamespace('ep',  'http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy')
    return $ns
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Response parsers
# ═══════════════════════════════════════════════════════════════════════════════
function Read-CepResponse ([string]$Xml) {
    $doc = [xml]$Xml;  $ns = Get-XmlNsManager $doc
    $fault = $doc.SelectSingleNode('//s:Fault',$ns)
    if ($fault) { throw "SOAP Fault: $($fault.SelectSingleNode('s:Reason/s:Text',$ns)?.InnerText)" }

    # OID reference map  id -> friendly name
    $oidMap = @{}
    foreach ($o in $doc.SelectNodes('//ep:oids/ep:oid',$ns)) {
        $id = $o.SelectSingleNode('ep:oIDReferenceID',$ns)?.InnerText
        $n  = $o.SelectSingleNode('ep:defaultName',$ns)?.InnerText
        if ($id -and $n) { $oidMap[$id] = $n }
    }

    $templates = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($pol in $doc.SelectNodes('//ep:response/ep:policies/ep:policy',$ns)) {
        $attrs = $pol.SelectSingleNode('ep:attributes',$ns); if (-not $attrs) { continue }
        $cn    = $attrs.SelectSingleNode('ep:commonName',$ns)?.InnerText; if (-not $cn) { continue }
        if ($attrs.SelectSingleNode('ep:permission/ep:enroll',$ns)?.InnerText -eq 'false') { continue }
        $ref   = $pol.SelectSingleNode('ep:policyOIDReference',$ns)?.InnerText
        $friendly = if ($ref -and $oidMap.ContainsKey($ref)) { $oidMap[$ref] } else { $cn }
        $templates.Add(@{ CommonName = $cn; FriendlyName = $friendly })
    }

    # CES URIs — prefer clientAuthentication=3 (Username/Password)
    $cesUris = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($caUri in $doc.SelectNodes('//ep:cAs/ep:cA/ep:uris/ep:cAUri',$ns)) {
        $auth = $caUri.SelectSingleNode('ep:clientAuthentication',$ns)?.InnerText
        $uri  = $caUri.SelectSingleNode('ep:uri',$ns)?.InnerText
        if ($uri) { $cesUris.Add(@{ Uri=$uri; AuthType=$auth }) }
    }
    return @{ Templates=$templates; CesUris=$cesUris }
}

function Read-CesResponse ([string]$Xml) {
    $doc = [xml]$Xml;  $ns = Get-XmlNsManager $doc
    $fault = $doc.SelectSingleNode('//s:Fault',$ns)
    if ($fault) { throw "SOAP Fault: $($fault.SelectSingleNode('s:Reason/s:Text',$ns)?.InnerText)" }

    $rstr = $doc.SelectSingleNode('//wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse',$ns)
    if (-not $rstr) { $rstr = $doc.SelectSingleNode('//wst:RequestSecurityTokenResponse',$ns) }
    if (-not $rstr) { throw 'No RequestSecurityTokenResponse in CES reply' }

    $disp  = $rstr.SelectSingleNode('wst:DispositionMessage',$ns)?.InnerText?.Trim()
    $reqId = $rstr.SelectSingleNode('wst:RequestID',$ns)?.InnerText?.Trim()

    # Certificate token
    $bst = $rstr.SelectSingleNode('.//wsse:BinarySecurityToken',$ns)
    if (-not $bst) { $bst = $rstr.SelectSingleNode('.//*[local-name()="BinarySecurityToken"]') }
    if ($bst) {
        $b64 = ($bst.InnerText -replace '\s','')
        if ($b64) { return @{ Status='issued'; Certificate=$b64; RequestId=$reqId; Disposition=$disp } }
    }

    $dl = $disp?.ToLower()
    $st = if     ($dl -match 'issued')              { 'issued'  }
          elseif ($dl -match 'pending|submission')  { 'pending' }
          elseif ($dl -match 'denied|rejected')     { 'denied'  }
          else                                      { 'unknown' }
    return @{ Status=$st; RequestId=$reqId; Disposition=$disp }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  UI helpers
# ═══════════════════════════════════════════════════════════════════════════════
function New-Lbl ([string]$Text, [int]$X, [int]$Y, [int]$W=200, [int]$H=18, $Font=$script:Fnt.Bold) {
    $l = [System.Windows.Forms.Label]::new()
    $l.Text=$Text; $l.Location=[System.Drawing.Point]::new($X,$Y)
    $l.Size=[System.Drawing.Size]::new($W,$H); $l.Font=$Font
    $l.ForeColor=$script:Clr.Text; return $l
}
function New-Txt ([int]$X, [int]$Y, [int]$W=200, [bool]$Pwd=$false, [bool]$Multi=$false, [int]$H=24) {
    $t = [System.Windows.Forms.TextBox]::new()
    $t.Location=[System.Drawing.Point]::new($X,$Y); $t.Size=[System.Drawing.Size]::new($W,$H)
    $t.Font=$script:Fnt.Body
    if ($Pwd)   { $t.UseSystemPasswordChar=$true }
    if ($Multi) { $t.Multiline=$true; $t.ScrollBars='Vertical'; $t.AcceptsReturn=$true }
    return $t
}
function New-Combo ([int]$X, [int]$Y, [int]$W=200, [string[]]$Items=@()) {
    $c = [System.Windows.Forms.ComboBox]::new()
    $c.Location=[System.Drawing.Point]::new($X,$Y); $c.Size=[System.Drawing.Size]::new($W,24)
    $c.Font=$script:Fnt.Body; $c.DropDownStyle='DropDownList'
    foreach ($i in $Items) { $c.Items.Add($i) | Out-Null }
    if ($Items.Count -gt 0) { $c.SelectedIndex=0 }
    return $c
}
function New-Btn ([string]$Text, [int]$X, [int]$Y, [int]$W=130, [int]$H=30, $FgColor=$null, $BgColor=$null) {
    $b = [System.Windows.Forms.Button]::new()
    $b.Text=$Text; $b.Location=[System.Drawing.Point]::new($X,$Y)
    $b.Size=[System.Drawing.Size]::new($W,$H); $b.Font=$script:Fnt.Bold
    $b.FlatStyle='Flat'; $b.FlatAppearance.BorderSize=0; $b.Cursor='Hand'
    if ($BgColor) { $b.BackColor=$BgColor } else { $b.BackColor=$script:Clr.Blue }
    if ($FgColor) { $b.ForeColor=$FgColor } else { $b.ForeColor=$script:Clr.White }
    return $b
}
function New-GroupBox ([string]$Text, [int]$X, [int]$Y, [int]$W, [int]$H) {
    $g = [System.Windows.Forms.GroupBox]::new()
    $g.Text=$Text; $g.Location=[System.Drawing.Point]::new($X,$Y)
    $g.Size=[System.Drawing.Size]::new($W,$H); $g.Font=$script:Fnt.SmBold
    $g.ForeColor=$script:Clr.Muted; return $g
}
function New-NoticePanel ([string]$Heading, [string]$Body, $BgColor, $BorderColor) {
    $p = [System.Windows.Forms.Panel]::new()
    $p.Size=[System.Drawing.Size]::new(728,0); $p.BackColor=$BgColor
    $p.Padding=[System.Windows.Forms.Padding]::new(10,8,10,8)

    $p.Add_Paint({
        param($s,$e)
        $pen=[System.Drawing.Pen]::new($s.Tag,3)
        $e.Graphics.DrawLine($pen,0,0,0,$s.Height)
        $pen.Dispose()
    })
    $p.Tag = $BorderColor

    $lh=[System.Windows.Forms.Label]::new()
    $lh.Text=$Heading; $lh.Font=$script:Fnt.Bold; $lh.AutoSize=$true
    $lh.Location=[System.Drawing.Point]::new(14,8); $lh.ForeColor=$script:Clr.Text
    $p.Controls.Add($lh)

    $lb=[System.Windows.Forms.Label]::new()
    $lb.Text=$Body; $lb.Font=$script:Fnt.Body; $lb.MaximumSize=[System.Drawing.Size]::new(700,0)
    $lb.AutoSize=$true; $lb.Location=[System.Drawing.Point]::new(14,26)
    $lb.ForeColor=$script:Clr.Text
    $p.Controls.Add($lb)

    $p.Height = 26 + $lb.Height + 14
    return $p
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Build step panels
# ═══════════════════════════════════════════════════════════════════════════════
function Build-Step1 {
    $pnl = [System.Windows.Forms.Panel]::new()
    $pnl.Size=[System.Drawing.Size]::new(778,460); $pnl.BackColor=$script:Clr.White

    # ── Credentials ───────────────────────────────────────────────────────────
    $gbAuth = New-GroupBox 'Authentication' 10 8 756 98
    $gbAuth.Controls.Add((New-Lbl 'Username *' 10 20 340))
    $script:TxtUsername = New-Txt 10 40 340
    $gbAuth.Controls.Add($script:TxtUsername)
    $gbAuth.Controls.Add((New-Lbl 'Password *' 370 20 376))
    $script:TxtPassword = New-Txt 370 40 376 $true
    $gbAuth.Controls.Add($script:TxtPassword)
    $script:ChkSelfSigned = [System.Windows.Forms.CheckBox]::new()
    $script:ChkSelfSigned.Text='Allow untrusted / self-signed TLS on CA servers'
    $script:ChkSelfSigned.Location=[System.Drawing.Point]::new(10,72)
    $script:ChkSelfSigned.Size=[System.Drawing.Size]::new(700,20)
    $script:ChkSelfSigned.Font=$script:Fnt.Body
    $gbAuth.Controls.Add($script:ChkSelfSigned)
    $pnl.Controls.Add($gbAuth)

    # ── CEP ───────────────────────────────────────────────────────────────────
    $gbCep = New-GroupBox 'Certificate Enrollment Policy (CEP)' 10 116 756 148
    $gbCep.Controls.Add((New-Lbl 'CEP Endpoint URL' 10 20 530))
    $script:TxtCepUrl = New-Txt 10 38 570
    $gbCep.Controls.Add($script:TxtCepUrl)
    $btnLoad = New-Btn 'Load Templates' 592 36 154 26
    $gbCep.Controls.Add($btnLoad)

    $script:LblCepStatus = New-Lbl '' 10 68 730 18 $script:Fnt.Small
    $script:LblCepStatus.ForeColor=$script:Clr.Muted
    $gbCep.Controls.Add($script:LblCepStatus)

    $gbCep.Controls.Add((New-Lbl 'Certificate Template *' 10 90 340))
    $script:CmbTemplate = New-Combo 10 108 360
    $script:CmbTemplate.Items.Add('— load from CEP above or enter name below —') | Out-Null
    $script:CmbTemplate.SelectedIndex=0
    $gbCep.Controls.Add($script:CmbTemplate)

    $gbCep.Controls.Add((New-Lbl 'Template internal name *' 380 90 366))
    $script:TxtTemplateName = New-Txt 380 108 366
    $gbCep.Controls.Add($script:TxtTemplateName)
    $pnl.Controls.Add($gbCep)

    # ── CES ───────────────────────────────────────────────────────────────────
    $gbCes = New-GroupBox 'Certificate Enrollment Service (CES)' 10 274 756 70
    $gbCes.Controls.Add((New-Lbl 'CES Endpoint URL *' 10 20 736))
    $script:TxtCesUrl = New-Txt 10 38 736
    $gbCes.Controls.Add($script:TxtCesUrl)
    $pnl.Controls.Add($gbCes)

    # ── Hint ──────────────────────────────────────────────────────────────────
    $hint = New-Lbl 'The CES URL is auto-filled from CEP. Both fields accept https:// URLs with Username/Password authentication.' 10 354 756 32 $script:Fnt.Small
    $hint.ForeColor=$script:Clr.Muted
    $pnl.Controls.Add($hint)

    # ── Events ────────────────────────────────────────────────────────────────
    $script:CmbTemplate.Add_SelectedIndexChanged({
        # When a real template is selected from the dropdown, clear manual box
        $sel = $script:CmbTemplate.SelectedItem
        if ($sel -and $sel -notmatch '^—') {
            # Extract commonName stored in Tag
            if ($script:CmbTemplate.SelectedIndex -gt 0) {
                $script:TxtTemplateName.Text = ''
            }
        }
    })

    $btnLoad.Add_Click({
        Invoke-LoadTemplates
    })

    return $pnl
}

function Build-Step2 {
    $pnl = [System.Windows.Forms.Panel]::new()
    $pnl.Size=[System.Drawing.Size]::new(778,460); $pnl.BackColor=$script:Clr.White

    $gbSubj = New-GroupBox 'Subject Distinguished Name' 10 8 756 188
    $gbSubj.Controls.Add((New-Lbl 'Common Name (CN) *' 10 20 480))
    $script:TxtCN = New-Txt 10 38 480
    $gbSubj.Controls.Add($script:TxtCN)
    $gbSubj.Controls.Add((New-Lbl 'Key Size' 500 20 246))
    $script:CmbKeySize = New-Combo 500 38 246 @('2048-bit (Recommended)','4096-bit (High Security)','1024-bit (Legacy)')
    $gbSubj.Controls.Add($script:CmbKeySize)

    $gbSubj.Controls.Add((New-Lbl 'Organization (O)' 10 74 363))
    $script:TxtOrg = New-Txt 10 92 363
    $gbSubj.Controls.Add($script:TxtOrg)
    $gbSubj.Controls.Add((New-Lbl 'Organizational Unit (OU)' 385 74 371))
    $script:TxtOU = New-Txt 385 92 371
    $gbSubj.Controls.Add($script:TxtOU)

    $gbSubj.Controls.Add((New-Lbl 'City / Locality (L)' 10 128 228))
    $script:TxtL = New-Txt 10 146 228
    $gbSubj.Controls.Add($script:TxtL)
    $gbSubj.Controls.Add((New-Lbl 'State / Province (ST)' 248 128 290))
    $script:TxtST = New-Txt 248 146 290
    $gbSubj.Controls.Add($script:TxtST)
    $gbSubj.Controls.Add((New-Lbl 'Country (C)' 548 128 100))
    $script:TxtC = New-Txt 548 146 100; $script:TxtC.MaxLength=2
    $gbSubj.Controls.Add($script:TxtC)
    $pnl.Controls.Add($gbSubj)

    $gbSan = New-GroupBox 'Subject Alternative Names (SANs)' 10 206 756 138
    $hint2 = New-Lbl 'One entry per line — DNS names (server.corp.local), IP addresses (192.168.1.1), or e-mail addresses' 10 20 730 18 $script:Fnt.Small
    $hint2.ForeColor=$script:Clr.Muted; $gbSan.Controls.Add($hint2)
    $script:TxtSANs = New-Txt 10 40 730 $false $true 88
    $gbSan.Controls.Add($script:TxtSANs)
    $pnl.Controls.Add($gbSan)

    return $pnl
}

function Build-Step3 {
    $pnl = [System.Windows.Forms.Panel]::new()
    $pnl.Size=[System.Drawing.Size]::new(778,460); $pnl.BackColor=$script:Clr.White

    $script:LblStatus = [System.Windows.Forms.Label]::new()
    $script:LblStatus.Text='Generating key pair and submitting request…'
    $script:LblStatus.Font=$script:Fnt.H2
    $script:LblStatus.ForeColor=$script:Clr.Muted
    $script:LblStatus.Location=[System.Drawing.Point]::new(20,20)
    $script:LblStatus.Size=[System.Drawing.Size]::new(738,28)
    $script:LblStatus.TextAlign='MiddleCenter'
    $pnl.Controls.Add($script:LblStatus)

    # Info table panel
    $script:PnlInfo = [System.Windows.Forms.Panel]::new()
    $script:PnlInfo.Location=[System.Drawing.Point]::new(20,56)
    $script:PnlInfo.Size=[System.Drawing.Size]::new(738,84)
    $script:PnlInfo.BackColor=$script:Clr.BgGray
    $script:PnlInfo.BorderStyle='FixedSingle'
    $script:PnlInfo.Visible=$false

    $rows = @('Request ID','Status','Disposition Message')
    $script:InfoValues = @{}
    for ($i=0; $i -lt $rows.Count; $i++) {
        $lk = New-Lbl $rows[$i] 12 ($i*26+8) 180 22 $script:Fnt.Bold
        $lk.ForeColor=$script:Clr.Muted; $script:PnlInfo.Controls.Add($lk)
        $lv = New-Lbl '—' 196 ($i*26+8) 534 22 $script:Fnt.Body
        $script:PnlInfo.Controls.Add($lv)
        $script:InfoValues[$rows[$i]] = $lv
    }
    $pnl.Controls.Add($script:PnlInfo)

    # Notice panels — created dynamically in Update-Step3Status
    $script:PnlNotice = [System.Windows.Forms.Panel]::new()
    $script:PnlNotice.Location=[System.Drawing.Point]::new(20,150)
    $script:PnlNotice.Size=[System.Drawing.Size]::new(738,120)
    $script:PnlNotice.Visible=$false
    $pnl.Controls.Add($script:PnlNotice)

    $script:LblLastChecked = New-Lbl '' 20 278 738 18 $script:Fnt.Small
    $script:LblLastChecked.ForeColor=$script:Clr.Muted; $script:LblLastChecked.Visible=$false
    $pnl.Controls.Add($script:LblLastChecked)

    return $pnl
}

function Build-Step4 {
    $pnl = [System.Windows.Forms.Panel]::new()
    $pnl.Size=[System.Drawing.Size]::new(778,460); $pnl.BackColor=$script:Clr.White

    $warn = New-NoticePanel 'Administrator Privileges Required' `
        'Installing to Local Machine requires this process to run as Administrator. Current User store does not require elevation.' `
        ([System.Drawing.Color]::FromArgb(254,243,199)) `
        $script:Clr.Amber
    $warn.Location=[System.Drawing.Point]::new(20,12)
    $pnl.Controls.Add($warn)

    $gbStore = New-GroupBox 'Destination' 20 92 736 88
    $gbStore.Controls.Add((New-Lbl 'Store Location' 10 20 340))
    $script:CmbStoreLocation = New-Combo 10 38 340 @('LocalMachine','CurrentUser')
    $gbStore.Controls.Add($script:CmbStoreLocation)
    $gbStore.Controls.Add((New-Lbl 'Certificate Store' 364 20 362))
    $script:CmbStoreName = New-Combo 364 38 362 @('My','WebHosting','TrustedPeople','CA','Root')
    $gbStore.Controls.Add($script:CmbStoreName)
    $pnl.Controls.Add($gbStore)

    $script:PnlInstallResult = [System.Windows.Forms.Panel]::new()
    $script:PnlInstallResult.Location=[System.Drawing.Point]::new(20,192)
    $script:PnlInstallResult.Size=[System.Drawing.Size]::new(738,140)
    $script:PnlInstallResult.Visible=$false
    $pnl.Controls.Add($script:PnlInstallResult)

    return $pnl
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Step indicator (custom-painted panel)
# ═══════════════════════════════════════════════════════════════════════════════
$script:StepLabels = @('CES Config','Certificate','Submit','Install')

function New-StepIndicatorPanel {
    $p = [System.Windows.Forms.Panel]::new()
    $p.Size=[System.Drawing.Size]::new(778,52); $p.BackColor=$script:Clr.LtGray

    $p.Add_Paint({
        param($sender,$e)
        $g=$e.Graphics
        $g.SmoothingMode=[System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint=[System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $step=$script:CurrentStep; $labels=$script:StepLabels
        $n=4; $spacing=$sender.Width/$n; $cy=18; $r=13

        for ($i=0;$i -lt $n;$i++) {
            $cx=[int]($spacing*$i+$spacing/2)

            if ($i -gt 0) {
                $prevCx=[int]($spacing*($i-1)+$spacing/2)
                $lineClr = if ($step -gt $i) { $script:Clr.Green } else { $script:Clr.Border }
                $pen=[System.Drawing.Pen]::new($lineClr,2)
                $g.DrawLine($pen,$prevCx+$r,$cy,$cx-$r,$cy); $pen.Dispose()
            }

            $fillClr = if ($step -gt $i+1)      { $script:Clr.Green }
                       elseif ($step -eq $i+1)   { $script:Clr.Blue }
                       else                       { $script:Clr.Border }

            $br=[System.Drawing.SolidBrush]::new($fillClr)
            $g.FillEllipse($br,$cx-$r,$cy-$r,$r*2,$r*2); $br.Dispose()

            $numTxt = if ($step -gt $i+1) { [char]0x2713 } else { "$($i+1)" }
            $sf=[System.Drawing.StringFormat]::new()
            $sf.Alignment=[System.Drawing.StringAlignment]::Center
            $sf.LineAlignment=[System.Drawing.StringAlignment]::Center
            $wbr=[System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
            $g.DrawString($numTxt,$script:Fnt.Bold,$wbr,[System.Drawing.RectangleF]::new($cx-$r,$cy-$r,$r*2,$r*2),$sf)
            $wbr.Dispose()

            $lblClr  = if ($step -eq $i+1) { $script:Clr.Blue } else { $script:Clr.Muted }
            $lblFont = if ($step -eq $i+1) { $script:Fnt.SmBold } else { $script:Fnt.Small }
            $lbr=[System.Drawing.SolidBrush]::new($lblClr)
            $sf2=[System.Drawing.StringFormat]::new(); $sf2.Alignment=[System.Drawing.StringAlignment]::Center
            $g.DrawString($labels[$i],$lblFont,$lbr,[System.Drawing.RectangleF]::new($cx-55,$cy+$r+2,110,16),$sf2)
            $lbr.Dispose()
        }
    })
    return $p
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Navigation
# ═══════════════════════════════════════════════════════════════════════════════
function Show-Step ([int]$N) {
    if ($script:PollTimer) { $script:PollTimer.Stop(); $script:PollTimer.Dispose(); $script:PollTimer=$null }
    $script:CurrentStep=$N
    $script:StepIndicator.Invalidate()

    $script:Step1Panel.Visible = ($N -eq 1)
    $script:Step2Panel.Visible = ($N -eq 2)
    $script:Step3Panel.Visible = ($N -eq 3)
    $script:Step4Panel.Visible = ($N -eq 4)

    $script:BtnBack.Enabled = ($N -gt 1)
    switch ($N) {
        1 { $script:BtnNext.Text='Next →';            $script:BtnNext.Enabled=$true }
        2 { $script:BtnNext.Text='Submit Request';    $script:BtnNext.Enabled=$true }
        3 { $script:BtnNext.Text='Next →';            $script:BtnNext.Enabled=$false }
        4 { $script:BtnNext.Text='Install Certificate'; $script:BtnNext.Enabled=$true }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Action: Load Templates (CEP)
# ═══════════════════════════════════════════════════════════════════════════════
function Invoke-LoadTemplates {
    $cepUrl  = $script:TxtCepUrl.Text.Trim()
    $user    = $script:TxtUsername.Text.Trim()
    $pass    = $script:TxtPassword.Text
    if (-not $cepUrl) { [System.Windows.Forms.MessageBox]::Show('Enter the CEP Endpoint URL first.','Validation',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null; return }
    if (-not $user)   { [System.Windows.Forms.MessageBox]::Show('Enter your username first.','Validation',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null; return }
    if (-not $pass)   { [System.Windows.Forms.MessageBox]::Show('Enter your password first.','Validation',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null; return }

    $script:LblCepStatus.ForeColor=$script:Clr.Muted
    $script:LblCepStatus.Text='Querying Certificate Enrollment Policy service…'
    $script:MainForm.Cursor='WaitCursor'; [System.Windows.Forms.Application]::DoEvents()

    try {
        $soap   = New-GetPoliciesSoap $cepUrl $user $pass
        $xml    = Invoke-SoapRequest $cepUrl $soap $script:ChkSelfSigned.Checked
        $result = Read-CepResponse $xml

        # Populate template combo
        $script:CmbTemplate.Items.Clear()
        $script:CmbTemplate.Items.Add('— select a template —') | Out-Null
        foreach ($t in $result.Templates) {
            $display = if ($t.FriendlyName -ne $t.CommonName) { "$($t.FriendlyName) ($($t.CommonName))" } else { $t.CommonName }
            $item = [System.Windows.Forms.ListViewItem]::new()   # reuse object to carry Tag
            $script:CmbTemplate.Items.Add($display) | Out-Null
        }
        # Store CommonName values in Tag array for lookup
        $script:TemplateMap = $result.Templates   # list of @{CommonName;FriendlyName}
        $script:CmbTemplate.SelectedIndex=0

        # Auto-fill CES URL from policy (prefer authType=3: Username/Password)
        $cesUri = $result.CesUris | Where-Object { $_.AuthType -eq '3' } | Select-Object -First 1
        if (-not $cesUri) { $cesUri = $result.CesUris | Select-Object -First 1 }
        if ($cesUri -and -not $script:TxtCesUrl.Text) { $script:TxtCesUrl.Text = $cesUri.Uri }

        $cnt = $result.Templates.Count
        $script:LblCepStatus.ForeColor=$script:Clr.Green
        $script:LblCepStatus.Text="Loaded $cnt template$(if($cnt -ne 1){'s'})."
    } catch {
        $script:LblCepStatus.ForeColor=$script:Clr.Red
        $script:LblCepStatus.Text="Error: $($_.Exception.Message)"
    } finally {
        $script:MainForm.Cursor='Default'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Action: Submit enrollment request (CES)
# ═══════════════════════════════════════════════════════════════════════════════
function Get-ResolvedTemplateName {
    $idx = $script:CmbTemplate.SelectedIndex
    if ($script:TemplateMap -and $idx -gt 0 -and $idx -le $script:TemplateMap.Count) {
        return $script:TemplateMap[$idx-1].CommonName
    }
    return $script:TxtTemplateName.Text.Trim()
}

function Invoke-EnrollRequest {
    # Validate step 2
    $cn = $script:TxtCN.Text.Trim()
    if (-not $cn) {
        [System.Windows.Forms.MessageBox]::Show('Common Name (CN) is required.','Validation',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        Show-Step 2; return
    }

    Show-Step 3
    $script:LblStatus.Text='Generating key pair and submitting request…'
    $script:LblStatus.ForeColor=$script:Clr.Muted
    $script:PnlInfo.Visible=$false; $script:PnlNotice.Visible=$false
    $script:LblLastChecked.Visible=$false
    [System.Windows.Forms.Application]::DoEvents()

    $cesUrl   = $script:TxtCesUrl.Text.Trim()
    $user     = $script:TxtUsername.Text.Trim()
    $pass     = $script:TxtPassword.Text
    $template = Get-ResolvedTemplateName
    $selfSign = $script:ChkSelfSigned.Checked
    $keyBits  = switch ($script:CmbKeySize.SelectedIndex) { 1 {4096} 2 {1024} default {2048} }

    $sans = ($script:TxtSANs.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $subject = @{
        CN=$cn; O=$script:TxtOrg.Text.Trim(); OU=$script:TxtOU.Text.Trim()
        L=$script:TxtL.Text.Trim(); ST=$script:TxtST.Text.Trim(); C=$script:TxtC.Text.Trim()
        SANs=$sans
    }

    $script:MainForm.Cursor='WaitCursor'; [System.Windows.Forms.Application]::DoEvents()
    try {
        $csr64  = New-CertificateSigningRequest -Subject $subject -KeyBits $keyBits
        $soap   = New-EnrollSoap $cesUrl $user $pass $csr64 $template
        $xml    = Invoke-SoapRequest $cesUrl $soap $selfSign
        $result = Read-CesResponse $xml

        $script:EnrollCtx = @{
            RequestId=$result.RequestId; CesUrl=$cesUrl
            Username=$user; Password=$pass; AllowSelfSigned=$selfSign
        }
        Update-Step3Status $result
    } catch {
        $script:LblStatus.Text="Error: $($_.Exception.Message)"
        $script:LblStatus.ForeColor=$script:Clr.Red
        $script:BtnNext.Enabled=$false
    } finally {
        $script:MainForm.Cursor='Default'
    }
}

function Update-Step3Status ([hashtable]$Result) {
    $script:PnlInfo.Visible=$true
    $script:InfoValues['Request ID'].Text  = if ($Result.RequestId) { $Result.RequestId } else { '—' }
    $script:InfoValues['Disposition Message'].Text = if ($Result.Disposition) { $Result.Disposition } else { '—' }
    $script:PnlNotice.Controls.Clear(); $script:PnlNotice.Visible=$true

    switch ($Result.Status) {
        'issued' {
            $script:IssuedCert64 = $Result.Certificate
            $script:LblStatus.Text='Certificate issued'; $script:LblStatus.ForeColor=$script:Clr.Green
            $script:InfoValues['Status'].Text='Issued ✓'; $script:InfoValues['Status'].ForeColor=$script:Clr.Green
            $n = New-NoticePanel 'Certificate Issued' 'The CA approved your request. Click Next to install the certificate.' `
                ([System.Drawing.Color]::FromArgb(220,252,231)) $script:Clr.Green
            $n.Location=[System.Drawing.Point]::new(0,0); $script:PnlNotice.Controls.Add($n)
            $script:BtnNext.Enabled=$true
        }
        'pending' {
            $script:LblStatus.Text='Awaiting CA administrator approval…'; $script:LblStatus.ForeColor=$script:Clr.Amber
            $script:InfoValues['Status'].Text='Pending'; $script:InfoValues['Status'].ForeColor=$script:Clr.Amber
            $n = New-NoticePanel 'Awaiting Approval' 'Your request is queued. This window polls the CA every 30 seconds automatically.' `
                ([System.Drawing.Color]::FromArgb(254,243,199)) $script:Clr.Amber
            $n.Location=[System.Drawing.Point]::new(0,0); $script:PnlNotice.Controls.Add($n)
            $script:LblLastChecked.Text="Last checked: $(Get-Date -Format 'HH:mm:ss')"
            $script:LblLastChecked.Visible=$true
            Start-PollTimer
        }
        'denied' {
            $script:LblStatus.Text='Request denied'; $script:LblStatus.ForeColor=$script:Clr.Red
            $script:InfoValues['Status'].Text='Denied'; $script:InfoValues['Status'].ForeColor=$script:Clr.Red
            $n = New-NoticePanel 'Request Denied' 'The CA administrator denied this request. Go back and start a new request.' `
                ([System.Drawing.Color]::FromArgb(254,226,226)) $script:Clr.Red
            $n.Location=[System.Drawing.Point]::new(0,0); $script:PnlNotice.Controls.Add($n)
        }
        default {
            $script:LblStatus.Text="Unknown status: $($Result.Disposition)"; $script:LblStatus.ForeColor=$script:Clr.Muted
            $script:InfoValues['Status'].Text=$Result.Status
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Poll timer
# ═══════════════════════════════════════════════════════════════════════════════
function Start-PollTimer {
    if ($script:PollTimer) { $script:PollTimer.Stop(); $script:PollTimer.Dispose() }
    $t=[System.Windows.Forms.Timer]::new(); $t.Interval=30000
    $t.Add_Tick({
        if (-not $script:EnrollCtx) { return }
        try {
            $soap   = New-RetrieveSoap $script:EnrollCtx.CesUrl $script:EnrollCtx.Username `
                                       $script:EnrollCtx.Password $script:EnrollCtx.RequestId
            $xml    = Invoke-SoapRequest $script:EnrollCtx.CesUrl $soap $script:EnrollCtx.AllowSelfSigned
            $result = Read-CesResponse $xml
            $script:LblLastChecked.Text="Last checked: $(Get-Date -Format 'HH:mm:ss')"
            if ($result.Status -ne 'pending') {
                $script:PollTimer.Stop()
                Update-Step3Status $result
            }
        } catch { $script:LblLastChecked.Text="Poll error: $($_.Exception.Message)" }
    })
    $script:PollTimer=$t; $t.Start()
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Action: Install certificate
# ═══════════════════════════════════════════════════════════════════════════════
function Invoke-InstallCertificate {
    $loc  = $script:CmbStoreLocation.SelectedItem
    $name = $script:CmbStoreName.SelectedItem

    if ($loc -eq 'LocalMachine' -and -not (Test-IsAdmin)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Installing to LocalMachine requires Administrator privileges.`nRestart this script as Administrator, or choose CurrentUser instead.",
            'Elevation Required',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        return
    }

    $script:PnlInstallResult.Controls.Clear(); $script:PnlInstallResult.Visible=$false
    $script:BtnNext.Enabled=$false; $script:MainForm.Cursor='WaitCursor'
    [System.Windows.Forms.Application]::DoEvents()

    try {
        $thumb = Install-IssuedCertificate -CertBase64 $script:IssuedCert64 `
                                           -PrivateKey  $script:RsaKey `
                                           -StoreLocation $loc -StoreName $name

        $n = New-NoticePanel "Certificate Installed — $loc\$name" `
            "Thumbprint: $thumb`r`nVerify in certlm.msc (Local Machine) or certmgr.msc (Current User)." `
            ([System.Drawing.Color]::FromArgb(220,252,231)) $script:Clr.Green
        $n.Location=[System.Drawing.Point]::new(0,0)
        $script:PnlInstallResult.Controls.Add($n)
        $script:PnlInstallResult.Height = $n.Height
        $script:PnlInstallResult.Visible=$true

        $script:RsaKey=$null; $script:IssuedCert64=$null; $script:EnrollCtx=$null
        $script:BtnNext.Text='Start Over'; $script:BtnNext.Enabled=$true
    } catch {
        $n = New-NoticePanel 'Installation Failed' $_.Exception.Message `
            ([System.Drawing.Color]::FromArgb(254,226,226)) $script:Clr.Red
        $n.Location=[System.Drawing.Point]::new(0,0)
        $script:PnlInstallResult.Controls.Add($n)
        $script:PnlInstallResult.Height = $n.Height
        $script:PnlInstallResult.Visible=$true
        $script:BtnNext.Enabled=$true
    } finally {
        $script:MainForm.Cursor='Default'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Build main form
# ═══════════════════════════════════════════════════════════════════════════════
$script:MainForm = [System.Windows.Forms.Form]::new()
$f=$script:MainForm
$f.Text='ADCS Certificate Enrollment'; $f.Size=[System.Drawing.Size]::new(794,642)
$f.FormBorderStyle='FixedSingle'; $f.MaximizeBox=$false
$f.StartPosition='CenterScreen'; $f.BackColor=$script:Clr.White
$f.Font=$script:Fnt.Body

# Header
$hdr=[System.Windows.Forms.Panel]::new()
$hdr.Location=[System.Drawing.Point]::new(0,0); $hdr.Size=[System.Drawing.Size]::new(778,65)
$hdr.BackColor=$script:Clr.BgBlue
$hdrTitle=[System.Windows.Forms.Label]::new()
$hdrTitle.Text='  🔒  ADCS Certificate Enrollment'; $hdrTitle.Font=$script:Fnt.Title
$hdrTitle.ForeColor=$script:Clr.White; $hdrTitle.Location=[System.Drawing.Point]::new(0,8)
$hdrTitle.Size=[System.Drawing.Size]::new(778,28); $hdr.Controls.Add($hdrTitle)
$hdrSub=[System.Windows.Forms.Label]::new()
$hdrSub.Text='  Request and install certificates via Active Directory Certificate Services (MS-WSTEP / MS-XCEP)'
$hdrSub.Font=$script:Fnt.Small; $hdrSub.ForeColor=[System.Drawing.Color]::FromArgb(180,210,255)
$hdrSub.Location=[System.Drawing.Point]::new(0,36); $hdrSub.Size=[System.Drawing.Size]::new(778,20)
$hdr.Controls.Add($hdrSub); $f.Controls.Add($hdr)

# Step indicator
$script:StepIndicator = New-StepIndicatorPanel
$script:StepIndicator.Location=[System.Drawing.Point]::new(0,65)
$f.Controls.Add($script:StepIndicator)

# Content area
$content=[System.Windows.Forms.Panel]::new()
$content.Location=[System.Drawing.Point]::new(0,117); $content.Size=[System.Drawing.Size]::new(778,462)
$content.BackColor=$script:Clr.White; $content.AutoScroll=$true

$script:Step1Panel = Build-Step1; $content.Controls.Add($script:Step1Panel)
$script:Step2Panel = Build-Step2; $content.Controls.Add($script:Step2Panel)
$script:Step3Panel = Build-Step3; $content.Controls.Add($script:Step3Panel)
$script:Step4Panel = Build-Step4; $content.Controls.Add($script:Step4Panel)
$f.Controls.Add($content)

# Footer
$footer=[System.Windows.Forms.Panel]::new()
$footer.Location=[System.Drawing.Point]::new(0,579); $footer.Size=[System.Drawing.Size]::new(778,63)
$footer.BackColor=$script:Clr.LtGray
$footer.Add_Paint({ param($s,$e); $e.Graphics.DrawLine([System.Drawing.Pens]::LightGray,0,0,$s.Width,0) })

$script:BtnBack = New-Btn '← Back' 14 16 110 30 $script:Clr.Text ([System.Drawing.Color]::FromArgb(229,231,235))
$script:BtnBack.Add_Click({ Show-Step ($script:CurrentStep - 1) })
$footer.Controls.Add($script:BtnBack)

$script:BtnNext = New-Btn 'Next →' 652 16 112 30
$script:BtnNext.Add_Click({
    switch ($script:CurrentStep) {
        1 {
            $u=$script:TxtUsername.Text.Trim(); $p=$script:TxtPassword.Text
            $ces=$script:TxtCesUrl.Text.Trim(); $tmpl=Get-ResolvedTemplateName
            if (-not $u)    { [System.Windows.Forms.MessageBox]::Show('Username is required.','Validation',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)|Out-Null; return }
            if (-not $p)    { [System.Windows.Forms.MessageBox]::Show('Password is required.','Validation',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)|Out-Null; return }
            if (-not $ces)  { [System.Windows.Forms.MessageBox]::Show('CES Endpoint URL is required.','Validation',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)|Out-Null; return }
            if (-not $tmpl) { [System.Windows.Forms.MessageBox]::Show('Select or enter a Certificate Template name.','Validation',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)|Out-Null; return }
            Show-Step 2
        }
        2 { Invoke-EnrollRequest }
        3 { Show-Step 4 }
        4 {
            if ($script:BtnNext.Text -eq 'Start Over') {
                # Reset state for a new request
                $script:TxtPassword.Text=''; $script:IssuedCert64=$null
                $script:RsaKey=$null; $script:EnrollCtx=$null
                $script:TemplateMap=$null
                $script:PnlInstallResult.Controls.Clear(); $script:PnlInstallResult.Visible=$false
                Show-Step 1
            } else {
                Invoke-InstallCertificate
            }
        }
    }
})
$footer.Controls.Add($script:BtnNext)
$f.Controls.Add($footer)

# ── Populate DNS-based defaults on load ───────────────────────────────────────
$f.Add_Shown({
    $suffix = Get-PrimaryDnsSuffix
    if ($suffix) {
        if (-not $script:TxtCepUrl.Text) {
            $script:TxtCepUrl.Text="https://$suffix/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP"
        }
        if (-not $script:TxtCesUrl.Text) {
            $script:TxtCesUrl.Text="https://$suffix/CertSrv/CES/service.svc/CES"
        }
    }
})

$script:TemplateMap = $null
Show-Step 1
[System.Windows.Forms.Application]::Run($f)
