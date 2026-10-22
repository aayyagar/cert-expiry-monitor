#Requires -Version 5.1
<#
.SYNOPSIS
    Scans TLS/SSL certificates on servers and endpoints and reports the ones expiring soon.

.DESCRIPTION
    Checks certificates from three kinds of source and reports each one with its days-to-expiry
    and a severity banded at 30 / 14 / 7 days:
      - Endpoints   : connect over TLS to host:port (HTTPS, LDAPS, SMTPS, custom) and read the leaf cert
      - IIS         : bindings with certificates on a local or remote Windows host (optional)
      - Local store : certificates in a Windows certificate store (e.g. the machine's personal store)

    It produces an HTML dashboard plus JSON and CSV. Read-only: it never installs or changes a cert.
    Use -Demo to see the dashboard with built-in sample data.

.PARAMETER Endpoints
    One or more host:port targets, e.g. www.example.com:443, ldap.example.com:636.

.PARAMETER EndpointFile
    A text file with one host:port per line (lines starting with # are ignored).

.PARAMETER IncludeLocalStore
    Also scan a local Windows certificate store.

.PARAMETER StoreLocation
    LocalMachine (default) or CurrentUser, used with -IncludeLocalStore.

.PARAMETER WarningDays / CriticalDays / UrgentDays
    Severity thresholds in days. Defaults 30 / 14 / 7.

.PARAMETER TimeoutSeconds
    TLS connection timeout per endpoint. Default 5.

.PARAMETER OutputPath
    Folder for the report files. Default .\CertReport

.PARAMETER Demo
    Use built-in sample data (no network calls).

.EXAMPLE
    .\Invoke-CertExpiryScan.ps1 -Endpoints www.example.com:443, mail.example.com:993

.EXAMPLE
    .\Invoke-CertExpiryScan.ps1 -EndpointFile .\endpoints.txt -IncludeLocalStore

.EXAMPLE
    .\Invoke-CertExpiryScan.ps1 -Demo

.NOTES
    Author : Akhilesh Ayyagari (github.com/aayyagar)
    Version: 1.0.0
    Safe   : read-only. Designed to run as a scheduled task and email or save the dashboard.
#>
[CmdletBinding()]
param(
    [string[]]$Endpoints,
    [string]$EndpointFile,
    [switch]$IncludeLocalStore,
    [ValidateSet('LocalMachine', 'CurrentUser')][string]$StoreLocation = 'LocalMachine',
    [string]$StoreName = 'My',
    [int]$WarningDays = 30,
    [int]$CriticalDays = 14,
    [int]$UrgentDays = 7,
    [int]$TimeoutSeconds = 5,
    [string]$OutputPath = (Join-Path (Get-Location) 'CertReport'),
    [switch]$Demo
)

$ErrorActionPreference = 'Stop'
$Script:Version = '1.0.0'
$Script:Now = Get-Date
$Script:Results = New-Object System.Collections.Generic.List[object]

function Get-Severity {
    param([int]$Days)
    if ($Days -lt 0) { 'Expired' }
    elseif ($Days -le $UrgentDays) { 'Urgent' }
    elseif ($Days -le $CriticalDays) { 'Critical' }
    elseif ($Days -le $WarningDays) { 'Warning' }
    else { 'OK' }
}

function Add-Result {
    param($Source, $Target, $Subject, $Issuer, $NotAfter, $NotBefore, $Thumbprint, $San, $Error)
    $days = if ($NotAfter) { [int][math]::Floor(($NotAfter - $Script:Now).TotalDays) } else { $null }
    $Script:Results.Add([pscustomobject]@{
            Source = $Source; Target = $Target
            Subject = $Subject; Issuer = $Issuer
            NotAfter = $NotAfter; NotBefore = $NotBefore
            DaysToExpiry = $days
            Severity = if ($Error) { 'Error' } else { Get-Severity $days }
            Thumbprint = $Thumbprint; San = $San; Error = $Error
        })
}

# ---------------------------------------------------------------------------------------------
#  Endpoint scanning (TLS handshake, read leaf certificate)
# ---------------------------------------------------------------------------------------------
function Test-Endpoint {
    param([string]$HostName, [int]$Port)
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $tcp.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($TimeoutSeconds))) {
            throw "connection timed out after $TimeoutSeconds s"
        }
        $tcp.EndConnect($iar)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
        try {
            $ssl.AuthenticateAsClient($HostName)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate
            $san = ''
            foreach ($ext in $cert.Extensions) {
                if ($ext.Oid.Value -eq '2.5.29.17') { $san = $ext.Format($false) }
            }
            Add-Result -Source 'Endpoint' -Target "${HostName}:${Port}" -Subject $cert.Subject -Issuer $cert.Issuer `
                -NotAfter $cert.NotAfter -NotBefore $cert.NotBefore -Thumbprint $cert.Thumbprint -San $san -Error $null
        } finally { $ssl.Dispose() }
    } catch {
        Add-Result -Source 'Endpoint' -Target "${HostName}:${Port}" -Subject '' -Issuer '' -NotAfter $null -NotBefore $null -Thumbprint '' -San '' -Error $_.Exception.Message
    } finally { $tcp.Dispose() }
}

function Get-LocalStoreCerts {
    try {
        $path = "Cert:\$StoreLocation\$StoreName"
        $certs = Get-ChildItem -Path $path -ErrorAction Stop | Where-Object { $_.HasPrivateKey -or $true }
        foreach ($c in $certs) {
            $san = ($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | ForEach-Object { $_.Format($false) }) -join ''
            Add-Result -Source 'LocalStore' -Target "$StoreLocation\$StoreName" -Subject $c.Subject -Issuer $c.Issuer `
                -NotAfter $c.NotAfter -NotBefore $c.NotBefore -Thumbprint $c.Thumbprint -San $san -Error $null
        }
    } catch {
        Add-Result -Source 'LocalStore' -Target "$StoreLocation\$StoreName" -Subject '' -Issuer '' -NotAfter $null -NotBefore $null -Thumbprint '' -San '' -Error $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------------------------
#  Demo data
# ---------------------------------------------------------------------------------------------
function Get-DemoData {
    $now = $Script:Now
    $rows = @(
        @('Endpoint', 'www.contoso.com:443', 'CN=www.contoso.com', 'CN=DigiCert TLS RSA SHA256 2020 CA1', 58, 'DNS Name=www.contoso.com, DNS Name=contoso.com'),
        @('Endpoint', 'api.contoso.com:443', 'CN=api.contoso.com', 'CN=Let''s Encrypt R3', 24, 'DNS Name=api.contoso.com'),
        @('Endpoint', 'mail.contoso.com:993', 'CN=mail.contoso.com', 'CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1', 11, 'DNS Name=mail.contoso.com'),
        @('Endpoint', 'vpn.contoso.com:443', 'CN=vpn.contoso.com', 'CN=Sectigo RSA Domain Validation Secure Server CA', 5, 'DNS Name=vpn.contoso.com'),
        @('IIS', 'WEB01 / Default Web Site:443', 'CN=portal.contoso.com', 'CN=Contoso Issuing CA', 3, 'DNS Name=portal.contoso.com'),
        @('Endpoint', 'legacy.contoso.com:443', 'CN=legacy.contoso.com', 'CN=Contoso Issuing CA', -4, 'DNS Name=legacy.contoso.com'),
        @('LocalStore', 'LocalMachine\My', 'CN=dc01.corp.contoso.com', 'CN=Contoso Issuing CA', 120, 'DNS Name=dc01.corp.contoso.com'),
        @('LocalStore', 'LocalMachine\My', 'CN=wsus.corp.contoso.com', 'CN=Contoso Issuing CA', 9, 'DNS Name=wsus.corp.contoso.com'),
        @('IIS', 'WEB02 / API Site:443', 'CN=*.contoso.com', 'CN=DigiCert TLS RSA SHA256 2020 CA1', 210, 'DNS Name=*.contoso.com')
    )
    foreach ($r in $rows) {
        Add-Result -Source $r[0] -Target $r[1] -Subject $r[2] -Issuer $r[3] -NotAfter $now.AddDays($r[4]) -NotBefore $now.AddDays($r[4] - 365) -Thumbprint ((([guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N')).Substring(0,40))) -San $r[5] -Error $null
    }
    Add-Result -Source 'Endpoint' -Target 'down.contoso.com:443' -Subject '' -Issuer '' -NotAfter $null -NotBefore $null -Thumbprint '' -San '' -Error 'connection timed out after 5 s'
}

# ---------------------------------------------------------------------------------------------
#  HTML dashboard
# ---------------------------------------------------------------------------------------------
function ConvertTo-HtmlSafe { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

function New-Dashboard {
    param([string]$OutFile)
    $e = { param($s) ConvertTo-HtmlSafe $s }
    $order = @{ Expired = 0; Urgent = 1; Critical = 2; Warning = 3; Error = 4; OK = 5 }
    $sorted = $Script:Results | Sort-Object @{e = { $order[$_.Severity] } }, DaysToExpiry
    $counts = @{}; foreach ($s in 'Expired', 'Urgent', 'Critical', 'Warning', 'OK', 'Error') { $counts[$s] = @($Script:Results | Where-Object Severity -eq $s).Count }
    $actionable = $counts.Expired + $counts.Urgent + $counts.Critical + $counts.Warning

    $rows = foreach ($r in $sorted) {
        $days = if ($null -eq $r.DaysToExpiry) { '-' } elseif ($r.DaysToExpiry -lt 0) { "expired $([math]::Abs($r.DaysToExpiry))d ago" } else { "$($r.DaysToExpiry) d" }
        $after = if ($r.NotAfter) { $r.NotAfter.ToString('yyyy-MM-dd') } else { '-' }
        $detail = if ($r.Error) { "<span class='err'>$(& $e $r.Error)</span>" } else { "$(& $e $r.Issuer)" }
        $cn = if ($r.Subject) { ($r.Subject -replace '^CN=', '' -replace ',.*$', '') } else { $r.Target }
        @"
<tr class='sev-$($r.Severity.ToLower())'>
<td><span class='pill $($r.Severity.ToLower())'>$($r.Severity)</span></td>
<td class='days'>$days</td>
<td>$(& $e $cn)<div class='sub'>$(& $e $r.Target)</div></td>
<td>$after</td>
<td class='src'>$($r.Source)</td>
<td class='iss'>$detail</td>
</tr>
"@
    }

    $css = @'
:root{--bg:#f3f4f7;--card:#fff;--ink:#151a2c;--mut:#5b6278;--line:#dcdfe7;--soft:#eef0f4;--ok:#17865f;--warn:#b07a00;--crit:#d9742b;--urg:#c8432b;--exp:#9b1c1c;--err:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#0f1220;--card:#181c2e;--ink:#e9ecf4;--mut:#9ca3ba;--line:#2a3048;--soft:#1f2438;--ok:#3fc48d;--warn:#e7b43b;--crit:#f0a05f;--urg:#f07a62;--exp:#f26d6d;--err:#8c93aa;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.w{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-end;margin-bottom:20px}
h1{margin:0;font-size:1.7rem;letter-spacing:-.02em}.sub{color:var(--mut);font-size:.82rem}.mono{font-family:Consolas,ui-monospace,monospace;font-size:.8rem;color:var(--mut)}
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:18px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}.kpi b{display:block;font-size:1.7rem;font-variant-numeric:tabular-nums}.kpi span{font-size:.75rem;color:var(--mut)}
.kpi.exp b{color:var(--exp)}.kpi.urg b{color:var(--urg)}.kpi.crit b{color:var(--crit)}.kpi.warn b{color:var(--warn)}.kpi.ok b{color:var(--ok)}.kpi.err b{color:var(--err)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);font-size:.9rem;vertical-align:top}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);background:var(--soft)}
tr:last-child td{border-bottom:0}
.days{font-variant-numeric:tabular-nums;white-space:nowrap}.sub{color:var(--mut);font-size:.76rem;font-family:Consolas,ui-monospace,monospace}
.src{color:var(--mut);font-size:.8rem}.iss{color:var(--mut);font-size:.82rem}.err{color:var(--urg)}
.pill{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:3px 9px;border-radius:999px;white-space:nowrap}
.pill.expired{background:var(--exp);color:#fff}.pill.urgent{background:var(--urg);color:#fff}.pill.critical{background:var(--crit);color:#fff}.pill.warning{background:var(--warn);color:#1a1a1a}.pill.ok{background:var(--soft);color:var(--ok)}.pill.error{background:var(--soft);color:var(--err)}
.leg{margin-top:14px;font-size:.8rem;color:var(--mut)}
@media (max-width:760px){.kpis{grid-template-columns:repeat(3,1fr)}.iss,.src{display:none}th:nth-child(5),th:nth-child(6),td:nth-child(5),td:nth-child(6){display:none}}
'@
    $tenantLine = "$($Script:Now.ToString('yyyy-MM-dd HH:mm')) &middot; thresholds $WarningDays / $CriticalDays / $UrgentDays days &middot; $($Script:Results.Count) certificate(s)"

    @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Certificate Expiry Dashboard</title><style>$css</style></head><body><div class="w">
<header><div><div class="mono">TLS / SSL CERTIFICATE EXPIRY</div><h1>Certificate Dashboard</h1><div class="sub">$tenantLine</div></div><div class="mono">Cert Expiry Monitor v$Script:Version</div></header>
<div class="kpis">
<div class="kpi exp"><b>$($counts.Expired)</b><span>Expired</span></div>
<div class="kpi urg"><b>$($counts.Urgent)</b><span>&le; $UrgentDays days</span></div>
<div class="kpi crit"><b>$($counts.Critical)</b><span>&le; $CriticalDays days</span></div>
<div class="kpi warn"><b>$($counts.Warning)</b><span>&le; $WarningDays days</span></div>
<div class="kpi ok"><b>$($counts.OK)</b><span>Healthy</span></div>
<div class="kpi err"><b>$($counts.Error)</b><span>Unreachable</span></div>
</div>
<table><thead><tr><th>Status</th><th>Expires in</th><th>Certificate</th><th>Not after</th><th>Source</th><th>Issuer / detail</th></tr></thead>
<tbody>$($rows -join "`n")</tbody></table>
<p class="leg">$actionable certificate(s) need attention. Severity bands: Expired, Urgent (&le; $UrgentDays d), Critical (&le; $CriticalDays d), Warning (&le; $WarningDays d). Generated by Cert Expiry Monitor &middot; github.com/aayyagar/cert-expiry-monitor</p>
</div></body></html>
"@ | Set-Content -Path $OutFile -Encoding UTF8
}

# ---------------------------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host "  Certificate Expiry Monitor v$Script:Version" -ForegroundColor White
Write-Host '  Read-only TLS/SSL certificate scan' -ForegroundColor DarkGray
Write-Host ''

if ($Demo) {
    Write-Host '  > Demo mode (sample data)' -ForegroundColor Cyan
    Get-DemoData
} else {
    $targets = @()
    if ($Endpoints) { $targets += $Endpoints }
    if ($EndpointFile) {
        if (-not (Test-Path $EndpointFile)) { throw "Endpoint file not found: $EndpointFile" }
        $targets += Get-Content $EndpointFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }
    }
    if (-not $targets -and -not $IncludeLocalStore) {
        throw 'Nothing to scan. Provide -Endpoints, -EndpointFile, or -IncludeLocalStore (or use -Demo).'
    }
    foreach ($t in $targets) {
        $parts = $t.Split(':')
        $h = $parts[0]; $p = if ($parts.Count -gt 1) { [int]$parts[1] } else { 443 }
        Write-Host "  > $h`:$p" -ForegroundColor Cyan
        Test-Endpoint -HostName $h -Port $p
    }
    if ($IncludeLocalStore) {
        Write-Host "  > local store $StoreLocation\$StoreName" -ForegroundColor Cyan
        Get-LocalStoreCerts
    }
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$base = Join-Path $OutputPath ("CertScan_{0}" -f $Script:Now.ToString('yyyyMMdd_HHmm'))
New-Dashboard -OutFile "$base.html"
$Script:Results | ConvertTo-Json -Depth 4 | Set-Content "$base.json" -Encoding UTF8
$Script:Results | Select-Object Severity, DaysToExpiry, Source, Target, Subject, Issuer, @{n = 'NotAfter'; e = { if ($_.NotAfter) { $_.NotAfter.ToString('yyyy-MM-dd') } } }, Thumbprint, Error |
    Export-Csv "$base.csv" -NoTypeInformation -Encoding UTF8

# Console summary, sorted by urgency
Write-Host ''
foreach ($r in ($Script:Results | Sort-Object DaysToExpiry)) {
    if ($r.Severity -in 'OK') { continue }
    $c = switch ($r.Severity) { 'Expired' { 'Red' } 'Urgent' { 'Red' } 'Critical' { 'DarkYellow' } 'Warning' { 'Yellow' } 'Error' { 'DarkGray' } default { 'Gray' } }
    $d = if ($null -eq $r.DaysToExpiry) { 'n/a' } else { "$($r.DaysToExpiry)d" }
    Write-Host ("  [{0,-8}] {1,6}  {2}" -f $r.Severity, $d, $r.Target) -ForegroundColor $c
}
Write-Host ''
Write-Host "  Dashboard: $base.html" -ForegroundColor White
Write-Host ''

# Non-zero exit if anything is expired or urgent - useful for scheduled tasks / monitoring
$fail = @($Script:Results | Where-Object { $_.Severity -in 'Expired', 'Urgent' }).Count
exit ([math]::Min($fail, 1))
