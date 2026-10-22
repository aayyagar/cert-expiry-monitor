# Certificate Expiry Monitor

A read-only PowerShell tool that scans TLS/SSL certificates across your servers and endpoints and tells you which ones are about to expire, with a clean HTML dashboard and alerting bands at **30 / 14 / 7 days**.

Expired certificates cause real outages — a missed renewal on a DNS, IIS, VPN or load-balancer endpoint takes a service down. This tool makes expiry visible before it bites.

**[View the sample dashboard →](https://aayyagar.github.io/cert-expiry-monitor/sample-report/)**

## What it scans

- **Endpoints** — connects over TLS to `host:port` and reads the live certificate. Works for HTTPS (443), LDAPS (636), IMAPS/SMTPS (993/465), and any custom port. This is what a load balancer or reverse proxy actually serves.
- **IIS bindings** — certificates bound to sites on a Windows host.
- **Local certificate store** — certificates in `LocalMachine\My` or another store (DCs, WSUS, IIS, internal services).

Each certificate is reported with its common name, issuer, expiry date, days remaining and a severity. Unreachable endpoints are flagged separately so a down host is never mistaken for a healthy one.

## Quick start

```powershell
# See the dashboard with sample data
.\Invoke-CertExpiryScan.ps1 -Demo

# Scan specific endpoints
.\Invoke-CertExpiryScan.ps1 -Endpoints www.example.com:443, mail.example.com:993

# Scan a list of endpoints and the local machine store
.\Invoke-CertExpiryScan.ps1 -EndpointFile .\endpoints.txt -IncludeLocalStore
```

Output (HTML dashboard, JSON and CSV) is written to `.\CertReport\`.

## Severity bands

| Band | Meaning |
|---|---|
| **Expired** | Already past expiry — service likely broken |
| **Urgent** | ≤ 7 days |
| **Critical** | ≤ 14 days |
| **Warning** | ≤ 30 days |
| **OK** | More than 30 days left |
| **Error** | Endpoint unreachable (timeout, refused, TLS failure) |

Thresholds are adjustable with `-WarningDays`, `-CriticalDays` and `-UrgentDays`.

## Run it on a schedule

Register a daily scan that writes the dashboard to a shared folder:

```powershell
.\Register-CertScanTask.ps1 -EndpointFile C:\certs\endpoints.txt -OutputPath C:\certs\reports -At 07:00
```

The scanner also returns a non-zero exit code when anything is expired or within 7 days, so you can wire it into existing monitoring or a pipeline gate.

## Parameters

| Parameter | Description |
|---|---|
| `-Endpoints` | One or more `host:port` targets |
| `-EndpointFile` | Text file, one `host:port` per line (`#` comments allowed) |
| `-IncludeLocalStore` | Also scan a Windows certificate store |
| `-StoreLocation` / `-StoreName` | Which store (default `LocalMachine\My`) |
| `-WarningDays` / `-CriticalDays` / `-UrgentDays` | Thresholds (default 30 / 14 / 7) |
| `-TimeoutSeconds` | TLS connect timeout per endpoint (default 5) |
| `-OutputPath` | Output folder (default `.\CertReport`) |
| `-Demo` | Use built-in sample data |

## Why this exists

This comes straight from enterprise certificate-lifecycle work: renewing SSL/TLS certificates on IIS, DNS and WSUS servers, where a missed renewal means an outage and an incident bridge. A simple, read-only inventory with early warning prevents most of those.

## Requirements

- PowerShell 5.1 or 7+
- Network access to the endpoints you scan
- For the local store or IIS checks, run on the relevant Windows host

## Output

- **HTML dashboard** — sortable severity view, suitable to email or publish
- **JSON** — full detail for automation
- **CSV** — for spreadsheets and ticketing

## Author

**Akhilesh Ayyagari**, Cloud Infrastructure & Identity Architect · [Portfolio](https://aayyagar.github.io) · [LinkedIn](https://www.linkedin.com/in/akhilesh-ayyagari)

## License

MIT
