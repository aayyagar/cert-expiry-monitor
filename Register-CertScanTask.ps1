#Requires -Version 5.1
<#
.SYNOPSIS
    Registers a daily scheduled task that runs the certificate scan and saves the dashboard.
.DESCRIPTION
    Convenience helper for Windows. Creates a task that runs Invoke-CertExpiryScan.ps1 each
    morning against an endpoint file, writing the dashboard to a shared folder you can bookmark.
.EXAMPLE
    .\Register-CertScanTask.ps1 -EndpointFile C:\certs\endpoints.txt -OutputPath C:\certs\reports -At 07:00
.NOTES
    Author : Akhilesh Ayyagari (github.com/aayyagar)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EndpointFile,
    [string]$OutputPath = 'C:\CertReports',
    [string]$At = '07:00',
    [string]$TaskName = 'Certificate Expiry Scan'
)
$script = Join-Path $PSScriptRoot 'Invoke-CertExpiryScan.ps1'
$arg = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -EndpointFile `"$EndpointFile`" -OutputPath `"$OutputPath`""
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
$trigger   = New-ScheduledTaskTrigger -Daily -At $At
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force
Write-Host "Registered '$TaskName' to run daily at $At." -ForegroundColor Green
