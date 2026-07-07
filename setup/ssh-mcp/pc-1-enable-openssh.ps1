#Requires -RunAsAdministrator
<#
  Run this ON THE HOME PC (Windows 11) in an ELEVATED PowerShell.
  Enables OpenSSH Server, makes PowerShell the default SSH shell, and restricts
  inbound SSH to the Tailscale network only (never the public internet).
#>
$ErrorActionPreference = 'Stop'
$TailscaleCgnat = '100.64.0.0/10'   # Tailscale's address range (covers 100.99.182.30)

Write-Host '== 1/4 Installing OpenSSH Server capability ==' -ForegroundColor Cyan
$cap = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' }
if ($cap.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
    Write-Host 'Installed.'
} else {
    Write-Host 'Already installed.'
}

Write-Host '== 2/4 Starting sshd and enabling at boot ==' -ForegroundColor Cyan
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

Write-Host '== 3/4 Setting default SSH shell to PowerShell ==' -ForegroundColor Cyan
$psPath = (Get-Command powershell.exe).Source
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
    -Value $psPath -PropertyType String -Force | Out-Null
Write-Host "DefaultShell = $psPath"

Write-Host '== 4/4 Restricting firewall to Tailscale only ==' -ForegroundColor Cyan
# Disable the broad default rule that opens port 22 to every network
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
# Replace any prior scoped rule (so re-runs are clean)
Get-NetFirewallRule -DisplayName 'SSH from Tailscale only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'SSH from Tailscale only' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 22 -RemoteAddress $TailscaleCgnat | Out-Null
Write-Host 'Inbound SSH now allowed only from 100.64.0.0/10 (Tailscale).'

Write-Host ''
Write-Host 'sshd status:' -ForegroundColor Green
Get-Service sshd | Format-Table -AutoSize
Write-Host "==> Your Windows username is: $env:USERNAME" -ForegroundColor Yellow
Write-Host '    Use it on the laptop:  ./laptop-setup.ps1 -PcUser ' -NoNewline -ForegroundColor Yellow
Write-Host $env:USERNAME -ForegroundColor Yellow
