# Windows Full System Report

Comprehensive PowerShell 5.1+ inventory and diagnostic report generator for Windows 10 and Windows 11.

The script preserves the original report areas and expands collection across hardware, firmware, storage, networking, software, processes, services, security, accounts, shares, startup, scheduled tasks, updates, policies, virtualization and event diagnostics. Output is written to one timestamped UTF-8 TXT file.

## Quick start

```powershell
Unblock-File .\Windows-FullSystemReport.ps1
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Windows-FullSystemReport.ps1
```

Run PowerShell as Administrator for the most complete result. The script continues when individual commands are unavailable or access is denied.

## Useful options

```powershell
.\Windows-FullSystemReport.ps1 -OutputDirectory C:\Temp -OpenReport
```

```powershell
.\Windows-FullSystemReport.ps1 -EventCount 200 -DriverLimit 1000 -ConnectionLimit 1000
```

```powershell
.\Windows-FullSystemReport.ps1 -SkipEventLogs -SkipDefender -SkipUserData
```

```powershell
.\Windows-FullSystemReport.ps1 -IncludeEnvironment
```

## Report coverage

- Windows identity, edition, build, installation, uptime, locale and time
- BIOS, baseboard, chassis, CPU, RAM, GPU, monitors, audio, battery, power, USB and PnP
- Logical and physical storage, partitions, volumes, reliability counters, BitLocker and shadow copies
- Adapters, profiles, advanced properties, traffic counters, IP, DNS, routes, Wi-Fi, proxy, ARP and hosts
- TCP listeners, UDP endpoints, established connections, process ownership and netstat
- Registry software, Store apps, provisioned packages, optional features, capabilities and runtimes
- Processes, owners, command lines, CPU, memory and services
- Defender, firewall, Secure Boot, TPM, Device Guard, BitLocker, UAC, audit policy and certificates
- Local users, groups, sessions, profiles, shares, SMB, mapped drives and printers
- Registry startup, startup folders and scheduled tasks
- Hotfixes, Windows Update history, DISM packages, component store and pending reboot indicators
- Hyper-V, WSL, Docker, execution policies and PowerShell logging settings
- Event logs, reliability records, boot performance, bugchecks, SFC and DISM health
- Per-block execution summary

## Privacy warning

The TXT report can contain usernames, computer names, domain names, serial numbers, MAC addresses, IP addresses, installed software, process command lines, network connections, certificates, group memberships, shares, event messages and security configuration. Review and sanitize the report before publishing or sending outside the authorized support channel.

The repository `.gitignore` excludes generated reports.

## Parameters

- `OutputDirectory`: destination directory
- `EventCount`: number of events per event section
- `DriverLimit`: maximum signed-driver records
- `ConnectionLimit`: maximum established connections
- `SkipEventLogs`: skips event-log sections
- `SkipDefender`: skips Defender cmdlets
- `SkipUserData`: skips logged-on-user and profile sections
- `IncludeEnvironment`: includes environment variables
- `OpenReport`: opens the report in Notepad at completion

## Validation

```powershell
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path '.\Windows-FullSystemReport.ps1'),
  [ref]$tokens,
  [ref]$errors
) | Out-Null
$errors
```

## License

MIT. See [LICENSE](LICENSE).
