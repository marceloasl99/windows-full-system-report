#requires -Version 5.1
<#
.SYNOPSIS
    Generates a comprehensive Windows system inventory and diagnostic TXT report.
.DESCRIPTION
    Collects operating-system, hardware, firmware, storage, network, ports,
    software, processes, services, security, users, shares, startup, scheduled
    tasks, updates, event logs, policies and troubleshooting information.
    Existing report areas are preserved and additional sections are appended.
.NOTES
    The report can contain sensitive operational data. Review before sharing.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Get-Location).Path,
    [ValidateRange(10,1000)][int]$EventCount = 100,
    [ValidateRange(50,5000)][int]$DriverLimit = 500,
    [ValidateRange(50,5000)][int]$ConnectionLimit = 500,
    [switch]$SkipEventLogs,
    [switch]$SkipDefender,
    [switch]$SkipUserData,
    [switch]$IncludeEnvironment,
    [switch]$OpenReport
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'SilentlyContinue'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$Output = Join-Path -Path $OutputDirectory -ChildPath "Full_Report_$timestamp.txt"
$script:SectionResults = New-Object System.Collections.ArrayList
$script:StartedAt = Get-Date

function W {
    param([string]$Text = '')
    Add-Content -LiteralPath $Output -Value $Text -Encoding UTF8
}
function Section {
    param([string]$Title)
    W ''; W ('=' * 100); W $Title; W ('=' * 100)
}
function Run-Block {
    param([string]$Title,[scriptblock]$Script)
    W ''; W ('-' * 100); W $Title; W ('-' * 100)
    $started = Get-Date
    try {
        $result = & $Script 2>&1 | Out-String -Width 8192
        if ([string]::IsNullOrWhiteSpace($result)) { W '[no data returned]' } else { W $result.TrimEnd() }
        [void]$script:SectionResults.Add([pscustomobject]@{Title=$Title;Status='OK';Seconds=[math]::Round(((Get-Date)-$started).TotalSeconds,2);Error=''})
    } catch {
        W "ERROR: $($_.Exception.Message)"
        [void]$script:SectionResults.Add([pscustomobject]@{Title=$Title;Status='ERROR';Seconds=[math]::Round(((Get-Date)-$started).TotalSeconds,2);Error=$_.Exception.Message})
    }
}
function Get-AdminStatus {
    try {
        $current=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=New-Object Security.Principal.WindowsPrincipal($current)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}
function Convert-Bytes {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes/1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes/1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes/1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes/1KB)) }
    return ('{0:N0} B' -f $Bytes)
}
function Command-Exists { param([string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

'=' * 100 | Out-File -LiteralPath $Output -Encoding UTF8
W 'FULL WINDOWS SYSTEM REPORT'
W "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
W "Computer: $env:COMPUTERNAME"
W "User: $env:USERDOMAIN\$env:USERNAME"
W "PowerShell: $($PSVersionTable.PSVersion)"
W "Administrator: $(Get-AdminStatus)"
W "Output: $Output"
W ('=' * 100)

Write-Host '[1/14] General information...'
Section 'GENERAL'
Run-Block 'Basic identity' {
    [pscustomobject]@{
        ComputerName=$env:COMPUTERNAME;UserName="$env:USERDOMAIN\$env:USERNAME";PSVersion=$PSVersionTable.PSVersion.ToString()
        PSEdition=$PSVersionTable.PSEdition;Is64BitOS=[Environment]::Is64BitOperatingSystem;Is64BitProcess=[Environment]::Is64BitProcess
        MachineName=[Environment]::MachineName;Domain=$env:USERDOMAIN;Administrator=Get-AdminStatus;CurrentDirectory=(Get-Location).Path
    } | Format-List
}
Run-Block 'Computer information summary' {
    Get-ComputerInfo | Select-Object CsName,CsManufacturer,CsModel,CsSystemType,CsProcessors,CsTotalPhysicalMemory,
        BiosBIOSVersion,BiosManufacturer,BiosSerialNumber,BiosReleaseDate,WindowsProductName,WindowsEditionId,
        WindowsVersion,WindowsBuildLabEx,OsName,OsVersion,OsBuildNumber,OsArchitecture,OsLocale,OsLanguage,
        TimeZone,CsDomain,CsWorkgroup,WindowsInstallDateFromRegistry,OsInstallDate,OsLastBootUpTime,
        OsUptime,HyperVisorPresent,DeviceGuardSmartStatus | Format-List
}
Run-Block 'Operating system (CIM)' {
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,SerialNumber,
        ProductType,SuiteMask,LastBootUpTime,InstallDate,LocalDateTime,Locale,CurrentTimeZone,
        TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory | Format-List
}
Run-Block 'Computer system (CIM)' {
    Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,SystemFamily,SystemSKUNumber,SystemType,
        TotalPhysicalMemory,Domain,DomainRole,PartOfDomain,Workgroup,UserName,NumberOfProcessors,
        NumberOfLogicalProcessors,HypervisorPresent,ThermalState | Format-List
}
Run-Block 'Uptime and current time' {
    $os=Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{CurrentTime=Get-Date;LastBoot=$os.LastBootUpTime;Uptime=(Get-Date)-$os.LastBootUpTime;TimeZone=(Get-TimeZone).DisplayName;NtpStatus=(w32tm /query /status 2>&1 | Out-String).Trim()} | Format-List
}
Run-Block 'Regional and language settings' {
    Get-Culture | Format-List *
    Get-WinSystemLocale | Format-List
    Get-WinUserLanguageList | Format-Table -AutoSize
}
if ($IncludeEnvironment) {
    Run-Block 'Environment variables' { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize }
}

Write-Host '[2/14] Hardware and firmware...'
Section 'HARDWARE AND FIRMWARE'
Run-Block 'BIOS (CIM)' { Get-CimInstance Win32_BIOS | Select-Object Manufacturer,Name,SMBIOSBIOSVersion,Version,SerialNumber,ReleaseDate,SMBIOSMajorVersion,SMBIOSMinorVersion | Format-List }
Run-Block 'Baseboard and chassis' {
    Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,SerialNumber | Format-List
    Get-CimInstance Win32_SystemEnclosure | Select-Object Manufacturer,ChassisTypes,SerialNumber,SMBIOSAssetTag,SecurityStatus | Format-List
}
Run-Block 'Processor' {
    Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,Description,ProcessorId,Architecture,
        NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,CurrentClockSpeed,L2CacheSize,L3CacheSize,
        VirtualizationFirmwareEnabled,VMMonitorModeExtensions,SecondLevelAddressTranslationExtensions,LoadPercentage | Format-Table -AutoSize
}
Run-Block 'Physical memory modules' {
    Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel,DeviceLocator,Manufacturer,
        @{N='Capacity';E={Convert-Bytes $_.Capacity}},Speed,ConfiguredClockSpeed,MemoryType,SMBIOSMemoryType,
        FormFactor,PartNumber,SerialNumber | Format-Table -AutoSize
}
Run-Block 'Memory array and usage' {
    Get-CimInstance Win32_PhysicalMemoryArray | Select-Object MemoryDevices,@{N='MaxCapacity';E={Convert-Bytes ($_.MaxCapacity*1KB)}},Use,Location | Format-List
    $os=Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{Total=Convert-Bytes($os.TotalVisibleMemorySize*1KB);Free=Convert-Bytes($os.FreePhysicalMemory*1KB);Used=Convert-Bytes(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)*1KB);UsagePercent=[math]::Round((($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize)*100,2)} | Format-List
}
Run-Block 'Graphics adapters and monitors' {
    Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,DriverVersion,DriverDate,VideoProcessor,@{N='AdapterRAM';E={Convert-Bytes $_.AdapterRAM}},CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate | Format-Table -AutoSize
    Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID | ForEach-Object {
        [pscustomobject]@{InstanceName=$_.InstanceName;Manufacturer=([Text.Encoding]::ASCII.GetString($_.ManufacturerName|Where-Object{$_-ne 0}));ProductCode=([Text.Encoding]::ASCII.GetString($_.ProductCodeID|Where-Object{$_-ne 0}));Serial=([Text.Encoding]::ASCII.GetString($_.SerialNumberID|Where-Object{$_-ne 0}));FriendlyName=([Text.Encoding]::ASCII.GetString($_.UserFriendlyName|Where-Object{$_-ne 0}))}
    } | Format-Table -AutoSize
}
Run-Block 'Audio devices' { Get-CimInstance Win32_SoundDevice | Select-Object Name,Manufacturer,ProductName,Status,PNPDeviceID | Format-Table -AutoSize }
Run-Block 'Battery and power status' {
    Get-CimInstance Win32_Battery | Select-Object Name,Status,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,DesignCapacity,FullChargeCapacity | Format-List
    powercfg /getactivescheme
    powercfg /a
}
Run-Block 'USB controllers and connected devices' {
    Get-CimInstance Win32_USBController | Select-Object Name,Manufacturer,Status,DeviceID | Format-Table -AutoSize
    Get-PnpDevice -PresentOnly | Where-Object {$_.Class -in @('USB','HIDClass','Ports','Bluetooth','Camera')} | Select-Object Class,FriendlyName,Status,InstanceId | Sort-Object Class,FriendlyName | Format-Table -AutoSize
}
Run-Block "PnP signed drivers (top $DriverLimit)" {
    Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName,DeviceClass,Manufacturer,DriverVersion,DriverProviderName,DriverDate,InfName,IsSigned,Signer | Sort-Object DeviceName | Select-Object -First $DriverLimit | Format-Table -AutoSize
}
Run-Block 'PnP devices with errors' {
    Get-PnpDevice | Where-Object {$_.Status -ne 'OK' -or $_.Problem -ne 0} | Select-Object Class,FriendlyName,Status,Problem,InstanceId | Sort-Object Class,FriendlyName | Format-Table -AutoSize
}

Write-Host '[3/14] Storage...'
Section 'STORAGE'
Run-Block 'Logical disks' {
    Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,DriveType,VolumeName,FileSystem,
        @{N='Size';E={Convert-Bytes $_.Size}},@{N='Free';E={Convert-Bytes $_.FreeSpace}},
        @{N='UsedPercent';E={if($_.Size){[math]::Round((($_.Size-$_.FreeSpace)/$_.Size)*100,2)}}},ProviderName | Format-Table -AutoSize
}
Run-Block 'Disk drives' { Get-CimInstance Win32_DiskDrive | Select-Object Index,Model,Manufacturer,FirmwareRevision,InterfaceType,MediaType,@{N='Size';E={Convert-Bytes $_.Size}},Partitions,SerialNumber,Status,PNPDeviceID | Format-Table -AutoSize }
Run-Block 'Physical disks and reliability' {
    if(Command-Exists 'Get-PhysicalDisk'){
        Get-PhysicalDisk | Select-Object FriendlyName,SerialNumber,MediaType,BusType,HealthStatus,OperationalStatus,@{N='Size';E={Convert-Bytes $_.Size}},FirmwareVersion | Format-Table -AutoSize
        Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object DeviceId,Temperature,Wear,PowerOnHours,ReadErrorsTotal,WriteErrorsTotal,ReadLatencyMax,WriteLatencyMax | Format-Table -AutoSize
    }
}
Run-Block 'Partitions and volumes' {
    Get-Partition | Select-Object DiskNumber,PartitionNumber,DriveLetter,Type,GptType,@{N='Size';E={Convert-Bytes $_.Size}},IsActive,IsBoot,IsSystem | Format-Table -AutoSize
    Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,DriveType,HealthStatus,OperationalStatus,@{N='Size';E={Convert-Bytes $_.Size}},@{N='Remaining';E={Convert-Bytes $_.SizeRemaining}} | Format-Table -AutoSize
}
Run-Block 'BitLocker volumes' { if(Command-Exists 'Get-BitLockerVolume'){Get-BitLockerVolume | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionMethod,EncryptionPercentage,AutoUnlockEnabled | Format-Table -AutoSize}else{manage-bde -status} }
Run-Block 'Shadow copies' { Get-CimInstance Win32_ShadowCopy | Select-Object ID,VolumeName,InstallDate,DeviceObject,State,Persistent,ClientAccessible | Format-Table -AutoSize }
Run-Block 'File system checks and TRIM' { fsutil behavior query DisableDeleteNotify; fsutil dirty query C: }

Write-Host '[4/14] Network...'
Section 'NETWORK'
Run-Block 'Network profiles' { Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,InterfaceIndex,NetworkCategory,IPv4Connectivity,IPv6Connectivity | Format-Table -AutoSize }
Run-Block 'Network adapters' { Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress,MediaType,PhysicalMediaType,DriverInformation,ifIndex,Hidden | Sort-Object Name | Format-Table -AutoSize }
Run-Block 'Network adapter advanced properties' { Get-NetAdapterAdvancedProperty | Select-Object Name,DisplayName,DisplayValue,RegistryKeyword,RegistryValue | Sort-Object Name,DisplayName | Format-Table -AutoSize }
Run-Block 'Network adapter statistics' { Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes,ReceivedUnicastPackets,SentUnicastPackets,ReceivedDiscardedPackets,OutboundDiscardedPackets,ReceivedPacketErrors,OutboundPacketErrors | Format-Table -AutoSize }
Run-Block 'IP configuration by interface' { Get-NetIPConfiguration -Detailed | Select-Object InterfaceAlias,InterfaceDescription,InterfaceIndex,NetProfile,IPv4Address,IPv6Address,IPv4DefaultGateway,IPv6DefaultGateway,DNSServer,NetAdapter | Format-List }
Run-Block 'Net IP addresses' { Get-NetIPAddress | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,IPAddress,PrefixLength,Type,PrefixOrigin,SuffixOrigin,AddressState,SkipAsSource,ValidLifetime,PreferredLifetime | Sort-Object InterfaceAlias,AddressFamily,IPAddress | Format-Table -AutoSize }
Run-Block 'Routes' { Get-NetRoute | Select-Object ifIndex,InterfaceAlias,AddressFamily,DestinationPrefix,NextHop,RouteMetric,InterfaceMetric,Protocol,State,Publish | Sort-Object AddressFamily,InterfaceAlias,DestinationPrefix | Format-Table -AutoSize }
Run-Block 'DNS client servers and suffixes' { Get-DnsClientServerAddress | Format-Table -AutoSize; Get-DnsClient | Select-Object InterfaceAlias,ConnectionSpecificSuffix,RegisterThisConnectionsAddress,UseSuffixWhenRegistering | Format-Table -AutoSize }
Run-Block 'DNS client cache' { Get-DnsClientCache | Select-Object Entry,Name,Data,Type,Status,TimeToLive | Select-Object -First 500 | Format-Table -AutoSize }
Run-Block 'Neighbor table' { Get-NetNeighbor | Select-Object InterfaceAlias,AddressFamily,IPAddress,LinkLayerAddress,State,PolicyStore | Sort-Object InterfaceAlias,IPAddress | Format-Table -AutoSize }
Run-Block 'IP interface configuration' { Get-NetIPInterface | Select-Object InterfaceAlias,AddressFamily,ConnectionState,Dhcp,AutomaticMetric,InterfaceMetric,WeakHostSend,WeakHostReceive,Forwarding,NlMtu | Format-Table -AutoSize }
Run-Block 'Wi-Fi interfaces and profiles' { netsh wlan show interfaces; netsh wlan show drivers; netsh wlan show profiles }
Run-Block 'Proxy configuration' { netsh winhttp show proxy; Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL,AutoDetect | Format-List }
Run-Block 'IPCONFIG /ALL' { ipconfig /all }
Run-Block 'ARP table' { arp -a }
Run-Block 'Route print' { route print }
Run-Block 'Hosts file' { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }

Write-Host '[5/14] Ports and connections...'
Section 'PORTS AND CONNECTIONS'
Run-Block 'Listening TCP ports with process names' {
    $processMap=@{};Get-Process|ForEach-Object{$processMap[$_.Id]=$_.ProcessName}
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{N='ProcessName';E={$processMap[[int]$_.OwningProcess]}},AppliedSetting | Sort-Object LocalPort | Format-Table -AutoSize
}
Run-Block 'UDP endpoints with process names' {
    $processMap=@{};Get-Process|ForEach-Object{$processMap[$_.Id]=$_.ProcessName}
    Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,@{N='ProcessName';E={$processMap[[int]$_.OwningProcess]}} | Sort-Object LocalPort | Format-Table -AutoSize
}
Run-Block "Established TCP connections (top $ConnectionLimit)" {
    $processMap=@{};Get-Process|ForEach-Object{$processMap[$_.Id]=$_.ProcessName}
    Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N='ProcessName';E={$processMap[[int]$_.OwningProcess]}} | Select-Object -First $ConnectionLimit | Format-Table -AutoSize
}
Run-Block 'TCP state summary' { Get-NetTCPConnection | Group-Object State | Sort-Object Count -Descending | Select-Object Name,Count | Format-Table -AutoSize }
Run-Block 'NETSTAT -ANO' { netstat -ano }

Write-Host '[6/14] Software...'
Section 'SOFTWARE'
Run-Block 'Installed software (registry)' {
    $paths=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
    Get-ItemProperty $paths | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,InstallSource,UninstallString,QuietUninstallString,PSPath | Sort-Object DisplayName,DisplayVersion -Unique | Format-Table -AutoSize
}
Run-Block 'Microsoft Store packages' { Get-AppxPackage -AllUsers | Select-Object Name,PackageFullName,Version,Publisher,Architecture,InstallLocation,Status | Sort-Object Name | Format-Table -AutoSize }
Run-Block 'Provisioned Windows packages' { Get-AppxProvisionedPackage -Online | Select-Object DisplayName,Version,PackageName,InstallLocation | Sort-Object DisplayName | Format-Table -AutoSize }
Run-Block 'Optional features' { Get-WindowsOptionalFeature -Online | Select-Object FeatureName,State | Sort-Object State,FeatureName | Format-Table -AutoSize }
Run-Block 'Windows capabilities' { Get-WindowsCapability -Online | Select-Object Name,State,DisplayName,Description | Sort-Object State,Name | Format-Table -AutoSize }
Run-Block 'PowerShell modules' { Get-Module -ListAvailable | Select-Object Name,Version,ModuleBase,CompatiblePSEditions | Sort-Object Name,Version -Unique | Format-Table -AutoSize }
Run-Block 'Development runtimes and command versions' {
    foreach($cmd in @('powershell','pwsh','python','py','pip','git','java','javac','node','npm','dotnet','docker','wsl','winget')){
        $c=Get-Command $cmd -ErrorAction SilentlyContinue
        if($c){[pscustomobject]@{Command=$cmd;Path=$c.Source;Version=try{& $cmd --version 2>&1|Select-Object -First 1}catch{''}}}
    } | Format-Table -AutoSize
}
Run-Block 'Windows editions and licensing' { cscript.exe //Nologo "$env:SystemRoot\System32\slmgr.vbs" /dli; cscript.exe //Nologo "$env:SystemRoot\System32\slmgr.vbs" /xpr }

Write-Host '[7/14] Processes and services...'
Section 'PROCESSES AND SERVICES'
Run-Block 'Processes by name' { Get-Process | Select-Object Id,ProcessName,Path,Company,Product,FileVersion,@{N='CPU_s';E={$_.CPU}},@{N='RAM_MB';E={[math]::Round($_.WorkingSet64/1MB,2)}},@{N='Private_MB';E={[math]::Round($_.PrivateMemorySize64/1MB,2)}},Handles,Threads,StartTime | Sort-Object ProcessName,Id | Format-Table -AutoSize }
Run-Block 'Processes with command lines and owners' {
    Get-CimInstance Win32_Process | ForEach-Object { $owner=$_.GetOwner();[pscustomobject]@{PID=$_.ProcessId;ParentPID=$_.ParentProcessId;Name=$_.Name;Owner=if($owner.ReturnValue-eq 0){"$($owner.Domain)\$($owner.User)"};ExecutablePath=$_.ExecutablePath;CommandLine=$_.CommandLine;CreationDate=$_.CreationDate} } | Sort-Object Name,PID | Format-List
}
Run-Block 'Top 50 processes by memory' { Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 50 Id,ProcessName,@{N='RAM_MB';E={[math]::Round($_.WorkingSet64/1MB,2)}},@{N='Private_MB';E={[math]::Round($_.PrivateMemorySize64/1MB,2)}},CPU,StartTime,Path | Format-Table -AutoSize }
Run-Block 'Top 50 processes by CPU time' { Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 Id,ProcessName,CPU,@{N='RAM_MB';E={[math]::Round($_.WorkingSet64/1MB,2)}},StartTime,Path | Format-Table -AutoSize }
Run-Block 'Services' { Get-CimInstance Win32_Service | Select-Object State,StartMode,Name,DisplayName,StartName,ProcessId,PathName,Description,ExitCode | Sort-Object State,Name | Format-Table -AutoSize }
Run-Block 'Service failures and recovery configuration' { Get-CimInstance Win32_Service | Where-Object {$_.State-ne'Running' -and $_.StartMode-eq'Auto'} | Select-Object Name,DisplayName,State,Status,StartMode,StartName,ExitCode,PathName | Format-Table -AutoSize }

Write-Host '[8/14] Security...'
Section 'SECURITY'
Run-Block 'Remote access tools detection' { $patterns='vnc|teamviewer|anydesk|rustdesk|mstsc|screenconnect|connectwise|logmein|bomgar|beyondtrust|splashtop|ammyy|radmin|dameware';Get-Process | Where-Object {$_.ProcessName-match$patterns} | Select-Object ProcessName,Id,Path,MainWindowTitle | Format-Table -AutoSize }
if(-not $SkipDefender){
    Run-Block 'Windows Defender status' { Get-MpComputerStatus | Format-List * }
    Run-Block 'Windows Defender preferences' { Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,PUAProtection,EnableNetworkProtection,MAPSReporting,SubmitSamplesConsent,ExclusionPath,ExclusionProcess,ExclusionExtension,AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions | Format-List }
    Run-Block 'Windows Defender detections' { Get-MpThreatDetection | Select-Object InitialDetectionTime,LastThreatStatusChangeTime,ThreatID,ThreatStatusID,ActionSuccess,Resources | Sort-Object InitialDetectionTime -Descending | Format-List }
}
Run-Block 'Firewall profiles' { Get-NetFirewallProfile | Format-List *; netsh advfirewall show allprofiles }
Run-Block 'Enabled firewall rules summary' { Get-NetFirewallRule -Enabled True | Group-Object Direction,Action | Select-Object Name,Count | Format-Table -AutoSize }
Run-Block 'Security products (SecurityCenter2)' { Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState,pathToSignedProductExe,pathToSignedReportingExe,timestamp | Format-Table -AutoSize }
Run-Block 'Secure Boot, TPM, Device Guard and Credential Guard' {
    try{[pscustomobject]@{SecureBoot=Confirm-SecureBootUEFI}|Format-List}catch{"Secure Boot: $($_.Exception.Message)"}
    if(Command-Exists 'Get-Tpm'){Get-Tpm|Format-List *}
    Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | Format-List *
}
Run-Block 'BitLocker status' { if(Command-Exists 'Get-BitLockerVolume'){Get-BitLockerVolume|Format-List *}else{manage-bde -status} }
Run-Block 'UAC configuration' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,ConsentPromptBehaviorUser,PromptOnSecureDesktop,FilterAdministratorToken,LocalAccountTokenFilterPolicy | Format-List }
Run-Block 'Audit policy' { auditpol /get /category:* }
Run-Block 'Local security policy summary' { secedit /export /cfg "$env:TEMP\FullReport-SecurityPolicy-$timestamp.inf" /quiet; Get-Content "$env:TEMP\FullReport-SecurityPolicy-$timestamp.inf"; Remove-Item "$env:TEMP\FullReport-SecurityPolicy-$timestamp.inf" -Force }
Run-Block 'Local users' { Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordExpires,UserMayChangePassword,PasswordLastSet,AccountExpires,SID,PrincipalSource,Description | Format-Table -AutoSize }
Run-Block 'Local group memberships' { Get-LocalGroup | ForEach-Object {$g=$_.Name;try{Get-LocalGroupMember -Group $g | Select-Object @{N='Group';E={$g}},Name,ObjectClass,PrincipalSource,SID}catch{}} | Format-Table -AutoSize }
Run-Block 'Certificates expiring within 90 days' { Get-ChildItem Cert:\LocalMachine\My,Cert:\CurrentUser\My | Where-Object {$_.NotAfter-lt(Get-Date).AddDays(90)} | Select-Object Subject,Issuer,Thumbprint,NotBefore,NotAfter,HasPrivateKey,PSParentPath | Sort-Object NotAfter | Format-Table -AutoSize }
Run-Block 'SMB security configuration' { Get-SmbServerConfiguration | Format-List *; Get-SmbClientConfiguration | Format-List * }
Run-Block 'RDP and WinRM configuration' { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' | Select-Object fDenyTSConnections | Format-List; Get-Service TermService,WinRM | Format-Table -AutoSize; winrm get winrm/config 2>&1 }
Run-Block 'Group Policy result' { gpresult /R /SCOPE COMPUTER; gpresult /R /SCOPE USER }

Write-Host '[9/14] Accounts, sessions and shares...'
Section 'ACCOUNTS, SESSIONS AND SHARES'
if(-not $SkipUserData){
    Run-Block 'Logged-on users and sessions' { quser 2>&1; Get-CimInstance Win32_LoggedOnUser | Select-Object Antecedent,Dependent | Format-Table -AutoSize }
    Run-Block 'User profiles' { Get-CimInstance Win32_UserProfile | Select-Object LocalPath,SID,Loaded,Special,RoamingConfigured,LastUseTime,Status | Sort-Object LocalPath | Format-Table -AutoSize }
}
Run-Block 'Shares (CIM and SMB)' { Get-CimInstance Win32_Share | Select-Object Name,Path,Description,Type,Status | Format-Table -AutoSize; Get-SmbShare | Select-Object Name,Path,Description,FolderEnumerationMode,EncryptData,CurrentUsers,Special | Format-Table -AutoSize }
Run-Block 'SMB sessions and open files' { Get-SmbSession | Format-Table -AutoSize; Get-SmbOpenFile | Format-Table -AutoSize }
Run-Block 'Mapped drives' { Get-CimInstance Win32_MappedLogicalDisk | Select-Object DeviceID,ProviderName,VolumeName,SessionID | Format-Table -AutoSize; net use }
Run-Block 'Printers' { Get-Printer | Select-Object Name,DriverName,PortName,Type,Shared,ShareName,Published,PrinterStatus,WorkOffline | Format-Table -AutoSize }

Write-Host '[10/14] Startup and tasks...'
Section 'STARTUP AND TASKS'
Run-Block 'Startup commands (registry and CIM)' {
    $startupPaths=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce')
    foreach($p in $startupPaths){if(Test-Path $p){"### $p ###";Get-ItemProperty -Path $p|Format-List}}
    Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User,UserSID | Format-Table -AutoSize
}
Run-Block 'Startup folders' { foreach($p in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")){"### $p ###";Get-ChildItem -LiteralPath $p -Force | Select-Object Name,FullName,Length,CreationTime,LastWriteTime} }
Run-Block 'Scheduled tasks with actions and triggers' { Get-ScheduledTask | ForEach-Object {[pscustomobject]@{TaskPath=$_.TaskPath;TaskName=$_.TaskName;State=$_.State;Author=$_.Author;Description=$_.Description;Actions=($_.Actions|ForEach-Object{"$($_.Execute) $($_.Arguments)"})-join'; ';Triggers=($_.Triggers|Out-String).Trim()}} | Sort-Object TaskPath,TaskName | Format-List }

Write-Host '[11/14] Updates and components...'
Section 'UPDATES AND COMPONENTS'
Run-Block 'Hotfixes' { Get-HotFix | Select-Object HotFixID,Description,InstalledBy,InstalledOn,Caption | Sort-Object InstalledOn -Descending | Format-Table -AutoSize }
Run-Block 'Windows Update history' { if(Command-Exists 'Get-WindowsUpdateLog'){Get-WindowsUpdateLog -LogPath "$env:TEMP\WindowsUpdate-$timestamp.log"|Out-Null};$session=New-Object -ComObject Microsoft.Update.Session;$searcher=$session.CreateUpdateSearcher();$count=$searcher.GetTotalHistoryCount();$searcher.QueryHistory(0,[Math]::Min($count,200)) | Select-Object Date,Title,Description,Operation,ResultCode,HResult | Format-Table -AutoSize }
Run-Block 'DISM package inventory' { dism.exe /Online /Get-Packages /Format:Table }
Run-Block 'Component store analysis' { dism.exe /Online /Cleanup-Image /AnalyzeComponentStore }
Run-Block 'Pending reboot indicators' {
    $checks=[ordered]@{
        CBSRebootPending=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        WURebootRequired=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        PendingFileRenameOperations=[bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
        SCCMClientReboot=try{([wmiclass]'ROOT\ccm\ClientSDK:CCM_ClientUtilities').DetermineIfRebootPending().RebootPending}catch{$null}
    };[pscustomobject]$checks|Format-List
}
Run-Block 'Windows Update services' { Get-Service wuauserv,bits,cryptsvc,usosvc,waasmedicsvc -ErrorAction SilentlyContinue | Format-Table -AutoSize }

Write-Host '[12/14] Policies and virtualization...'
Section 'POLICIES AND VIRTUALIZATION'
Run-Block 'Virtualization and Hyper-V' { systeminfo | Select-String 'Hyper-V Requirements','Virtualization'; Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All,VirtualMachinePlatform,Microsoft-Windows-Subsystem-Linux,Containers -ErrorAction SilentlyContinue | Format-Table -AutoSize; Get-Service vmcompute,hns,LxssManager -ErrorAction SilentlyContinue | Format-Table -AutoSize }
Run-Block 'WSL status and distributions' { if(Command-Exists 'wsl'){wsl --status 2>&1;wsl --version 2>&1;wsl --list --verbose 2>&1} }
Run-Block 'Docker status' { if(Command-Exists 'docker'){docker version 2>&1;docker info 2>&1;docker ps -a 2>&1} }
Run-Block 'Windows Sandbox and containers' { Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM,Containers -ErrorAction SilentlyContinue | Format-Table -AutoSize }
Run-Block 'PowerShell execution policies' { Get-ExecutionPolicy -List | Format-Table -AutoSize }
Run-Block 'PowerShell logging policy' { Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue | Format-List; Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue | Format-List; Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue | Format-List }

Write-Host '[13/14] Recent events and diagnostics...'
Section 'RECENT EVENTS AND DIAGNOSTICS'
if(-not $SkipEventLogs){
    Run-Block "System event log (last $EventCount)" { Get-WinEvent -LogName System -MaxEvents $EventCount | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,MachineName,Message | Format-List }
    Run-Block "Application event log (last $EventCount)" { Get-WinEvent -LogName Application -MaxEvents $EventCount | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,MachineName,Message | Format-List }
    Run-Block "System errors and critical events (last 7 days, top $EventCount)" { Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2;StartTime=(Get-Date).AddDays(-7)} -MaxEvents $EventCount | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List }
    Run-Block "Application errors and critical events (last 7 days, top $EventCount)" { Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2;StartTime=(Get-Date).AddDays(-7)} -MaxEvents $EventCount | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List }
    Run-Block 'Unexpected shutdown and bugcheck events' { Get-WinEvent -FilterHashtable @{LogName='System';Id=41,1001,6008} -MaxEvents 50 | Select-Object TimeCreated,Id,ProviderName,Message | Format-List }
}
Run-Block 'Reliability records (last 30 days)' { Get-CimInstance Win32_ReliabilityRecords | Where-Object {$_.TimeGenerated-ge(Get-Date).AddDays(-30)} | Select-Object TimeGenerated,SourceName,EventIdentifier,ProductName,RecordNumber,Message | Sort-Object TimeGenerated -Descending | Select-Object -First 300 | Format-List }
Run-Block 'Last boot performance events' { Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational';Id=100..199} -MaxEvents 50 | Select-Object TimeCreated,Id,LevelDisplayName,Message | Format-List }
Run-Block 'System integrity quick checks' { sfc /verifyonly; dism.exe /Online /Cleanup-Image /ScanHealth }

Write-Host '[14/14] Report summary...'
Section 'COLLECTION SUMMARY'
Run-Block 'Section execution summary' { $script:SectionResults | Sort-Object Status,Title | Format-Table -AutoSize }
Run-Block 'Report file information' {
    $file=Get-Item -LiteralPath $Output
    [pscustomobject]@{Path=$file.FullName;Size=Convert-Bytes $file.Length;Started=$script:StartedAt;Completed=Get-Date;Duration=(Get-Date)-$script:StartedAt;Blocks=$script:SectionResults.Count;Errors=@($script:SectionResults|Where-Object{$_.Status-eq'ERROR'}).Count;Administrator=Get-AdminStatus} | Format-List
}
Section 'END'
W "Report saved to: $Output"
W "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
Write-Host ''
Write-Host "Report generated: $Output" -ForegroundColor Green
if($OpenReport){Start-Process notepad.exe -ArgumentList ('"{0}"' -f $Output)}
