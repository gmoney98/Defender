

#This script is used to setup the default Defender Client settings on VDI. Please report any issues to gmaney@wcu.edu

#Core defender settings
$coreParams = @{
    DisableRealtimeMonitoring       = $false    #Turn off real-time protection; $false is enabled
    DisableBehaviorMonitoring       = $false    #Turn on behavior monitoring; $false is enabled
    DisableIOAVProtection           = $false    #Scan all downloaded files and attachments; $false is enabled
    DisableScriptScanning           = $false    #Allows or disallows Windows Defender Script Scanning functionality; $false is enabled
    DisableBlockAtFirstSeen         = $false    #Threat protection feature of next-generation protection that detects new malware and blocks it within seconds; $false is enabled
    RealTimeScanDirection           = 0         #This policy setting allows you to configure monitoring for incoming and outgoing files; 0 = Scan incoming and outgoing files
    PUAProtection                   = 1         #Enable or disable detection for potentially unwanted applications; 1 = Enabled(Block Mode)
}

#Cloud-delivered protection settings
$cloudParams = @{
    MAPSReporting                   = 2         #Type of membership in Microsoft Active Protection Service; 2 = Advanced membership
    SubmitSamplesConsent            = 1         #Specifies how Windows Defender checks for user consent for certain samples; 1 = Send Safe Samples Automatically
    CloudBlockLevel                 = 1         #Determines how aggressive Microsoft Defender Antivirus will be in blocking and scanning suspicious files; 1 = Moderate, delivers verdict only for high confidence detections
    CloudExtendedTimeout            = 20        #Specify the extended cloud check time in seconds; 10 seconds is the default, any defined number will be ADDED to the 10 seconds
}

#Network Protection Settings
$networkParams = @{
    EnableNetworkProtection             = 1         #Enable/Disable blocking malicious domains/IPs; 1 = Enabled(Block Mode)
    DisableHttpParsing                  = $false    #Specifies whether to disable inspection of HTTP traffic; $false = Enabled
    DisableTlsParsing                   = $false    #Specifies whether to disable inspection of tls traffic; $false = Enabled
    DisableDnsParsing                   = $false    #Specifies whether to disable inspection of dns traffic; $false = Enabled
    DisableDnsOverTcpParsing            = $false    #Specifies whether to disable inspection of dns traffic over tcp; $false = Enabled
    DisableFtpParsing                   = $false    #Specifies whether to disable inspection of ftp traffic; $false = Enabled
    DisableSmtpParsing                  = $false    #Specifies whether to disable inspection of smtp traffic; $false = Enabled
    DisableSshParsing                   = $false    #Specifies whether to disable inspection of ssh traffic; $false = Enabled
    DisableRdpParsing                   = $false    #Specifies whether to disable inspection of rdp traffic; $false = Enabled
    DisableInboundConnectionFiltering   = $false    #Specifies whether to inspect only outbound connections; $false = bi-directional
    EnableDnsSinkhole                   = $true     #pecifies whether to examine DNS traffic to detect and sinkhole DNS exfiltration attempts and other DNS based malicious attacks; $true = Enabled
}

#Scan Parameters
$scanParams = @{
    ScanParameters                                  = 1                         #Specifies the scan type to use during a scheduled scan; 1 = Quick Scan
    ScanScheduleDay                                 = 0                         #Specifies the day of the week to run scheduled scans; 0 = Everyday (Default)  #
    CheckForSignaturesBeforeRunningScan             = $true                     #Specifies whether to check for signature updates before running scan; $true = Enaled
    ScanOnlyIfIdleEnabled                           = $false                    #Specifies whether scheduled scans should only run when the computer is idle;
    DisableArchiveScanning                          = $false                    #Specifies whether to scan archive files, such as .zip and .cab files; $false = Enabled
    DisableEmailScanning                            = $false                    #Specifies whether to parse mail and mail files; $false = Enabled
    DisableRemovableDriveScanning                   = $true                     #Specifies whether to scan for malicious and unwanted software in removable drives, such as flash drives, during a FULL scan; $false = Enabled
    DisableScanningMappedNetworkDrivesForFullScan   = $false                    #Specifies whether to scan mapped network drives during full scan; $false = Enabled
    DisableScanningNetworkFiles                     = $false                    #Specifies whether to scan for network files; $false = Enabled
    ScanAvgCPULoadFactor                            = 50                        #Specifies the maximum percentage CPU usage for a scan, not a hard limit; 50 = default
    DisableCatchupFullScan                          = $false                    #Specifies whether to run catch-up scans for scheduled full scans; $false = Enabled
    DisableCatchupQuickScan                         = $false                    #Specifies whether to run catch-up scans for scheduled full scans; $false = Enabled
    EnableFullScanOnBatteryPower                    = $true                     #Specifies whether a full scan is done while on battery power; $true = Enabled
}

#Signature Update Settings
$sigParams = @{
    SignatureUpdateInterval                          = 6                                        #Specifies the interval, in hours, at which to check for definition updates; if undefined, default interval is used
    SignatureUpdateCatchupInterval                   = 1                                        #Specifies the number of days after which Windows Defender requires a catch-up definition update; 1 = default
    SignatureFallbackOrder                           = "MicrosoftUpdateServer|MMPC"             #Specifies the order in which to contact different definition update sources
    SignatureDisableUpdateOnStartupWithoutEngine     = $false                                   #Specifies whether to initiate definition updates even if no antimalware engine is present; $false = Enabled
    MeteredConnectionUpdates                         = $true                                    #Specifies whether to update managed devices to update through metered connections; $true = Enabled
    SharedSignaturesPath                             = "\\wcu.edu\mdatp$\data\wdav-update\"     #Specifies a shared folder path to use for signature updates in a domain environment; leave blank for default
}

#Threat Settings
$threatParams = @{
    SevereThreatDefaultAction           = 2             #Specifies which automatic remediation action to take for a severe level threat; 2 = Quarantine
    HighThreatDefaultAction             = 2             #Specifies which automatic remediation action to take for a high level threat; 2 = Quarantine
    ModerateThreatDefaultAction         = 2             #Specifies which automatic remediation action to take for a medium level threat; 2 = Quarantine
    LowThreatDefaultAction              = 2             #Specifies which automatic remediation action to take for a low level threat; 2 = Quarantine
    UnknownThreatDefaultAction          = 2             #Specifies which automatic remediation action to take for a unknown level threat; 2 = Quarantine
    QuarantinePurgeItemsAfterDelay      = 7             #Specifies the number of days to keep items in the Quarantine folder; default is infinite
    EnableFileHashComputation           = $true         #Specifies whether to computes hashes for files it scans; $true = Enabled
    DisableAutoExclusions               = $true         #Specifies whether to disable the Automatic Exclusions feature for the server; $true = Disabled
    OobeEnableRtpAndSigUpdate           = $true         #Specifies whether real-time protection and Security Intelligence Updates are enabled during Out of Box experience; $true = Enabled
}

#Attack Surface Reduction Rules - specify rules to off (0), block (1), audit (2), or warn (6); if not specified, rules will remain unchanged
$asrRules = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = 1 #Block abuse of exploited vulnerable signed drivers
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 1 #Block Adobe Reader from creating child processes
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 1 #Block all Office applications from creating child processes
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1 #Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 1 #Block executable content from email client and webmail
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = 1 #Block executable files from running unless they meet a prevalence, age, or trusted list criterion*
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 1 #Block execution of potentially obfuscated scripts
    "d3e037e1-3eb8-44c8-a917-57927947596d" = 1 #Block JavaScript or VBScript from launching downloaded executable content
    "3b576869-a4ec-4529-8536-b80a7769e899" = 1 #Block Office applications from creating executable content
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = 1 #Block Office applications from injecting code into other processes
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = 1 #Block Office communication application from creating child processes
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 1 #Block persistence through WMI event subscription
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = 1 #Block process creations originating from PSExec and WMI commands
    "33ddedf1-c6e0-47cb-833e-de6133960387" = 1 #Block rebooting machine in Safe Mode
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1 #Block untrusted and unsigned processes that run from USB
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = 1 #Block use of copied or impersonated system tools
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = 1 #Block Webshell creation for Servers
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 1 #Block Win32 API calls from Office macros
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = 1 #Use advanced protection against ransomware and other threats
}

#Controlled Folder Access settings - specify 0 for off, 1 for on, or 2 for audit mode
$cfaconfig = @{
    EnableControlledFolderAccess =  1 #Enable or disable Controlled Folder Access; 1 = Enabled(Block Mode)
    AllowedApplications = @(
        #"C:\Program Files\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe"

    ) #List of applications to allow through CFA; specify full path to executable
    CustomProtectedFolders = @(
        #C:\TestFolder

    ) #List of additional folders to protect with CFA; specify full path to folder
}

#Definitions - dont touch
$cloudblocklevelnames = @{ 0 = "Default (0)"; 1 = "Moderate (1)"; 2 = "High (2)"; 4 = "High+ (4)"; 6 = "ZeroTolerance (6)"}
$scandirectionlevels = @{ 0 = "Both (0)"; 1 = "Incoming (1)"; 2 = "Outgoing (2)"}
$puaprotectionlevels = @{ 0 = "Off (0)"; 1 = "Block Mode (1)"; 2 = "Audit Mode (2)"}
$sampleconsentlevels = @{ 0 = "Always prompt (0)"; 1 = "Send safe samples  (1)"; 2 = "Never send (2)"; 3 = "Send all samples (3)"}
$mapsreportinglevels = @{ 0 = "Disabled (0)"; 1 = "Basic  (1)"; 2 = "Advanced (2)"}
$netprotectionlevels = @{ 0 = "Off (0)"; 1 = "Block Mode (1)"; 2 = "Audit Mode (2)"}
$scanparameterlevels = @{ 1 = "Quick scan (1)"; 2 = "Full scan (2)"}
$scanday = @{ 0 = "Everyday (0)"; 1 = "Sunday (1)"; 2 = "Monday (2)"; 3 = "Tuesday (3)"; 4 = "Wednesday (4)"; 5 = "Thursday (5)"; 6 = "Friday (6)"; 7 = "Saturday (7)"; 8 = "Never (8)"}
$remediationactions = @{ 0 = "Apply based on Intelligence (0)"; 1 = "Clean (1)"; 2 = "Quarantine (2)"; 3 = "Remove (3)"; 6 = "Allow (6)";8 = "Used Defined (8)"; 9 = "No Action (9)"; 10 = "Block (10)"}
$asrmodes = @{ 0 = "Not Configured (0)"; 1 = "Block Mode (1)"; 2 = "Audit Mode (2)"; 6 = "Warn Mode (6)"}
$cfaNames = @{ 0 = "Disabled (0)"; 1 = "Block Mode (1)"; 2 = "Audit Mode (2)" }

#Attack Surface Reduction Rules
$asrIds = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion*"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
    "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools"
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware and other threats"
}




Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Windows Defender Setup Script v1.0" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# -------------------------------------------------------------------
# STEP 0: Tamper Protection Check
# -------------------------------------------------------------------
Write-Host "[0/9] Checking Tamper protection status" -ForegroundColor Green

$tamperprotection = Get-MpComputerStatus | Select-Object -Property IsTamperProtected
if ($tamperprotection.IsTamperProtected -eq $true) {
    Write-Host "Tamper protection is enabled, please disable before running this script"
    Exit
}

# -------------------------------------------------------------------
# STEP 1: Force-enable Windows Defender service
# -------------------------------------------------------------------
Write-Host "[1/9] Verifying Windows Defender service is running..." -ForegroundColor Green

$defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if ($defenderService) {
    if ($defenderService.Status -ne 'Running') {
        try {
            Start-Service -Name WinDefend -ErrorAction Stop
            Write-Host "  - WinDefend service started" -ForegroundColor White
        } catch {
            Write-Host "  - WARNING: Could not start WinDefend. Third-party AV may be installed." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  - WinDefend service is running" -ForegroundColor White
    }
} else {
    Write-Host "  - WARNING: WinDefend service not found" -ForegroundColor Yellow
}


# -------------------------------------------------------------------
# STEP 2: Set Core Defender Service Settings
# -------------------------------------------------------------------
Write-Host "[2/9] Setting Core Defender Service Settings..." -ForegroundColor Green

try {
    Set-MpPreference @coreParams
    Write-Host "  - Disable-Real-time protection: $($coreParams.DisableRealtimeMonitoring)" -ForegroundColor White
    Write-Host "  - Disable Behavior Monitoring: $($coreParams.DisableBehaviorMonitoring)" -ForegroundColor White
    Write-Host "  - Disable IOAV protection (downloads/attachments): $($coreParams.DisableIOAVProtection)" -ForegroundColor White
    Write-Host "  - Disable Script scanning (AMSI): $($coreParams.DisableScriptScanning)" -ForegroundColor White
    Write-Host "  - Disable Block at First Seen: $($coreParams.DisableBlockAtFirstSeen)" -ForegroundColor White
    Write-Host "  - RealTime Scan Direction: $($scandirectionlevels[$coreParams.RealTimeScanDirection])" -ForegroundColor White
    Write-Host "  - PUA Protection: $($puaprotectionlevels[$coreParams.PUAProtection])" -ForegroundColor White

} catch {
            Write-Host "  - ERROR setting core params: $($_.Exception.Message)" -ForegroundColor Red
        }


# -------------------------------------------------------------------
# STEP 3: Cloud-delivered protection
# -------------------------------------------------------------------
Write-Host "[3/9] Configuring cloud-delivered protection..." -ForegroundColor Green

try {
    Set-MpPreference @cloudParams
    Write-Host "  - MAPS Reporting: $($mapsreportinglevels[$cloudParams.MAPSReporting])" -ForegroundColor White
    Write-Host "  - Sample Submission: $($sampleconsentlevels[$cloudParams.SubmitSamplesConsent])" -ForegroundColor White
    Write-Host "  - Cloud Block Level: $($cloudblocklevelnames[$cloudParams.CloudBlockLevel])" -ForegroundColor White
    Write-Host "  - Cloud Extended Timeout: +$($cloudParams.CloudExtendedTimeout) seconds" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting cloud params: $($_.Exception.Message)" -ForegroundColor Red
}


# -------------------------------------------------------------------
# STEP 4: Network protection and traffic inspection
# -------------------------------------------------------------------
Write-Host "[4/9] Configuring network protection..." -ForegroundColor Green

try {
    Set-MpPreference @networkParams
    Write-Host "  - Network Protection: $($netprotectionlevels[$networkParams.EnableNetworkProtection])" -ForegroundColor White
    Write-Host "  - Disable HTTP inspection: $($networkParams.DisableHttpParsing)" -ForegroundColor White
    Write-Host "  - Disable TLS inspection: $($networkParams.DisableTlsParsing)" -ForegroundColor White
    Write-Host "  - Disable DNS inspection: $($networkParams.DisableDnsParsing)" -ForegroundColor White
    Write-Host "  - Disable DNS over TCP inspection: $($networkParams.DisableDnsOverTcpParsing)" -ForegroundColor White
    Write-Host "  - Disable FTP inspection: $($networkParams.DisableFtpParsing)" -ForegroundColor White
    Write-Host "  - Disable SMTP inspection: $($networkParams.DisableSmtpParsing)" -ForegroundColor White
    Write-Host "  - Disable SSH inspection: $($networkParams.DisableSshParsing)" -ForegroundColor White
    Write-Host "  - Disable RDP inspection: $($networkParams.DisableRdpParsing)" -ForegroundColor White
    Write-Host "  - Disable Inbound Connection Filtering: $($networkParams.DisableInboundConnectionFiltering)" -ForegroundColor White
    Write-Host "  - Enable DNS Sinkhole: $($networkParams.EnableDnsSinkhole)" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting network params: $($_.Exception.Message)" -ForegroundColor Red
}


# -------------------------------------------------------------------
# STEP 5: Scan configuration
# -------------------------------------------------------------------
Write-Host "[5/9] Configuring scan settings..." -ForegroundColor Green

try {
    Set-MpPreference @scanParams
    Write-Host "  - Scheduled scan type: $($scanparameterlevels[$scanParams.ScanParameters])" -ForegroundColor White
    Write-Host "  - Scan schedule day: $($scanday[$scanParams.ScanScheduleDay])" -ForegroundColor White
    Write-Host "  - Check for signature before scan: $($scanParams.CheckForSignaturesBeforeRunningScan)" -ForegroundColor White
    Write-Host "  - Scan only if idle: $($scanParams.ScanOnlyIfIdleEnabled)" -ForegroundColor White
    Write-Host "  - Disable archive scanning: $($scanParams.DisableArchiveScanning)" -ForegroundColor White
    Write-Host "  - Disable email scanning: $($scanParams.DisableEmailScanning)" -ForegroundColor White
    Write-Host "  - Disable removable drive scanning: $($scanParams.DisableRemovableDriveScanning)" -ForegroundColor White
    Write-Host "  - Disable mapped network drive scan during full: $($scanParams.DisableScanningMappedNetworkDrivesForFullScan)" -ForegroundColor White
    Write-Host "  - Disable network file scanning: $($scanParams.DisableScanningNetworkFiles)" -ForegroundColor White
    Write-Host "  - Scan avg CPU limit: $($scanParams.ScanAvgCPULoadFactor)%" -ForegroundColor White
    Write-Host "  - Disable catchup full scan: $($scanParams.DisableCatchupFullScan)" -ForegroundColor White
    Write-Host "  - Disable catchup quick scan: $($scanParams.DisableCatchupQuickScan)" -ForegroundColor White
    Write-Host "  - Enable full scan on battery power: $($scanParams.EnableFullScanOnBatteryPower)" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting scan params: $($_.Exception.Message)" -ForegroundColor Red
}


# -------------------------------------------------------------------
# STEP 6: Signature update settings
# -------------------------------------------------------------------
Write-Host "[6/9] Configuring signature update settings..." -ForegroundColor Green

try {
    Set-MpPreference @sigParams
    Write-Host "  - Signature Update Interval: $($sigParams.SignatureUpdateInterval) hours" -ForegroundColor White
    Write-Host "  - Signature Update Catchup Interval: $($sigParams.SignatureUpdateCatchupInterval) day(s)" -ForegroundColor White
    Write-Host "  - Signature Fallback Order: $($sigParams.SignatureFallbackOrder)" -ForegroundColor White
    Write-Host "  - Disable Update on Startup without Engine: $($sigParams.SignatureDisableUpdateOnStartupWithoutEngine)" -ForegroundColor White
    Write-Host "  - Allow updates over metered connections: $($sigParams.MeteredConnectionUpdates)" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting signature update params: $($_.Exception.Message)" -ForegroundColor Red
}


# -------------------------------------------------------------------
# STEP 7: Threat remediation settings
# -------------------------------------------------------------------
Write-Host "[7/9] Configuring threat remediation settings..." -ForegroundColor Green

try {
    Set-MpPreference @threatParams
    Write-Host "  - Severe Threat Default Action: $($remediationactions[$threatParams.SevereThreatDefaultAction])" -ForegroundColor White
    Write-Host "  - High Threat Default Action: $($remediationactions[$threatParams.HighThreatDefaultAction])" -ForegroundColor White
    Write-Host "  - Moderate Threat Default Action: $($remediationactions[$threatParams.ModerateThreatDefaultAction])" -ForegroundColor White
    Write-Host "  - Low Threat Default Action: $($remediationactions[$threatParams.LowThreatDefaultAction])" -ForegroundColor White
    Write-Host "  - Unknown Threat Default Action: $($remediationactions[$threatParams.UnknownThreatDefaultAction])" -ForegroundColor White
    Write-Host "  - Purge Quarantine items after: $($threatParams.QuarantinePurgeItemsAfterDelay) day(s)" -ForegroundColor White
    Write-Host "  - Enable file hash computation: $($threatParams.EnableFileHashComputation)" -ForegroundColor White
    Write-Host "  - Disable automatic exclusions: $($threatParams.DisableAutoExclusions)" -ForegroundColor White
    Write-Host "  - Enable RTP and SI updates during OOBE: $($threatParams.OobeEnableRtpAndSigUpdate)" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting threat params: $($_.Exception.Message)" -ForegroundColor Red
}


# -------------------------------------------------------------------
# STEP 8: Attack Surface Reduction (ASR) rules
# -------------------------------------------------------------------
Write-Host "[8/9] Configuring Attack Surface Reduction rules..." -ForegroundColor Green

try {
    Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRules.Keys -AttackSurfaceReductionRules_Actions $asrRules.Values
    foreach ($rule in $asrRules.GetEnumerator()) {
        Write-Host "  - $($asrIds[$($rule.Key)]): $($asrmodes[$($rule.Value)])" -ForegroundColor White
    }
} catch {
    Write-Host "  - ERROR setting ASR rules: $($_.Exception.Message)" -ForegroundColor Red
}


# -------------------------------------------------------------------
# STEP 9: Controlled Folder Access (ransomware protection)
# -------------------------------------------------------------------
Write-Host "[9/9] Configuring Controlled Folder Access..." -ForegroundColor Green

try {
if($cfaconfig.EnableControlledFolderAccess -eq 1) {
    Write-Host "  *NOTE: Legitimate apps may be blocked from writing to Documents, Pictures, etc.*" -ForegroundColor Yellow
    Set-MpPreference -EnableControlledFolderAccess $cfaconfig.EnableControlledFolderAccess
    write-Host "  - Enable Controlled Folder Access: $($cfaNames[$cfaconfig.EnableControlledFolderAccess])" -ForegroundColor White
        if ($cfaconfig.AllowedApplications.Count -gt 0) {
            foreach ($app in $cfaconfig.AllowedApplications) {
            Add-MpPreference -ControlledFolderAccessAllowedApplications $app
            Write-Host "  -- Allowed CFA Application: $app" -ForegroundColor White
    }}
        else {
        write-Host "  -- No allowed applications added for CFA" -ForegroundColor White
    }
        if ($cfaconfig.CustomProtectedFolders.Count -gt 0) {
            foreach ($folder in $cfaconfig.CustomProtectedFolders) {
            Add-MpPreference -ControlledFolderAccessProtectedFolders $folder
            Write-Host "  -- Custom Protected Folder: $folder" -ForegroundColor White
    }}
        else {
        write-Host "  -- No custom protected folders added for CFA" -ForegroundColor White
}
}
else {
    write-Host "  - Enable Controlled Folder Access: $($cfaNames[$cfaconfig.EnableControlledFolderAccess])" -ForegroundColor White
}
}
 catch {
    Write-Host "  - ERROR: $($_.Exception.Message)" -ForegroundColor Red
}
