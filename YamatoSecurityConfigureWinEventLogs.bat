:: Yamato Security's Configure Windows Event Logs Batch File
:: Author: Zach Mathis (@yamatosecurity), Sachiel Archangel
:: This script is based off the work of Sachiel Archangel's WinEventEnable.bat
:: https://github.com/Sachiel-archangel/WinEventEnable/blob/main/WinEventEnable.bat
::
:: Warning: Use this batch script as a template and understand what you are enabling!
:: You will need to customize this file to fit your environment.
:: Make sure you test this out thoroughly beforing using in production!!
::
:: You need to run this with local Administrator or SYSTEM privileges.

:: Increase or decrease the log sizes as you see fit (in bytes of 64kb blocks):
:: 2 GB: 2147483648
:: 1 GB: 1073741824
:: 512 MB: 536870912
:: 256 MB: 268435456
:: 128 MB: 134217728

:: Set Security and PowerShell-related logs' maximum file size to 1 GB
:: Note: you should also increase the max. size of the Sysmon log to 1 GB if you use Sysmon.
wevtutil sl Security /ms:1073741824
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:1073741824
wevtutil sl "Windows PowerShell" /ms:1073741824
wevtutil sl PowerShellCore/Operational /ms:1073741824
::wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824

:: Set all other important logs to 128 MB. Increase or decrease to fit your environment.
wevtutil sl System /ms:134217728
wevtutil sl Application /ms:134217728
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Bits-Client/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" /ms:134217728
wevtutil sl "Microsoft-Windows-NTLM/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Security-Mitigations/KernelMode" /ms:134217728
wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728
wevtutil sl "Microsoft-Windows-PrintService/Admin" /ms:134217728
wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728
wevtutil sl "Microsoft-Windows-PrintService/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-SmbClient/Security" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/MSI and Script" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Deployment" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Execution" /ms:134217728
wevtutil sl "Microsoft-Windows-CodeIntegrity/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Diagnosis-Scripted/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /ms:134217728

:: Enable any logs that need to be enabled
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true

:: Enable PowerShell Module logging
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /f /t REG_DWORD /d 1
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames  /f /v ^* /t REG_SZ /d ^*

:: Enable PowerShell Script Block logging
reg add HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /f /t REG_DWORD /d 1

::
:: Configure Security log 
:: Note: subcategory IDs are used instead of the names in order to work in any OS language.

:: Account Logon
:::: Credential Validation
auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Kerberos Authentication Service (disable for clients)
auditpol /set /subcategory:{0CCE9242-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Kerberos Service Ticket Operations (disable for clients)
auditpol /set /subcategory:{0CCE9240-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Account Management
:::: Computer Account Management
auditpol /set /subcategory:{0CCE9236-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Other Account Management Events
auditpol /set /subcategory:{0CCE923A-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Security Group Management
auditpol /set /subcategory:{0CCE9237-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: User Account Management
auditpol /set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Detailed Tracking
:::: Plug and Play
auditpol /set /subcategory:{0cce9248-69ae-11d9-bed3-505054503030} /success:enable /failure:enable
:::: Process Creation
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Enable command line auditing (Detailed Tracking)
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
:::: Process Termination (default: disabled)
:: auditpol /set /subcategory:{0CCE922C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: RPC Events
auditpol /set /subcategory:{0CCE922E-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Audit Token Right Adjustments (default: disabled)
:: auditpol /set /subcategory:{0CCE924A-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: DS Access
:::: Directory Service Access (disable for clients)
auditpol /set /subcategory:{0CCE923B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Directory Service Changes (disable for clients)
auditpol /set /subcategory:{0CCE923C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Logon/Logoff
:::: Account Lockout
auditpol /set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Group Membership (disabled due to noise)
:: auditpol /set /subcategory:{0CCE9249-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Logoff
auditpol /set /subcategory:{0CCE9216-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Logon
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Network Policy Server (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9243-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Other Logon/Logoff Events
auditpol /set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Special Logon
auditpol /set /subcategory:{0CCE921B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Object Access
:::: Application Generated (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9222-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Certification Services (disable for client OSes)
auditpol /set /subcategory:{0CCE9221-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Detailed File Share (disabled due to noise)
:: auditpol /set /subcategory:{0CCE9244-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: File Share (disable if too noisy)
auditpol /set /subcategory:{0CCE9224-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: File System (disabled due to noise)
:: auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Filtering Platform Connection (disable if too noisy)
auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Filtering Platform Packet Drop (disabled due to noise)
:: auditpol /set /subcategory:{0CCE9225-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Kernel Object (disabled due to noise)
:: auditpol /set /subcategory:{0CCE921F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Other Object Access Events
auditpol /set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Registry (currently disabled due to noise)
:: auditpol /set /subcategory:{0CCE921E-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Removable Storage
auditpol /set /subcategory:{0CCE9245-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: SAM
auditpol /set /subcategory:{0CCE9220-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Policy Change
:::: Audit Policy Change
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Authentication Policy Change
auditpol /set /subcategory:{0CCE9230-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Authorization Policy Change (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9231-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Filtering Platform Policy Change (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9233-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: MPSSVC Rule-Level Policy Change (currently disabled while testing)
:: auditpol /set /subcategory:{0CCE9232-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Other Policy Change Events
auditpol /set /subcategory:{0CCE9234-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Privilege Use
:::: Sensitive Privilege Use (disable if too noisy)
auditpol /set /subcategory:{0CCE9228-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: System
:::: Other System Events (needs testing)
auditpol /set /subcategory:{0CCE9214-69AE-11D9-BED3-505054503030} /success:disable /failure:enable
:::: Security State Change
auditpol /set /subcategory:{0CCE9210-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Security System Extension
auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: System Integrity
auditpol /set /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
