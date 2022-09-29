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

:: Set Security and PowerShell log maximum file size to 1 GB
:: Note: you should also increase the max. size of the Sysmon log to 1 GB if you use sysmon.
wevtutil sl Security /ms:1073741824
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:1073741824
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


:: Configure Security log 
:: Note: subcategory IDs are used instead of the names in order to work in any OS language.

:: Credential Validation
auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Other Account Logon Events
auditpol /set /subcategory:{0CCE9241-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Account Management
auditpol /set /category:{6997984E-797A-11D9-BED3-505054503030} /success:enable /failure:enable

:: Detailed Tracking
:::: Plug and Play
auditpol /set /subcategory:{0CCE9248-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
:::: Process Creation
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: RPC Events
auditpol /set /subcategory:{0CCE922E-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Audit Token Right Adjustments
auditpol /set /subcategory:{0CCE924A-69AE-11D9-BED3-505054503030} /success:enable /failure:disable

::  DS Access
::::Directory Service Changes
auditpol /set /subcategory:{0CCE923C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Logon/Logoff
:::: Account Lockout
auditpol /set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
:::: Group Membership
auditpol /set /subcategory:{0CCE9249-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
:::: Logoff
auditpol /set /subcategory:{0CCE9216-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
:::: Logon
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Network Policy Server
auditpol /set /subcategory:{0CCE9243-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Other Logon/Logoff Events
auditpol /set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Special Logon
auditpol /set /subcategory:{0CCE921B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Object Access
:::: Application Generated
auditpol /set /subcategory:{0CCE9222-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Certification Services
auditpol /set /subcategory:{0CCE9221-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Detailed File Share
auditpol /set /subcategory:{0CCE9244-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
:::: File Share
auditpol /set /subcategory:{0CCE9224-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: File System
auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
:::: Filtering Platform Connection
:::: Removable Storage
:::: Registry
:::: SAM
auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
auditpol /set /subcategory:{0CCE9245-69AE-11D9-BED3-505054503030} /success:enable /failure:enable


:: Policy Change
:::: Audit Policy Change
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Authentication Policy Change
auditpol /set /subcategory:{0CCE9230-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Authorization Policy Change
auditpol /set /subcategory:{0CCE9231-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Filtering Platform Policy Change
auditpol /set /subcategory:{0CCE9233-69AE-11D9-BED3-505054503030} /success:enable /failure:disable

:: Privilege Use
:::: Sensitive Privilege Use
auditpol /set /subcategory:{0CCE9228-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: System
:::: IPsec Driver
auditpol /set /subcategory:{0CCE9213-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
:::: Other System Events
auditpol /set /subcategory:{0CCE9214-69AE-11D9-BED3-505054503030} /success:disable /failure:enable
:::: Security State Change
auditpol /set /subcategory:{0CCE9210-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: Security System Extension
auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:::: System Integrity
auditpol /set /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030} /success:enable /failure:enable