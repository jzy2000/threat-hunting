# Various Ways of Remote Execution on Windows

*   PsExecSvc Remote Execution
    *   Search System Event ID 7045 (A new service was installed in the system) when PsExec service is installed
    *   Search registry _HKLM\System\CurrentControlSet\Services\PSEXESVC_ for new service creation.
    *   Search in ShimCache and AmCache for first time execution: _psexesvc.exe_
    *   Search Prefetch folder which records malicious binary and PsExec binary: _C:\Windows\Prefetch\evil.exe-{hash}.pf C:\Windows\Prefetch\psexesvc.exe-{hash}.pf_
    *   Search _psexesvc.exe_ as well as malicious executables (e.g. _evil.exe_) that are pushed by PsExec, placed in ADMIN$ folder by default.
    *   Search Security Event ID 5140 (A network share object was accessed) \
Check ‘Share Name’ field for windows shares _ADMIN$_ were used by PsExec
    *   Search Security Event ID 4648 (A logon was attempted using explicit credentials) for logon specifying alternate credentials in:
        *   Connecting User Name
        *   Process Name 
    *   Search Security Event ID 4624(An account was successfully logged on)
        *   Filter by “Logon Type”=3 or 2 if “-u” Alternate Credentials are used.
        *   Extract caller info stored in “Source IP/Logon User Name” field 
    *   Search Security Event ID 4672 for a user with administrative privileges
*   Remote Scheduler Tasks Creation
    *   Search Security Event ID:
        *   4698 – Scheduled task created
        *   4702 – Scheduled task updated
        *   4699 – Scheduled task deleted
        *   4700/4701 – Scheduled task enabled/disabled
    *   Search Windows-Task Scheduler Log Event ID:
        *    106 – Scheduled task created
        *    140 – Scheduled task updated
        *    141 – Scheduled task deleted
        *    200/201 – Scheduled task executed/completed
    *   Search registry _HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks_ (flat list by GUID)_HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree_ (tree view by task name) for new installed tasks
    *   Search in ShimCache and AmCache for first time malicious file execution.
    *   Search for Job files created in folder _C:\Windows\Tasks_
    *   Search for XML task files created in folder _C:\Windows\System32\Tasks_
        *   Extract Author tag under "RegistrationInfo" can identify: Source system name and Creator username
    *   Search Prefetch folder which records malicious task binary execution:_ \
C:\Windows\Prefetch\evil.exe-{hash}.pf_
    *   Search Security Event ID 4624(An account was successfully logged on)
        *   Filter by “Logon Type”=3
        *   Extract caller info stored in “Source IP/Logon User Name” field 
    *   Search Security Event ID 4672 (Special privileges assigned to new logon) for a user logon with administrative privileges
*   Remote Services Installation
    *   Search System Event ID:
        *   7034 – Service crashed unexpectedly 
        *   7035 – Service sent a Start/Stop control 
        *   7036 – Service started or stopped 
        *   7040 – Start type changed (Boot | On Request | Disabled) 
        *   7045 – A service was installed on the system
    *   Search registry _HKLM\System\CurrentControlSet\Services_ for new service creation.
    *   Search Prefetch folder which records malicious service binary execution: _C:\Windows\Prefetch\evil.exe-{hash}.pf_
    *   Search in ShimCache and AmCache for first time malicious service executable (unless service is implemented as a service DLL).
    *   Search Security Event ID 4697 (A service was installed in the system) for a new server installed.
    *   Search Security Event ID 4624 (An account was successfully logged on)
        *   Filter by “Logon Type”=3
        *   Extract caller info stored in “Source IP/Logon User Name” field 
*   WMI/WMIC Remote Execution
    *   WMI Activity Event ID 5857 \
Indicates time of _wmiprvse.exe_ execution and path to provider DLL, note attackers sometimes install malicious WMI provider DLLs
    *   WMI Activity Event ID 5860 (Registration of Temporary) and 5861 (Registration of Permanent) \
Typically used for persistence, but can indicate remote execution.
    *   Search in ShimCache and AmCache for first time execution: \
_scrcons.exe_, _mofcomp.exe_,_ wmiprvse.exe_, and malicious executable.
    *   Search Prefetch folder which records WMI remote execution: \
_C:\Windows\Prefetch\scrcons.exe-{hash}.pf  \
C:\Windows\Prefetch\mofcomp.exe-{hash}.pf  \
C:\Windows\Prefetch\wmiprvse.exe-{hash}.pf  \
C:\Windows\Prefetch\evil.exe-{hash}.pf_
    *   Search unauthorized changes in WMI Repository in _C:\Windows\ System32\wbem\Repository_ using [WMI Query](https://docs.microsoft.com/en-us/windows/desktop/wmisdk/querying-wmi).
    *   Search Security Event ID 4624(An account was successfully logged on)
        *   Filter by “Logon Type”=3
        *   Extract caller info stored in “Source IP/Logon User Name” field 
    *   Search Security Event ID 4672 (Special privileges assigned to new logon) for a user logon with administrative privileges
*   PowerShell Remote Execution
    *   Search PowerShell Event ID 400, 403 "ServerRemoteHost" indicates start/end of Remoting Powershell session
    *   Search PowerShell Event ID 4103, 4104 Script Block logging Logs scripts
    *   Search Prefetch folder which records malicious binary file and WinRM Remote Powershell session: _C:\Windows\Prefetch\evil.exe-{hash}.pf C:\Windows\Prefetch\wsmprovhost.exe-{hash}.pf_
    *   Search in ShimCache and AmCache for first time execution: \
_wsmprovhost.exe_ and malicious executable.
    *   Search Security Event ID 4624, filter by “Logon Type”=3, caller info stored in “Source IP/Logon User Name” field 
    *   Search Security Event ID 4672 for a user with administrative privileges

In the event of suspicious PowerShell execution, further search PowerShell cmdlets calls below(not a complete list) for execution:



*   Mimikatz, powercat, powersploit, PowershellEmpire, Payload, GetProcAddress
*   Set-ExecutionPolicy, Set-MasterBootRecord  
*   Get-WMIObject, Get-GPPPassword, Get-Keystrokes, Get-TimedScreenshot, Get-VaultCredential, GetServiceUnquoted, Get-ServiceEXEPerms, Get-ServicePerms, Get-RegAlwaysInstallElevated, Get-RegAutoLogon, Get-UnattendedInstallFiles, Get-Webconfig, Get-ApplicationHost, Get-PassHashes, Get-LsaSecret, GetInformation, Get-PSADForestInfo, Get-KerberosPolicy, Get-PSADForestKRBTGTInfo, Get-PSADForestInfo, GetKerberosPolicy  
*   Invoke-Command, Invoke-Expression, iex, Invoke-Shellcode, Invoke--Shellcode, Invoke-ShellcodeMSIL, InvokeMimikatzWDigestDowngrade, Invoke-NinjaCopy, Invoke-CredentialInjection, Invoke-TokenManipulation, InvokeCallbackIEX, Invoke-PSInject, Invoke-DllEncode, Invoke-ServiceUserAdd, Invoke-ServiceCMD, Invoke-ServiceStart, Invoke-ServiceStop, Invoke-ServiceEnable, Invoke-ServiceDisable, Invoke-FindDLLHijack, Invoke-FindPathHijack, Invoke-AllChecks, Invoke-MassCommand, Invoke-MassMimikatz, Invoke-MassSearch, Invoke-MassTemplate, Invoke-MassTokens, Invoke-ADSBackdoor, Invoke-CredentialsPhish, Invoke-BruteForce, Invoke-PowerShellIcmp, Invoke-PowerShellUdp, Invoke-PsGcatAgent, Invoke-PoshRatHttps, Invoke-PowerShellTcp, Invoke-PoshRatHttp, Invoke-PowerShellWmi, Invoke-PSGcat, Invoke-CreateCertificate, InvokeNetworkRelay,  
*   EncodedCommand, New-ElevatedPersistenceOption, wsman, Enter-PSSession, DownloadString, DownloadFile  
*   Out-Word, Out-Excel, Out-Java, Out-Shortcut, Out-CHM, Out-HTA, Out-Minidump, HTTP-Backdoor, FindAVSignature, DllInjection, ReflectivePEInjection, Base64, System.Reflection, System.Management  
*   Restore-ServiceEXE, Add-ScrnSaveBackdoor, Gupt-Backdoor, Execute-OnTime, DNS_TXT_Pwnage, WriteUserAddServiceBinary, Write-CMDServiceBinary, Write-UserAddMSI, Write-ServiceEXE, Write-ServiceEXECMD,  Enable-DuplicateToken, Remove-Update, Execute-DNSTXT-Code, Download-Execute-PS, Execute-CommandMSSQL, Download_Execute, Copy-VSS, Check-VM, Create-MultipleSessions, Run-EXEonRemote, Port-Scan, Remove-PoshRat, TexttoEXE, Base64ToString, StringtoBase64, Do-Exfiltration, Parse_Keys, Add-Exfiltration, AddPersistence, Remove-Persistence, Find-PSServiceAccounts, Discover-PSMSSQLServers, DiscoverPSMSExchangeServers, Discover-PSInterestingServices, Discover-PSMSExchangeServers, DiscoverPSInterestingServices  
