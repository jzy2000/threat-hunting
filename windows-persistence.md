# Examine Malware Persistence

Run _schtasks_ or Task Scheduler(GUI) version to check current scheduled tasks to see if any have been added, as well as tasks executed in the past which are recorded in scheduled task log file: `_C:\Windows\Tasks\SCHEDLGU.TXT_`

Alternatively, run Osquery if available: _SELECT hidden,name,action FROM scheduled_tasks WHERE enabled = 1;_

Attackers may abuse Background Intelligent Transfer Service(BITS) to download, execute, and even clean up after running malicious code.

Use [bits_parser](https://github.com/ANSSI-FR/bits_parser) CLI to extract BITS job from QMGR queue or disk image to CSV file, and scan _src_fn_ field for suspicious downloading URL. For example:

`bits_parser -o result.csv C:\ProgramData\Microsoft\Network\Downloader\qmgr0.dat`

Search various folders, pay special attention to executables or scripts with file following extensions: _.bat, .cmd, .com, .lnk, .pif, .scr, .vb, .vbe, .vbs, .wsh, .ps, .exe_

Especially those files with multiple extensions e.g. _image.jpg.exe_, and disguising for instance, a standard image icon to look like a harmless image, are very likely indicators of malware.

Use Google to search for a process name and determine its function or if it is malicious:

*   _C:\windows\temp_
*   Recycle Bin
*   Recent items
*   _C:\Users\<user-name>\AppData\Roaming\Microsoft\Windows\Recent_ 
*   Shared folders: use _net_ command to list all sharing folders: _net view \\127.0.0.1_

A PowerShell profile is a script that runs as a logon script when PowerShell starts. 

Locations that profile.ps1 can be stored should be monitored for new profiles or changes since these can be used for malicious persistence:



*   AllUsersAllHosts -_ %windir%\System32\WindowsPowerShell\v1.0\profile.ps1_ 
*   AllUsersAllHosts (WoW64) - _%windir%\SysWOW64\WindowsPowerShell\v1.0\profile.ps1_ 
*   AllUsersCurrentHost - _%windir%\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1_ 
*   AllUsersCurrentHost (ISE) - _%windir%\System32\WindowsPowerShell\v1.0\Microsoft.PowerShellISE_profile.ps1_ 
*   AllUsersCurrentHost (WoW64) – _%windir%\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1_ 
*   AllUsersCurrentHost (ISE - WoW64) - _%windir%\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShellISE_profile.ps1_ 
*   CurrentUserAllHosts -_ %homedrive%%homepath%\[My]Documents\profile.ps1_ 
*   CurrentUserCurrentHost - _%homedrive%%homepath%\[My]Documents\Microsoft.PowerShell_profile.ps1_ 
*   CurrentUserCurrentHost (ISE) - _%homedrive%%homepath%\[My]Documents\Microsoft.PowerShellISE_profile.ps1_

Search Registry audit events around time of incident for possible fileless malware using Registry as storage, particularly in following events:



*   4656 A handle to an object was requested
*   4657 A registry value was modified
*   4659 A handle to an object was requested with intent to delete
*   4663 An attempt was made to access an object
*   4670 Permissions on an object were changed

Scan for new key with large encoded binary created and fetched from the Registry audit events.

Pay attention to which Exe accessed and modified those keys.

Many Registry keys are defined to load and run Exe/DLL/shell when various events occur in Windows. To locate for malware using Registry key to persist, [here](https://www.dropbox.com/s/rlzvhaaqrq9xyns/autoruns.txt?dl=0) is a comprehensive list of key location, and consider using [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) whenever possible, or manually examine these registry locations:

Search unauthorized Browser Helper Objects(IE BHO) being installed:



*   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects

Search hijacked DLL Search Order:



*   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs

Search BootExecute Key:



*   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute:

Search unauthorized Services being installed:



*   HKLM\System\CurrentControlSet\Services  (start value of 0 indicates kernel drivers, which load before kernel initiation)
*   HKLM\System\CurrentControlSet\Services (start value of 2, auto-start and 3, manual start via SCM)
*   HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
*   HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
*   HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
*   HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
*   Alternatively, run Osquery if available:

    `SELECT name,display_name,user_account,path FROM services WHERE start_type = ‘AUTO_START’ AND path NOT LIKE ‘C:\Windows\system32\svchost.exe -k %’;`


Search unauthorized Winlogon script being installed:



*   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
*   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
*   HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
*   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
*   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad

Search unauthorized startup program in Run/RunOnce Keys:



*   HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
*   HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
*   HKLM\Software\Microsoft\Windows\CurrentVersion\Run
*   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
*   HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
*   HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
*   HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
*   HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
*   HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
*   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
*   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
*   Alternatively, run OSquery if available: \
`SELECT name,path,source,status,username FROM startup_items;`

Search Legacy Windows Load:



*   HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load
*   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows

Search unauthorized execution registered in Scheduled Tasks key:



*   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler 
*   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks (flat list by GUID)
*   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree(tree view by task name) 
*   Alternatively, run OSquery if available: \
`SELECT hidden,name,action FROM scheduled_tasks WHERE enabled = 1;`

AppInit_DLLs



*   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\\AppInit_DLLs

AppCombat Shims:



*   %WINDIR%\AppPatch\sysmain.sdb 
*   HKLM\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb 
*   %WINDIR%\AppPatch\custom
*   %WINDIR%\AppPatch\AppPatch64\Custom
*   HKLM\software\microsoft\windows nt\currentversion\appcompatflags\custom
*   Alternatively, run OSquery if available: \
`SELECT executable,path,description,sdb_id FROM appcompat_shims;`

Googling the SDB ID can provide lots of context to decide whether a shim entry is legitimate or not.
