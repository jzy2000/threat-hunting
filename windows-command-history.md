# Review Command History

Examine execution history across all accounts on the system:

Search Security audit logs for process related events:



*   4688 A new process has been created \
Filter out events has LogonID=0x3e7, means Windows ran the programs. \
Use “LogonID” to correlate backwards to the logon event (4624) \
Use “Creator Process ID” to look for parent process in a preceding 4688 event
*   4689 A process has exited

Artifacts in `Windows Prefetch` folder are important to collect, Windows records programs that have been run on a system, even after the program has since been deleted.

`ShimCache` stored in SYSTEM registry hive stores information about all executed binaries that have been executed in the system since it was rebooted and it tracks:



*   File Full Path
*   File Size
*   $Standard_Information (SI) Last Modified time
*   Shimcache Last Updated time
*   Process Execution Flag

When `Prefetch` is disabled the ShimCache becomes a more valuable artifact. Data can be extracted using [ShimCacheParser.py](https://github.com/mandiant/ShimCacheParser) 

`Amcache.hve` file is also an important artifact to record the traces of anti-forensic programs, portable programs, and external storage devices. It tracks:



*   Execution path
*   First executed time
*   Deleted time
*   First installation

The hive content can be analyzed using amcache plugin of [RegRipper](https://github.com/keydet89/RegRipper2.8)

Once program execution info collection completed, look for suspicious executables:



*   Mislocated folder \
`C:\Windows\tasks.exe` (instead of `C:\Windows\System32`)
*   Typosquatting  \
`C:\Windows\System32\taskse.exe` (instead of `tasks.exe`)
*   Executables located in:
    *   `%Temp%` folder
    *   Download folder
    *   public folders
    *   Folder with random characters
    *   Registry location with random characters
*   Uncommon association with the parent process, such as:
    *   `svchost.exe` as parent process of interactive applications (Malware infection)
    *   Firefox launches an executable (Malicious plug-in or vulnerability in browser)
    *   Office executable(e.g. `Excel.exe`, `Word.exe`) launches an executable such as `cmd.exe`, `powershell.exe` (Malicious Office micro)
    *   `mshta.exe` launches Javascript or VBscript from registry location (HTA abuse behavior)
    *   `svchost.exe` launches Script Event Consumer WMI `scrcons.exe` (WMI backdoor)
    *   `powershell.exe` launches `regsvr32.exe` to load data from remote 
    *   Etc.
*   Executable with name known for attacker’s use such as `empire`, `mimikatz`
*   Check command line for suspicious arguments:
    *   “Process Command Line” field has `powershell.ex` in it, scan for encoded payload.
    *   `regsvr32.exe` is called to register and run COM data from remote location (Squiblydoo)
    *   `cmd.exe /Q /c` follow with `powershell.exe`, `wmic`
    *   etc.
*   Programs that may indicate an attempt to hide info such as `Eraser` and `CCleaner`
*   Check good processes make bad connection as a result of malware injection:
*   Trusted executables such as `wmic, regsvr32, powershell` etc. connect to suspicious IPs. E.g. `msiexec.exe` connects to Cryptomining IP.
*   WMI ActiveScriptEventConsumer `scrcons.exe` runs malicious scripts.

If process name suspicious to you, Google the executable name and its common location.

To confirm a suspicious executable, VirtusTotal can be helpful to either scan it in a sandbox or search by the hash of executable for known good/bad binaries.

When less-known malware executable/process is identified, investigate the damage further by looking into the events between 4688 and 4689 related to the process in question.
