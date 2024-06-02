Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits                                                                    
    OS Name: Microsoft Windows 10 Pro
    OS Version: 10.0.19041 N/A Build 19041
    System Type: x64-based PC
    Hostname: oscp
    ProductName: Windows 10 Pro
    EditionID: Professional
    ReleaseId: 2004
    BuildBranch: vb_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 2
    SystemLang: en-US
    KeyboardLang: English (United States)
    TimeZone: (UTC-08:00) Pacific Time (US & Canada)
    IsVirtualMachine: True
    Current Time: 6/2/2024 8:54:26 AM
    HighIntegrity: False
    PartOfDomain: False
    Hotfixes: KB5006365, KB5015684, KB5020372,

  [?] Windows vulns search powered by Watson(https://github.com/rasta-mouse/Watson)
 [*] OS Version: 2004 (19041)
 [*] Enumerating installed KBs...
 [!] CVE-2020-1013 : VULNERABLE
  [>] https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/                                                                                                         
 [*] Finished. Found 1 potential vulnerabilities.
System Environment Variables
� Check for some passwords or keys in the env variables 
    ComSpec: C:\WINDOWS\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\WINDOWS\TEMP
    TMP: C:\WINDOWS\TEMP
    USERNAME: SYSTEM
    windir: C:\WINDOWS
    Path: C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\;C:\Program Files\PuTTY\
    NUMBER_OF_PROCESSORS: 2
    PROCESSOR_LEVEL: 25
    PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
    PROCESSOR_REVISION: 0101

����������͹ PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.19041.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\offsec\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 8B
Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    offsec::OSCP:1122334455667788:516cd1d7e51e6ee1b6e813049144d87c:0101000000000000fbf04e2805b5da0108edaee988368a3e00000000080030003000000000000000000000000020000030847b0d30db27e4a5300f471fe10166642c0e61df075aa9ad1d3cd8a8f337740a00100000000000000000000000000000000000090000000000000000000000
  C:\Users\offsec\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt 
  Interesting files and registry �������������������������������������

����������͹ Putty Sessions
    RegKey Name: zachary
    RegKey Value: "&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"
