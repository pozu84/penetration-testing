════════════════════════════════════╣ System Information ╠════════════════════════════════════

╔══════════╣ Basic System Information
╚ Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits
    OS Name: Microsoft Windows Server 2022 Standard
    OS Version: 10.0.20348 N/A Build 20348
    System Type: x64-based PC
    Hostname: EXTERNAL
    ProductName: Windows Server 2022 Standard
    EditionID: ServerStandard
    ReleaseId: 2009
    BuildBranch: fe_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 2
    SystemLang: en-US
    KeyboardLang: English (United States)
    TimeZone: (UTC-08:00) Pacific Time (US & Canada)
    IsVirtualMachine: True
    Current Time: 6/1/2024 12:46:04 AM
    HighIntegrity: False
    PartOfDomain: False
    Hotfixes: KB5004330, KB5005039, KB5005552,
╔══════════╣ User Environment Variables
╚ Check for some passwords or keys in the env variables
    COMPUTERNAME: EXTERNAL
    USERPROFILE: C:\Users\emma
    HOMEPATH: \Users\emma
    LOCALAPPDATA: C:\Users\emma\AppData\Local
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files (x86)\Microsoft SQL Server\150\Tools\PowerShell\Modules\
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files (x86)\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files (x86)\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\;C:\Users\emma\AppData\Local\Microsoft\WindowsApps;
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 25
    LOGONSERVER: \\EXTERNAL
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    HOMEDRIVE: C:
    SystemRoot: C:\Windows
    SESSIONNAME: RDP-Tcp#0
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    APPDATA: C:\Users\emma\AppData\Roaming
    PROCESSOR_REVISION: 0101
    USERNAME: emma
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    CLIENTNAME: kali
    OS: Windows_NT
    AppKey: !8@aBRBYdb3!
    USERDOMAIN_ROAMINGPROFILE: EXTERNAL
    PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
    ComSpec: C:\Windows\system32\cmd.exe
    PROMPT: $P$G
    SystemDrive: C:
    TEMP: C:\Users\emma\AppData\Local\Temp\2
    ProgramFiles: C:\Program Files
    NUMBER_OF_PROCESSORS: 2
    TMP: C:\Users\emma\AppData\Local\Temp\2
    ProgramData: C:\ProgramData
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: EXTERNAL
    PUBLIC: C:\Users\Public
╔══════════╣ System Environment Variables
╚ Check for some passwords or keys in the env variables
    ComSpec: C:\Windows\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files (x86)\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files (x86)\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files (x86)\Microsoft SQL Server\150\Tools\PowerShell\Modules\
    TEMP: C:\Windows\TEMP
    TMP: C:\Windows\TEMP
    USERNAME: SYSTEM
    windir: C:\Windows
    NUMBER_OF_PROCESSORS: 2
    PROCESSOR_LEVEL: 25
    PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
    PROCESSOR_REVISION: 0101
    AppKey: !8@aBRBYdb3!
╔══════════╣ PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.20348.1
    PowerShell Core Version:
    Transcription Settings:
    Module Logging Settings:
    Scriptblock Logging Settings:
    PS history file: C:\Users\emma\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 383B
╔══════════╣ Scheduled Applications --Non Microsoft--
╚ Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries
    (Administrator) BetaTask: C:\BetaMonitor\BetaMonitor.exe
    Trigger: At system startup-After triggered, repeat every 00:01:00 for a duration of 1.00:00:00.
════════════════════════════════════╣ Network Information ╠════════════════════════════════════

╔══════════╣ Network Shares
    ADMIN$ (Path: C:\Windows)
    C$ (Path: C:\)
    IPC$ (Path: )
    transfer (Path: C:\transfer) -- Permissions: AllAccess
    Users (Path: C:\Users) -- Permissions: AllAccess

╔══════════╣ Enumerate Network Mapped Drives (WMI)

╔══════════╣ Host File

╔══════════╣ Network Ifaces and known hosts
╚ The masks are only for the IPv4 addresses
    Ethernet0[00:50:56:AB:37:F8]: 192.168.197.248 / 255.255.255.0
        Gateways: 192.168.197.254
        DNSs: 192.168.197.254
        Known hosts:
          169.254.169.254       00-00-00-00-00-00     Invalid
          192.168.50.254        00-50-56-AB-04-CD     Dynamic
          192.168.197.254       00-50-56-AB-04-CD     Dynamic
          192.168.197.255       FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static


╔══════════╣ Current TCP Listening Ports
╚ Check for services restricted from the outside
  Enumerating IPv4 connections

  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               80            0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         892             svchost
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               3389          0.0.0.0               0               Listening         368             svchost
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         676             lsass
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         540             wininit
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1080            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         1472            svchost
  TCP        0.0.0.0               49668         0.0.0.0               0               Listening         1408            svchost
  TCP        0.0.0.0               49669         0.0.0.0               0               Listening         2284            svchost
  TCP        0.0.0.0               49670         0.0.0.0               0               Listening         656             services
  TCP        0.0.0.0               49965         0.0.0.0               0               Listening         3152            sqlservr
  TCP        192.168.197.248       139           0.0.0.0               0               Listening         4               System
  TCP        192.168.197.248       3389          192.168.45.165        36774           Established       368             svchost

  Enumerating IPv6 connections

  Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name

  TCP        [::]                                        80            [::]                                        0               Listening         4               System
  TCP        [::]                                        135           [::]                                        0               Listening         892             svchost
  TCP        [::]                                        445           [::]                                        0               Listening         4               System
  TCP        [::]                                        3389          [::]                                        0               Listening         368             svchost
  TCP        [::]                                        5985          [::]                                        0               Listening         4               System
  TCP        [::]                                        47001         [::]                                        0               Listening         4               System
  TCP        [::]                                        49664         [::]                                        0               Listening         676             lsass
  TCP        [::]                                        49665         [::]                                        0               Listening         540             wininit
  TCP        [::]                                        49666         [::]                                        0               Listening         1080            svchost
  TCP        [::]                                        49667         [::]                                        0               Listening         1472            svchost
  TCP        [::]                                        49668         [::]                                        0               Listening         1408            svchost
  TCP        [::]                                        49669         [::]                                        0               Listening         2284            svchost
  TCP        [::]                                        49670         [::]                                        0               Listening         656             services
  TCP        [::]                                        49965         [::]                                        0               Listening         3152            sqlservr

╔══════════╣ Current UDP Listening Ports
╚ Check for services restricted from the outside
  Enumerating IPv4 connections

  Protocol   Local Address         Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        0.0.0.0               123           *:*                            2684              svchost
  UDP        0.0.0.0               500           *:*                            2292              svchost
  UDP        0.0.0.0               3389          *:*                            368               svchost
  UDP        0.0.0.0               4500          *:*                            2292              svchost
  UDP        0.0.0.0               5353          *:*                            1608              svchost
  UDP        0.0.0.0               5355          *:*                            1608              svchost
  UDP        0.0.0.0               53940         *:*                            1608              svchost
  UDP        0.0.0.0               55968         *:*                            1608              svchost
  UDP        127.0.0.1             55741         *:*                            2392              svchost
  UDP        192.168.197.248       137           *:*                            4                 System
  UDP        192.168.197.248       138           *:*                            4                 System

  Enumerating IPv6 connections

  Protocol   Local Address                               Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        [::]                                        123           *:*                            2684              svchost
  UDP        [::]                                        500           *:*                            2292              svchost
  UDP        [::]                                        3389          *:*                            368               svchost
  UDP        [::]                                        4500          *:*                            2292              svchost
  UDP        [::]                                        53940         *:*                            1608              svchost
  UDP        [::]                                        55968         *:*                            1608              svchost

  




