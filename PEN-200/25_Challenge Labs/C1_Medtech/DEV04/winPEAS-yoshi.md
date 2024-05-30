Basic System Information
╚ Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits
    OS Name: Microsoft Windows Server 2022 Standard
    OS Version: 10.0.20348 N/A Build 20348
    System Type: x64-based PC
    Hostname: DEV04
    Domain Name: medtech.com
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
    Current Time: 5/30/2024 8:28:11 AM
    HighIntegrity: False
    PartOfDomain: True
    Hotfixes: KB5004330, KB5005039, KB5005552,
User Environment Variables
╚ Check for some passwords or keys in the env variables
    COMPUTERNAME: DEV04
    USERPROFILE: C:\Users\yoshi
    HOMEPATH: \Users\yoshi
    LOCALAPPDATA: C:\Users\yoshi\AppData\Local
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\yoshi\AppData\Local\Microsoft\WindowsApps;
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 25
    LOGONSERVER: \\DC01
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    HOMEDRIVE: C:
    SystemRoot: C:\Windows
    SESSIONNAME: RDP-Tcp#0
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    APPDATA: C:\Users\yoshi\AppData\Roaming
    PROCESSOR_REVISION: 0101
    USERNAME: yoshi
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    CLIENTNAME: kali
    OS: Windows_NT
    USERDOMAIN_ROAMINGPROFILE: MEDTECH
    PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
    ComSpec: C:\Windows\system32\cmd.exe
    PROMPT: $P$G
    SystemDrive: C:
    TEMP: C:\Users\yoshi\AppData\Local\Temp\2
    ProgramFiles: C:\Program Files
    NUMBER_OF_PROCESSORS: 2
    TMP: C:\Users\yoshi\AppData\Local\Temp\2
    ProgramData: C:\ProgramData
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: MEDTECH
    PUBLIC: C:\Users\Public
    USERDNSDOMAIN: MEDTECH.COM
 System Environment Variables
╚ Check for some passwords or keys in the env variables
    ComSpec: C:\Windows\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\Windows\TEMP
    TMP: C:\Windows\TEMP
    USERNAME: SYSTEM
    windir: C:\Windows
    NUMBER_OF_PROCESSORS: 2
    PROCESSOR_LEVEL: 25
    PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
    PROCESSOR_REVISION: 0101
PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.20348.1
    PowerShell Core Version:
    Transcription Settings:
    Module Logging Settings:
    Scriptblock Logging Settings:
    PS history file: C:\Users\yoshi\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 187B
RDP Sessions
    SessID    pSessionName   pUserName      pDomainName              State     SourceIP
    1         Console        leon           MEDTECH                  Active
    2         RDP-Tcp#0      yoshi          MEDTECH                  Active    127.0.0.1
Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  medtech.com
    DefaultUserName               :  leon
Network Information ╠════════════════════════════════════

╔══════════╣ Network Shares
    ADMIN$ (Path: C:\Windows)
    C$ (Path: C:\)
    IPC$ (Path: )

╔══════════╣ Enumerate Network Mapped Drives (WMI)

╔══════════╣ Host File

╔══════════╣ Network Ifaces and known hosts
╚ The masks are only for the IPv4 addresses
    Ethernet0[00:50:56:AB:AF:7A]: 172.16.219.12 / 255.255.255.0
        Gateways: 172.16.219.254
        DNSs: 172.16.219.10
        Known hosts:
          172.16.219.10         00-50-56-AB-E8-19     Dynamic
          172.16.219.254        00-50-56-AB-EA-5E     Dynamic
          172.16.219.255        FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static
Current TCP Listening Ports
╚ Check for services restricted from the outside
  Enumerating IPv4 connections

  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               135           0.0.0.0               0               Listening         884             svchost
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               3389          0.0.0.0               0               Listening         268             svchost
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         668             lsass
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         540             wininit
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1160            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         668             lsass
  TCP        0.0.0.0               49668         0.0.0.0               0               Listening         1544            svchost
  TCP        0.0.0.0               49669         0.0.0.0               0               Listening         1280            svchost
  TCP        0.0.0.0               49670         0.0.0.0               0               Listening         652             services
  TCP        0.0.0.0               49671         0.0.0.0               0               Listening         2124            svchost
  TCP        172.16.219.12         139           0.0.0.0               0               Listening         4               System
  TCP        172.16.219.12         3389          172.16.219.254        49754           Established       268             svchost

  Enumerating IPv6 connections

  Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name

  TCP        [::]                                        135           [::]                                        0               Listening         884             svchost
  TCP        [::]                                        445           [::]                                        0               Listening         4               System
  TCP        [::]                                        3389          [::]                                        0               Listening         268             svchost
  TCP        [::]                                        5985          [::]                                        0               Listening         4               System
  TCP        [::]                                        47001         [::]                                        0               Listening         4               System
  TCP        [::]                                        49664         [::]                                        0               Listening         668             lsass
  TCP        [::]                                        49665         [::]                                        0               Listening         540             wininit
  TCP        [::]                                        49666         [::]                                        0               Listening         1160            svchost
  TCP        [::]                                        49667         [::]                                        0               Listening         668             lsass
  TCP        [::]                                        49668         [::]                                        0               Listening         1544            svchost
  TCP        [::]                                        49669         [::]                                        0               Listening         1280            svchost
  TCP        [::]                                        49670         [::]                                        0               Listening         652             services
  TCP        [::]                                        49671         [::]                                        0               Listening         2124            svchost

╔══════════╣ Current UDP Listening Ports
╚ Check for services restricted from the outside
  Enumerating IPv4 connections

  Protocol   Local Address         Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        0.0.0.0               123           *:*                            356               svchost
  UDP        0.0.0.0               162           *:*                            2244              snmptrap
  UDP        0.0.0.0               500           *:*                            2116              svchost
  UDP        0.0.0.0               3389          *:*                            268               svchost
  UDP        0.0.0.0               4500          *:*                            2116              svchost
  UDP        0.0.0.0               5353          *:*                            1060              svchost
  UDP        0.0.0.0               5355          *:*                            1060              svchost
  UDP        0.0.0.0               53232         *:*                            1060              svchost
  UDP        0.0.0.0               58353         *:*                            1060              svchost
  UDP        127.0.0.1             51772         *:*                            1324              svchost
  UDP        127.0.0.1             52651         *:*                            2168              svchost
  UDP        127.0.0.1             53242         *:*                            4596              C:\Users\yoshi\Desktop\winpeas.exe
  UDP        127.0.0.1             60216         *:*                            668               lsass
  UDP        172.16.219.12         137           *:*                            4                 System
  UDP        172.16.219.12         138           *:*                            4                 System

  Enumerating IPv6 connections

  Protocol   Local Address                               Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        [::]                                        123           *:*                            356               svchost
  UDP        [::]                                        162           *:*                            2244              snmptrap
  UDP        [::]                                        500           *:*                            2116              svchost
  UDP        [::]                                        3389          *:*                            268               svchost
  UDP        [::]                                        4500          *:*                            2116              svchost
  UDP        [::]                                        53232         *:*                            1060              svchost
  UDP        [::]                                        58353         *:*                            1060              svchost

╔══════════╣ Firewall Rules
╚ Showing only DENY rules (too many ALLOW rules always)
    Current Profiles: PUBLIC
    FirewallEnabled (Domain):    False
    FirewallEnabled (Private):    False
    FirewallEnabled (Public):    False
    DENY rules:
Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    yoshi::MEDTECH:1122334455667788:fa6975ece97295fea3659004bd2af353:0101000000000000216f6a0ba6b2da010e9a590873eb9e8a00000000080030003000000000000000000000000020000006665000add33f456a9cd1cded7156fd765b3998c9b1159c46124729c1eb2cbc0a00100000000000000000000000000000000000090000000000000000000000
Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\TEMP\backup.exe": yoshi [WriteData/CreateFiles]
     File Permissions "C:\Users\yoshi\Desktop\winpeas.exe": yoshi [AllAccess]