Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits                                                                    
    OS Name: Microsoft Windows Server 2022 Standard
    OS Version: 10.0.20348 N/A Build 20348
    System Type: x64-based PC
    Hostname: WEB02
    Domain Name: dmz.medtech.com
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
    Current Time: 5/28/2024 8:12:47 AM
    HighIntegrity: False
    PartOfDomain: True
    Hotfixes: KB5017265, KB5012170, KB5017316, KB5016704,
User Environment Variables
� Check for some passwords or keys in the env variables 
    COMPUTERNAME: WEB02
    PUBLIC: C:\Users\Public
    LOCALAPPDATA: C:\Windows\ServiceProfiles\MSSQL$SQLEXPRESS\AppData\Local
    PSModulePath: %ProgramFiles%\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files (x86)\Microsoft SQL Server\150\Tools\PowerShell\Modules\
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\;C:\Program Files (x86)\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files (x86)\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files\Azure Data Studio\bin;C:\Windows\ServiceProfiles\MSSQL$SQLEXPRESS\AppData\Local\Microsoft\WindowsApps
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 25
    ProgramFiles: C:\Program Files
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    USERPROFILE: C:\Windows\ServiceProfiles\MSSQL$SQLEXPRESS
    SystemRoot: C:\Windows
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    ProgramData: C:\ProgramData
    PROCESSOR_REVISION: 0101
    COMPLUS_MDA: InvalidVariant;RaceOnRCWCleanup;InvalidFunctionPointerInDelegate;InvalidMemberDeclaration;ReleaseHandleFailed;MarshalCleanupError;ReportAvOnComRelease;DangerousThreadingAPI;invalidOverlappedToPinvoke
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    OS: Windows_NT
    PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
    ComSpec: C:\Windows\system32\cmd.exe
    PROMPT: $P$G
    SystemDrive: C:
    TEMP: C:\Windows\SERVIC~1\MSSQL$~1\AppData\Local\Temp
    NUMBER_OF_PROCESSORS: 2
    APPDATA: C:\Windows\ServiceProfiles\MSSQL$SQLEXPRESS\AppData\Roaming
    TMP: C:\Windows\SERVIC~1\MSSQL$~1\AppData\Local\Temp
    USERNAME: MSSQL$SQLEXPRESS
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: NT Service
    USERDNSDOMAIN: medtech.com
System Environment Variables
� Check for some passwords or keys in the env variables 
    ComSpec: C:\Windows\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\;C:\Program Files (x86)\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files (x86)\Microsoft SQL Server\150\DTS\Binn\;C:\Program Files\Azure Data Studio\bin
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
Enumerating NTLM Settings
  LanmanCompatibilityLevel    :  (Send NTLMv2 response only - Win7+ default)
                                                                                                                    

  NTLM Signing Settings                                                                                             
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : False
      ServerNegotiateSigning  : False
      LdapSigning             : Negotiate signing (Negotiate signing)

  Session Security                                                                                                  
      NTLMMinClientSec        : 536870912 (Require 128-bit encryption)
      NTLMMinServerSec        : 536870912 (Require 128-bit encryption)
                                                                                                                    

  NTLM Auditing and Restrictions                                                                                    
      InboundRestrictions     :  (Not defined)
      OutboundRestrictions    :  (Not defined)
      InboundAuditing         :  (Not defined)
      OutboundExceptions      : 
Users Information �������������������������������������

����������͹ Users
� Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups                                                                                  
  Current user: MSSQL$SQLEXPRESS
  Current groups: Everyone, Builtin\Performance Monitor Users, Users, Service, Console Logon, Authenticated Users, This Organization, Local, NT Services\All Services
   =================================================================================================

    WEB02\Administrator: Built-in account for administering the computer/domain
        |->Groups: Administrators,Remote Desktop Users
        |->Password: CanChange-NotExpi-Req

    WEB02\DefaultAccount(Disabled): A user account managed by the system.
        |->Groups: System Managed Accounts Group
        |->Password: CanChange-NotExpi-NotReq

    WEB02\Guest(Disabled): Built-in account for guest access to the computer/domain
        |->Groups: Guests
        |->Password: NotChange-NotExpi-NotReq

    WEB02\offsec: offsec
        |->Groups: Users
        |->Password: CanChange-NotExpi-Req

    WEB02\WDAGUtilityAccount(Disabled): A user account managed and used by the system for Windows Defender Application Guard scenarios.
        |->Password: CanChange-NotExpi-Req
Current Token privileges
� Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#token-manipulation                                                                      
    SeAssignPrimaryTokenPrivilege: DISABLED
    SeIncreaseQuotaPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeManageVolumePrivilege: SE_PRIVILEGE_ENABLED
    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreateGlobalPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: DISABLED
Logged users
    NT Service\MSSQL$SQLEXPRESS
    NT SERVICE\SQLTELEMETRY$SQLEXPRESS
    NT SERVICE\MSSQL$MICROSOFT##WID
    MEDTECH\joe
Display information about local users
   Computer Name           :   WEB02
   User Name               :   Administrator
   User Id                 :   500
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :   Built-in account for administering the computer/domain
   Last Logon              :   5/28/2024 7:25:19 AM
   Logons Count            :   54
   Password Last Set       :   12/5/2022 12:10:28 PM
Network Ifaces and known hosts
� The masks are only for the IPv4 addresses 
    Ethernet0[00:50:56:AB:78:4A]: 192.168.215.121 / 255.255.255.0
        Gateways: 192.168.215.254
        Known hosts:
          192.168.215.254       00-50-56-AB-C6-03     Dynamic
          192.168.215.255       FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          239.255.255.250       01-00-5E-7F-FF-FA     Static

    Ethernet1[00:50:56:AB:8B:B2]: 172.16.215.254 / 255.255.255.0
        DNSs: 172.16.215.10
        Known hosts:
          172.16.215.10         00-50-56-AB-AD-15     Dynamic
          172.16.215.11         00-50-56-AB-B2-C3     Dynamic
          172.16.215.12         00-50-56-AB-71-18     Dynamic
          172.16.215.13         00-50-56-AB-7A-1B     Dynamic
          172.16.215.14         00-50-56-AB-06-93     Dynamic
          172.16.215.82         00-50-56-AB-84-CF     Dynamic
          172.16.215.83         00-50-56-AB-C1-7B     Dynamic
          172.16.215.255        FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          239.255.255.250       01-00-5E-7F-FF-FA     Static
DNS cached --limit 70--
    Entry                                 Name                                  Data
    dc01.medtech.com                      DC01.medtech.com                      172.16.215.10
    dc01.medtech.com                      DC01.medtech.com                      172.16.215.10
Found Misc-Usernames Regexes
C:\inetpub\wwwroot\assets\js\jquery.form.js: username', value: 'jresig' }, { name: 'password', value: 'secret' } ]
Found Misc-Code asigning passwords Regexes
C:\inetpub\wwwroot\web.config: password=WhileChirpTuesday218;Trusted_Connection=False;MultipleActiveResultSets=true; Integrated Security=False; Max Pool Size=500;" /> 
