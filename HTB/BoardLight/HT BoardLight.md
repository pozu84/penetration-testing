sudo nmap -sC -sV -T4 10.10.11.11

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

sudo nano /etc/hosts
10.10.11.11 boardlight.htb

# Since it only have 2 port open, lets see how we can exploit the port 80 
# Lets try out the directory and subdomain buster

gobuster dns -d boardlight.htb -w /home/kali/Tools/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt
# Subdomain doesnt have any results..

gobuster dir -u http://boardlight.htb -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 4 

# We still can try with ffuf and wfuzz
ffuf -w /usr/share/wordlists/wfuzz/general/medium.txt -u http://FUZZ.boardlight.htb 

wfuzz -H "Host: FUZZ.boardlight.htb" --hc 404,403 -H "User-Agent: PENTEST" -c -z file,"/home/kali/Tools/SecLists-master/Discovery/DNS/subdomains-top1million-20000.txt" -u http://boardlight.htb --hl 517


