# MS01
192.168.162.141
22/tcp   open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
81/tcp   open  http          Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3306/tcp open  mysql         MySQL (unauthorized)

# AERO
192.168.162.143
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
81/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open  http       Apache httpd 2.4.41
3000/tcp open  ppp?
3001/tcp open  nessus?
3003/tcp open  cgms?
3306/tcp open  mysql      MySQL (unauthorized)
5432/tcp open  postgresql PostgreSQL DB 9.6.0 or later

# CRYSTAL
192.168.162.144
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|     Remotes:
|_      https://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@github.com/PWK-Challenge-Lab/dev.git


# HERMES
192.168.162.145
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services

