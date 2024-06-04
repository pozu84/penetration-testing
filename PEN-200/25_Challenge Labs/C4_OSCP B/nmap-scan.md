## DMZ
192.168.212.147

192.168.212.149
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 5c:5f:f1:bb:02:f9:14:7c:8e:38:32:2b:f4:bc:d0:8c (RSA)
|   256 18:e2:47:e1:c8:40:a1:d0:2c:a5:87:97:bd:01:12:27 (ECDSA)
|_  256 26:2d:98:d9:47:6d:22:5d:4a:14:7a:24:5c:98:a2:1d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


192.168.212.150
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ad:ac:80:0a:5f:87:44:ea:ba:7f:95:ca:1e:90:78:0d (ECDSA)
|_  256 b3:ae:d1:25:24:c2:ab:4f:f9:40:c5:f0:0b:12:87:bb (ED25519)
8080/tcp open  http-proxy
|_http-favicon: Spring Java Framework
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
|_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: application/json;charset=UTF-8
|     Date: Tue, 04 Jun 2024 14:15:53 GMT
|     Connection: close
|     {"timestamp":"2024-06-04T14:15:53.213+0000","status":404,"error":"Not Found","message":"No message available","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/plain;charset=UTF-8
|     Content-Length: 19
|     Date: Tue, 04 Jun 2024 14:15:53 GMT
|     Connection: close
|     {"api-status":"up"}
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Tue, 04 Jun 2024 14:15:53 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 505 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 830
|     Date: Tue, 04 Jun 2024 14:15:53 GMT
|   Socks5: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 800
|     Date: Tue, 04 Jun 2024 14:15:53 GMT
|     Connection: close
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

192.168.212.151
PORT     STATE SERVICE          VERSION
80/tcp   open  http             Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
| http-methods: 
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
|_ssl-date: 2024-06-04T14:18:29+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=OSCP
| Not valid before: 2024-04-07T16:58:32
|_Not valid after:  2024-10-07T16:58:32
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: OSCP
|   DNS_Computer_Name: OSCP
|   Product_Version: 10.0.19041
|_  System_Time: 2024-06-04T14:18:24+00:00
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


