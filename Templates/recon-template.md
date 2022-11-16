# Summary
- IP: 
- OS: 

===============================
|   AVOID  *RABBIT*  HOLES!   |
===============================
|       Stuck 2+ Hours        |
|           ------            |
|     Fifteen Minute Break    |
|    And Change Vulnerabily   |
===============================

## POINTERS
- File:
- Type: 
- Notes: 

### VULNERABILITIES DISCOVERED
- CVE: 
- Type: 
- PoC: 

### REVERSE SHELL
Bash -
nodeJS -
PHP -
Python - 
Powershell -
Msfvenom - 

## Port Scanning 
-----------------------------
nmap scans to start 

### Scan all TCP ports 
`nmap -p- -Pn -sT --reason --open -oA tcp_full_port_scan <ip>` 

### Scan all UDP ports 
`sudo nmap -sU -p- -oA udp_full_port_scan <ip>` 

### Version and default scripts on found ports
`nmap -p <ports> -Pn -sC -sV -oA nmap_default_scripts <ip>`

> Then you can run nmap automator! 
`nmapAutomator.sh -H <ip> -t All`

## Web Enumeration 
----------------------------- 
- Web Application:
- Web Technologies: 
- Database: 
- Language:
- Framework:
- What does the application do?: 

*If port 443 is open, view the certificate*
- Add any DNS names in cert to /etc/hosts  

*Remember to change http parameters when testing! (GET/POST/PUT, etc)* 

*Check for robots.txt, changelog, readme, etc.* 

If wordpress site: 
`wpscan -e ap,at,tt --plugins-detection aggressive --plugins-version-detection aggressive --api-token $WP_SCAN_TOKEN --url http://10.10.110.100:65000/wordpress`

Scan website for common issues:
`nikto -h "http://$IP" | tee nikto.log` 

Subdirectory brute force:
`gobuster dir -u http://$IP -f -w /usr/share/wordlists/dirb/big.txt -b 400,401,404,500 -x php,sh,txt,cgi,html,js,css | tee gobuster.txt`
`dirbuster -u http://10.10.10.60 -t 20 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -e php,txt,html` 

nmap default scripts for http:
`sudo nmap -Pn -p 80 -sC 192.168.120.108` 

If webdav:
`davtest -url http://10.10.10.15` 

## SMB 
-----------------------------
[Enumeration](https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/)
[Crackmapexec](https://wiki.porchetta.industries/smb-protocol/enumeration)

`crackmapexec smb 10.10.10.161 -u '' -p ''`
`crackmapexec smb 10.10.10.161 --pass-pol`
`crackmapexec smb 10.10.10.161 --users`
`crackmapexec smb 10.10.10.161 --groups`

**If AD DC** 
`./kerbrute_linux_amd64 userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175` 
**Once you have a user list**
`GetNPUsers.py egotistical-bank.local/ -usersfile <file> -format hashcat -outputfile hashes.domain.txt` 

`nmap --script smb-vuln* -p 445 -oA smb_vulns <ip>`

## DNS Enumeration
Don't forget to add hosts to /etc/hosts! 

[DNS Enum](https://github.com/muckitymuck/OSCP-Study-Guide/blob/master/enumeration/active_information_gathering.md#dns-enumeration)

Zone Transfer:
`dig axfr cronos.htb @10.10.10.13` 

Subdomain brute force:
`gobuster dns -d cronos.htb -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt`

`wfuzz -c -u http://10.10.10.43/ -H "Host: FUZZ.nineveh.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 178` ** --hh is hide responses of a certain size

use nslookup for machines with port 53 open:
```
root@kali# nslookup 
> server 10.10.10.13
Default server: 10.10.10.13
Address: 10.10.10.13#53
> 10.10.10.13
13.10.10.10.in-addr.arpa        name = ns1.cronos.htb.
``` 

Automated dns recon:
`dnsenum --dnsserver 10.10.10.175 egotistical-bank.local`

`dnsrecon -d egotistical-bank.local -a -n 10.10.10.175`

## Exploitation 
-------------------------
Enter info about exploitation here
