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
TCP connect san across all ports

`nmap -p- -Pn -sT --reason --open -oA full_port_scan <ip>` 

`nmap -p <ports> -Pn -sC -sV -oA nmap_default_scripts <ip>`

> Then you can run nmap automator! 

## Web Enumeration 
----------------------------- 
- Web Application:
- Web Technologies: 
- Database: 
- Language:
- Framework:
- What does the application do?: 

`nikto -h "http://$IP" | tee nikto.log` 

`gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/big.txt -b 400,401,404,500 -x php,sh,txt,cgi,html,js,css | tee gobuster.txt`

`sudo nmap -p 80 -sC 192.168.120.108` 

### SMB 
-----------------------------
(Enumeration)[https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/] 

Get Domain   
`ldap -h 10.10.10.161 -x -s base namingcontexts` 

Get domain users 
`ldap -h 10.10.10.161 -x -b "DC=htb,DC=local" '(objectClass=Person)'` 

## Exploitation 
-------------------------
Enter info about exploitation here
