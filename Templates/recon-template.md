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
`nmap -p- -Pn -sT --reason --open --min-rate 10000 -oA tcp_full_port_scan <ip>` 

### Scan all UDP ports 
`sudo nmap -sU -p- --min-rate 10000 -oA udp_full_port_scan <ip>` 

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

If wordpress site: 
`wpscan -e ap,at,tt --plugins-detection aggressive --plugins-version-detection aggressive --api-token $WP_SCAN_TOKEN --url http://10.10.110.100:65000/wordpress`

`nikto -h "http://$IP" | tee nikto.log` 

`gobuster dir -u http://$IP -f -w /usr/share/wordlists/dirb/big.txt -b 400,401,404,500 -x php,sh,txt,cgi,html,js,css | tee gobuster.txt`

`sudo nmap -Pn -p 80 -sC 192.168.120.108` 

### SMB 
-----------------------------
(Enumeration)[https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/] 
(Crackmapexec)[https://wiki.porchetta.industries/smb-protocol/enumeration]

`nmap --script smb-vuln* -p 445 -oA smb_vulns <ip>`

### DNS Enumeration
(DNS Enum)[https://github.com/muckitymuck/OSCP-Study-Guide/blob/master/enumeration/active_information_gathering.md#dns-enumeration]

## Exploitation 
-------------------------
Enter info about exploitation here
