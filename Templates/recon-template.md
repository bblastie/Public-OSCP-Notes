# Summary
- IP: 
- Web Application:
- Web Technologies: 
- Web Server: 
- SSH Service: 
- Database: 
- OS: 


## Top Options
- Mantis Bug tracker exploit 
- Adminer weak admin creds
- Adminer vulnerability
- Wordpress vulnerability
- Duplication of app on 8082? 


## Reconnaissance
-----------------------------

### Port Scanning 
-----------------------------

TCP connect san across all ports

`nmap -p- -Pn -sT --reason --open <ip>` 

`nmap -p <ports> -Pn -sC -sV -oA nmap_default_scripts <ip>`

> Then you can run nmap automator! 

### Manual Port Probing
-----------------------------
`nc -nv <ip> <port>` 

`telnet <ip> <port>`

### Services 
-----------------------------

### Web Port 80
-----------------------------

`nikto -h "http://$IP" | tee nikto.log` 

`gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/small.txt -b 400,401,404,500 -x php,sh,txt,cgi,html,js,css`

`sudo nmap -p 80 -sC 192.168.120.108` 

### SMB 
-----------------------------
(Enumeration)[https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/] 

Get Domain   
`ldap -h 10.10.10.161 -x -s base namingcontexts` 

Get domain users 
`ldap -h 10.10.10.161 -x -b "DC=htb,DC=local" '(objectClass=Person)'` 

### SearchSploit Results
-----------------------------

## Exploitation 
-------------------------
Enter info about exploitation here
