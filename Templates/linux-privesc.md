
## Privilege Escalation
---------------------------------------------
### Final solution

**Step 1** Review PrivEsc Mind map
https://raw.githubusercontent.com/hxhBrofessor/PrivEsc-MindMap/main/Linux-Privesc.JPG

**Step 2** Look around the file system!!! 

**Step 3** Run (linpeas)[https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS]

### Information Gathering 
(Password Attacks)[https://medium.com/@kuwaitison/local-password-attack-and-credentials-theft-for-windows-linux-5764a1a25363]

### Sudo list
`sudo -l`

### List of users​ Linux 
`cat /etc/passwd | cut -d: -f1`    

#### List of super users Linux 
`grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'`        

Check for files with SUID bit set and then check gtfobins
# Sticky bit
`find / -perm -1000 -type d 2>/dev/null`   

```
/dev/mqueue
/dev/shm
/var/spool/cron/crontabs
/var/tmp
/var/lib/php/sessions
/sys/fs/bpf
/tmp
/run/lock
``` 

# SUID bit 
`find / -perm -u=s -type f 2>/dev/null` 

```
/usr/bin/su
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/gpasswd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
``` 

# SGID Bit 
`find / -perm -g=s -type f 2>/dev/null` 

```
/usr/sbin/unix_chkpwd
/usr/bin/wall
/usr/bin/chage
/usr/bin/status
/usr/bin/bsd-write
/usr/bin/ssh-agent
/usr/bin/expiry
/usr/bin/dotlockfile
/usr/bin/crontab
``` 

### Information Gathering (OS and Kernel)

`cat /etc/issue`

`cat /etc/*-release`

`cat /etc/lsb-release`

`cat /proc/version`

`uname -mrs`

### Information Gathering (Running Processes)

### grep for a string in a dir of files
`grep -ls 'pass' ${PWD}/* `

`ps aux | grep root`

`ps -ef | grep root`

`cat /etc/services `

### Information Gathering (Installed Packages and Programs)

`ls -alh /usr/bin/`

`ls -alh /sbin/`

`dpkg -l`

`rpm -qa`

`ls -alh /var/cache/apt/archivesO`

`ls -alh /var/cache/yum/`

## Tools to run

(linux-smart-enumeration)[https://github.com/diego-treitos/linux-smart-enumeration] 
(process snooper)[https://github.com/DominicBreuker/pspy] 
(linux exploit suggester)[https://github.com/jondonas/linux-exploit-suggester-2]
