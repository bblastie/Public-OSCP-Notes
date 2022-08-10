#/bin/bash

ip='<TARGET-IP-HERE>'
shares=('C$' 'D$' 'ADMIN$' 'IPC$' 'PRINT$' 'FAX$' 'SYSVOL' 'NETLOGON')

for share in ${shares[*]}; do
    output=$(smbclient -U '%' -N \\\\$ip\\$share -c '') 

    if [[ -z $output ]]; then 
        echo "[+] creating a null session is possible for $share" # no output if command goes through, thus assuming that a session was created
    else
        echo $output # echo error message (e.g. NT_STATUS_ACCESS_DENIED or NT_STATUS_BAD_NETWORK_NAME)
    fi
done