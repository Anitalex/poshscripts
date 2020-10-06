Import-Module activedirectory
Install-Module MSOnline 

$VerbosePreference = 'Continue'


# connect to office 365
$password = ConvertTo-SecureString $passwd -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("$username", $password)
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell/ -Credential $creds -Authentication Basic –AllowRedirection
Import-PSSession $Session -AllowClobber

# Get user from office 365
$365users = Get-Mailbox -ResultSize Unlimited #| Select-Object DisplayName,PrimarySmtpAddress,EmailAddresses,Alias,UserPrincipalName

# find user in AD
foreach ($365user in $365users){
    $upn =  $365user.UserPrincipalName
    Write-Host $upn
    $filter = "proxyAddresses -like `"*SMTP:$upn*`""
    $aduser = get-aduser -filter $filter -Properties *
    
    if ($aduser){
        Write-Verbose "**** Setting properties for user $($365user.DisplayName)"
        # set proxy in AD equal to proxy 365 case sensitive
        Write-Verbose "set proxy in AD equal to proxy 365 case sensitive"
        $proxies = $365user.EmailAddresses
        foreach ($proxy in $proxies){
            if ($aduser.proxyAddresses -cmatch $proxy){
                Write-Verbose "The proxy address matched for $proxy"
            } else {
                Write-Verbose "Adding proxy $proxy to AD"
                Set-ADUser $aduser -Add @{ProxyAddresses = $proxy}
            }
        }

        # set Display name in 365 equal to AD with case sensitive
        Write-Verbose "**** set Display name in 365 equal to AD with case sensitive"
        if ($aduser.DisplayName -ceq $365user.DisplayName){
            Write-Verbose "Display names match for $($aduser.displayname)"
        }else{
            Write-Verbose "Setting the Display Name from $($365user.DisplayName) -ceq $($aduser.DisplayName)"
            Connect-MsolService -Credential $creds
            Set-MsolUser -UserPrincipalName $upn -DisplayName $($aduser.displayname)
        }

        # set upn in AD equal to 365 with case sensitivity
        Write-Verbose "**** set upn in AD equal to 365 with case sensitivity"
        if ($aduser.UserPrincipalName -ceq $365user.UserPrincipalName){
            Write-Verbose "UserPrincipalName match for $($aduser.UserPrincipalName)"
        }else{
            Write-Verbose "Setting the UPN $($aduser.UserPrincipalName) -ceq $($365user.UserPrincipalName)"
            Set-ADuser -Identity $aduser -UserPrincipalName $upn
        }

        # set mail property in AD equalt to the the default SMTP
        Write-Verbose "**** set mail property in AD equalt to the the default SMTP"
        foreach ($proxy in $proxies){
            if ($proxy -cmatch 'SMTP:'){
                $email = $proxy.split(":")[1]
                Write-Verbose "The default SMTP is $email"
                Set-ADuser -Identity $aduser -EmailAddress $email
            }
        }

    } else {
        Write-Verbose "User $($365user.DisplayName) was not found"
    }
}














