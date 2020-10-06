# import the Active Directory module to get the cmdlets
Import-Module activedirectory
Install-Module MSOnline 

# set verbose preference for the Write-Verbose cmdlet
$VerbosePreference = 'Continue'
$username = ''
$passwd = ''

# connect to office 365
$password = ConvertTo-SecureString $passwd -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("$username", $password)
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell/ -Credential $creds -Authentication Basic –AllowRedirection
Import-PSSession $Session -AllowClobber
Connect-MsolService -Credential $creds

# get the the list of OUs from the root SBSUsers OU
$DLOU = Get-ADOrganizationalUnit -Identity 'OU=Distro Groups,OU=SBSUsers,OU=Users,OU=MyBusiness,DC=W3,DC=local'
$users = Get-Aduser -filter * -Properties * -SearchBase $DLOU -SearchScope OneLevel

# loop through each user
foreach ($user in $users){
    Write-Verbose "Checking to see if the group $($user.name) was created "
    $dl = Get-UnifiedGroup "$($user.name)"
    if ($dl -eq $null){
        Write-Verbose "Group $($user.name) did not exist, creating now......"
        $365user = (Get-MsolUser | Where {$_.DisplayName -match "$($user.DisplayName)"}).UserPrincipalName
        $365display = (Get-MsolUser | Where {$_.DisplayName -match "$($user.DisplayName)"}).DisplayName
        Write-Host "$($user.name)"
        Write-Verbose "Creating group named $($user.name)...."
        New-UnifiedGroup "$($user.name)" -DisplayName "$($user.name)" -PrimarySmtpAddress $($user.EmailAddress) -Owner $365display
        Write-Verbose "Checking to see if the group was created "
        $dlcheck = Get-UnifiedGroup "$($user.name)"
        if ($dlcheck -ne $null){
            Write-Verbose "Adding member $365user to group $($user.name)"
            Add-UnifiedGroupLinks -Identity "$($user.name)" -LinkType Members -Links $365user
            $365user = (Get-UnifiedGroupLinks -Identity $dlcheck.DisplayName -LinkType Members).PrimarySmtpAddress
            Set-UnifiedGroup -GrantSendOnBehalfTo $365user
            Write-Verbose "Checking for the list of proxy addresses for $($user.name)"
            $proxies = $user.proxyaddresses | where {$_ -notmatch 'w3.local'}
            $proxies
            foreach ($proxy in $proxies){
                $proxy = $proxy.split(":")[1]
                Write-Verbose "$proxy"
                Set-UnifiedGroup "$($user.name)" -emailaddresses @{Add=$proxy}
            }
        }
    } else {
        Write-Host "A group named $($user.name) exists "
    }
}


