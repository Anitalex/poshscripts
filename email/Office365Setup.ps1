<#
$username =
$pswd =
#>

$folderPath = 'C:\Office365'
$newaccts = 'C:\Office365\NewAccounts.csv'

#Connect to Office 365
$credential = Get-Credential
Import-Module MsOnline
Connect-MsolService -Credential $credential
$exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://outlook.office365.com/powershell-liveid/" -Credential $credential -Authentication "Basic" -AllowRedirection
Import-PSSession $exchangeSession -DisableNameChecking

#Show Office Licenses
Get-MsolAccountSku | select accountskuid, activeunits | out-file $newaccts -append

Read-Host "Copy the account SKUID to the appropriate user in $newaccts"

#Enable impersonation for Office 365 Administrator Account
$Office365Admin = Read-Host "Office 365 Adminstrator Email Address?"
Enable-OrganizationCustomization
New-ManagementRoleAssignment -Role "ApplicationImpersonation" -User $Office365Admin

<#
Ask for domainname input
Add Domain to Office 365
Displays information for DNS TXT Record that needs to be created to verify domain name
#>
$domainname = Read-Host "Primary Domain Name?"
New-MsolDomain -Authentication Managed -Name $domainname
Get-MsolDomainVerificationDns -DomainName $domainname -Mode DnsTxtRecord

<#Do Until loop
- Pause Script for 5 minutes
- Confirm Domain Name
- Get Domain and Status
- Will continue to do this until status=Verified
#>
Do{

#Pause Script for 5 minutes
Start-Sleep -Seconds 300

#Confirm Domain Name
Confirm-MsolDomain -DomainName $domainname

#Get Domain Names
$var=Get-MsolDomain -DomainName $domainname
    $name=$var.Name
    $status=$var.Status
    }
Until ($status-eq"Verified")
Echo "Verified Continuing Script"

#Set domain name as default
Set-MsolDomain -Name $domainname -IsDefault

#Create users from CSV file
Import-Csv -Path "C:\Office365\NewAccounts.csv" | foreach {New-MsolUser -DisplayName $_.DisplayName -FirstName $_.FirstName -LastName $_.LastName -UserPrincipalName $_.UserPrincipalName -UsageLocation $_.UsageLocation -LicenseAssignment $_.AccountSkuId} | Export-Csv -Path "C:\Office365\NewAccountResults.csv"

#Set all users password to never expire
Get-MSOLUser | Set-MsolUser -PasswordNeverExpires $true

#Pause Script for 45 Minutes
Start-Sleep -Seconds 2700

#Create distribution groups from CSV
Import-CSV -Path "C:\Office365\NewDistributionGroups.csv" | foreach {New-DistributionGroup -Name $_.name -DisplayName $_.displayname -Type $_.type -PrimarySMTPAddress $_.primarysmtpaddress} | Export-Csv -Path "C:\Office365\NewDistributionGroupsResults.csv"

#Add members to distribution groups
Import-CSV -Path "C:\Office365\DGMembers.csv" | foreach {Add-DistributionGroupMember -Identity $_.GroupName -Member $_.UPN}

#Enable external sender to send email to all distribution groups
Get-DistributionGroup | Set-DistributionGroup -RequireSenderAuthenticationEnabled $False


#Create shared mailboxes from CSV
Import-CSV -Path "C:\Office365\SharedMailboxes.csv" | foreach {New-Mailbox -Shared -Name $_.name -DisplayName $_.displayname -Alias $_.alias -PrimarySmtpAddress $_.emailaddress}

#Add shared mailbox permission
Import-CSV -Path "C:\Office365\SMPermissions.csv" | foreach {Add-MailboxPermission -Identity $_.sharedmailboxalias -User $_.user -AccessRights $_.accessrights}

#Add Additional Domain Names
Do{
$AddDomain = Read-Host "Are there Additional Domains? (Enter y or yes or n or no)"
    if($AddDomain -eq 'y' -or $AddDomain -eq 'yes'){
        $adddomainname = Read-Host "Domain Name?"
        New-MsolDomain -Authentication Managed -Name $adddomainname
        Get-MsolDomainVerificationDns -DomainName $adddomainname -Mode DnsTxtRecord
        Do{
            #Pause Script for 5 minutes
            Start-Sleep -Seconds 300

            #Confirm Domain Name
            Confirm-MsolDomain -DomainName $domainname

            #Get Domain Names
            $var=Get-MsolDomain -DomainName $domainname
                $name=$var.Name
                $status=$var.Status
                }
            Until ($status-eq"Verified")}
    elseif($AddDomain -eq ''){
        $AddDomain = Read-Host "Please enter a valid response (Enter y or yes or n or no)"}}
Until($AddDomain -eq 'n' -or 'no')

        
# Add Email Address Alias
Import-CSV "C:\Office365\AddEmailAddressAlias.csv" | ForEach {Set-Mailbox $_.Mailbox -EmailAddresses @{add=$_.NewEmailAddress}}

#Setup email forwarding
Import-CSV "C:\Office365\emailforwarding.csv" | ForEach {Set-Mailbox $_.Mailbox -ForwardingAddress $_.ForwardingAddress -DeliverToMailboxAndForward $true}

# Add Calendar Permissions
Import-CSV "C:\Office365\CalendarPermissions.csv" | ForEach {Add-MailboxFolderPermission -Identity $_.Identity -User $_.User -AccessRights $_.AccessRights} 


#Disconnect from Office 365
Remove-PSSession $exchangeSession