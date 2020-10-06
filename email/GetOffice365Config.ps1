#param($username,$password)
Start-Transcript -Path "C:\Windows\LTSvc\scripts\GetOffice365Config-Transcript.rtf" -Append -Force -NoClobber
$verbosepreference = "continue"
$output = 'C:\Office365'
#$pass = ConvertTo-SecureString -AsPlainText $password -Force

# ensure that the Office 365 module is installed
$msonline = Get-Module msonline
if ($msonline -eq $null){
    Save-Module -Name MSOnline -Path $output -Force
    Install-Module -Name MSOnline 
    Import-Module MsOnline
} else {
    Import-Module MsOnline
}

# Connect to Office 365
$credential = Get-Credential
#$credential = New-Object System.Management.Automation.PSCredential $username,$pass
Connect-MsolService -Credential $credential
$exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://outlook.office365.com/powershell-liveid/" -Credential $credential -Authentication "Basic" -AllowRedirection
Import-PSSession $exchangeSession -DisableNameChecking -AllowClobber

if(Test-Path $output){
} else {
    New-Item $output -ItemType directory -Force
}

###############################################################
#   Get Mailboxes and Output to CSV
###############################################################

# retrieve a list of mailboxes from the serve
$mailboxes = Get-Mailbox | select name,UserPrincipalName,PrimarySmtpAddress,DistinguishedName,IsValid,RecipientType,OrganizationalUnit,AccountDisabled
$mailboxes | Export-Csv "$output\UserAccounts.csv" -force -notypeinformation
# retrieve a total count of mailboxes
$count = $mailboxes.count
# output to the screen the count of mailboxes
Write-Verbose "There are $count mailboxes"

###############################################################
#   Get Mailbox Permissions and Output to CSV
###############################################################

# retrieve mailbox permissions and export to csv
Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | Where {$_.user -notlike "NT AUTHORITY\SELF" -and $_.IsInherited -eq $false} | 
    Select Identity,User,@{Name='Access Rights';Expression={[String]::join(‘, ‘, $_.AccessRights)}} | 
        Export-Csv $output\MailboxPermissions.csv -NoTypeInformation


###############################################################
#   Get Distribution Groups and Output to CSV
###############################################################

# retrieve a list of distribution groups from the server
$distgroups = Get-DistributionGroup
# retrieve a total count of distribution groups
$dgcount = $distgroups.count
# output to the screen the count of distribution groups
Write-Verbose "There are $dgcount distribution groups"

foreach ($dg in $distgroups) {
    $dgmembers = Get-DistributionGroupMember $dg.name
    foreach ($dgmember in $dgmembers) {
        $object = New-Object psobject
        $object | Add-Member –MemberType NoteProperty –Name Name –Value $dg.name
        $object | Add-Member –MemberType NoteProperty –Name PrimarySMTPAddress –Value $dg.PrimarySMTPAddress
        $object | Add-Member –MemberType NoteProperty –Name GroupType –Value $dg.grouptype
        $object | Add-Member –MemberType NoteProperty –Name Owner –Value $dg.ManagedBy.name
        $object | Add-Member –MemberType NoteProperty –Name UserDisplayName –Value $dgmember.DisplayName
        $object | Add-Member –MemberType NoteProperty –Name UserEmail –Value $dgmember.PrimarySMTPAddress
        $object | Add-Member –MemberType NoteProperty –Name UserType –Value $dgmember.RecipientType
        $object | Add-Member –MemberType NoteProperty –Name UserUPN –Value $dgmember.UserPrincipleName 
        $object | Export-Csv $output\DistributionGroups.csv -NoTypeInformation -Append
    }
}

Invoke-Item $output

Stop-Transcript