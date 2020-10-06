$verbosepreference = "continue"
$output = 'C:\temp'


# creating a hash table to store the version numbers
# of Exchange so we can determine what PSSnapin to load

Write-Verbose "Creating a hash table to store the version numbers of Exchange so we can determine what PSSnapin to load"
$versions = @{
"Microsoft Exchange Server 2003" = "6.5.6944";
"Microsoft Exchange Server 2003 SP1" = "6.5.7226";
"Microsoft Exchange Server 2003 SP2" = "6.5.7638";
"Microsoft Exchange Server 2003 SP2 March 2008 update" = "6.5.7653.33";
"Microsoft Exchange Server 2003 SP2 August 2008 update" = "6.5.7654.4";
"Microsoft Exchange Server 2007" = "8.0.685.24";
"Microsoft Exchange Server 2007 " = "8.0.685.25";
"Microsoft Exchange Server 2007 SP1" = "8.1.240.006";
"Microsoft Exchange Server 2007 SP2" = "8.2.176.002";
"Microsoft Exchange Server 2007 SP3" = "8.3.83.006";
"Microsoft Exchange Server 2010" = "14.0.639.21";
"Microsoft Exchange Server 2010 SP1" = "14.1.218.15";
"Microsoft Exchange Server 2010 SP2" = "14.2.247.5";
"Microsoft Exchange Server 2010 SP3" = "14.3.123.4";
"Microsoft Exchange Server 2013" = "15.0.516.032";
"Microsoft Exchange Server 2016" = "15.1.669.32"
}

# retrieve the version of Exchange that is installed
Write-Verbose "Retrieving the version of Exchange that is installed"
$installver = (get-wmiobject win32_product | where {$_.name -match "exchange server" -and $_.name -notmatch "Language Pack"}).version
$installname = ($versions.GetEnumerator() | Where {$_.value -eq $installver}).name

# load the PSSnapin for the particular version of Exchange
Write-Verbose "Loading the PSSnapin for the particular version of Exchange"
if ($installname -match "2007"){
    Write-Verbose "Loading the PSSnapin for Exchange 2007"
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
}elseif ($installname -match "2010") {
    Write-Verbose "Loading the PSSnapin for Exchange 2010"
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010
}elseif ($installname -match "2013") {
    Write-Verbose "Loading the PSSnapin for Exchange 2013"
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
}elseif ($installname -match "2016") {
    Write-Verbose "Loading the PSSnapin for Exchange 2016"
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
}else {
    Write-Verbose "Exchange did not match 2007, 2010, 2013, or 2016"
}

# retrieve a list of Exchange Servers and output to screen
Write-Verbose "Retrieve a list of Exchange Servers and output to screen"
$exc = Get-ExchangeServer
foreach ($item in $exc){
    $excname = $item.name
    Write-Verbose "There is an Exchange Server named $excname"
}

###############################################################
#   Get Mailboxes and Output to CSV
###############################################################

# retrieve a list of mailboxes from the server
Write-Verbose "Retrieving a list of mailboxes from the server"
$mailboxes = Get-Mailbox | select name,SamAccountName,PrimarySmtpAddress,UserPrincipalName,DistinguishedName,IsValid,RecipientType,OrganizationalUnit,AccountDisabled
$mailboxes | Export-Csv "$output\UserAccounts.csv" -force -notypeinformation
# retrieve a total count of mailboxes
Write-Verbose "Retrieving a total count of mailboxes"
$count = $mailboxes.count
# output to the screen the count of mailboxes
Write-Verbose "There are $count mailboxes"

###############################################################
#   Get Mailbox Permissions and Output to CSV
###############################################################

# retrieve mailbox permissions and export to csv
Write-Verbose "Retrieving mailbox permissions and export to csv"
Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | Where {$_.user -notlike "NT AUTHORITY\SELF" -and $_.IsInherited -eq $false} | 
    Select Identity,User,@{Name='Access Rights';Expression={[String]::join(‘, ‘, $_.AccessRights)}} | 
        Export-Csv $output\MailboxPermissions.csv -NoTypeInformation


###############################################################
#   Get Distribution Groups and Output to CSV
###############################################################

# retrieve a list of distribution groups from the server
Write-Verbose "Retrieving a list of distribution groups from the server"
$distgroups = Get-DistributionGroup
# retrieve a total count of distribution groups
Write-Verbose "Retrieving a total count of distribution groups"
$dgcount = $distgroups.count
# output to the screen the count of distribution groups
Write-Verbose "There are $dgcount distribution groups"

foreach ($dg in $distgroups) {
    $dgmembers = Get-DistributionGroupMember $dg
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
        $object | convertto-Csv -NoTypeInformation | out-file $output\DistributionGroups.csv -append
    }
}

