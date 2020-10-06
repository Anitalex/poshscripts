$verbosepreference = "continue"
$output = 'C:\Office365'
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

$groups = Get-UnifiedGroup | where name -match ""
foreach ($group in $groups){
    $aliases = $group.EmailAddresses
    $primary = $group.PrimarySmtpAddress
    $name = $group.ID.Split("_")[0]
    $owner = $group.GrantSendOnBehalfTo[0]
    $members = $group | Get-UnifiedGroupLinks -linktype Members
    Remove-UnifiedGroup $group.name
    start-sleep 30
    New-DistributionGroup -PrimarySmtpAddress $primary -Name $name -DisplayName $name
    Get-DistributionGroup -identity $name | Set-DistributionGroup -RequireSenderAuthenticationEnabled $False -ManagedBy $(get-mailbox $owner).PrimarySmtpAddress
    Get-DistributionGroup -identity $name | Set-DistributionGroup -emailaddresses $group.emailaddresses
    foreach ($member in $members){
        Add-DistributionGroupMember $name -Member $member.PrimarySmtpAddress
    }
}



