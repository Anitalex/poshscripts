$verbosepreference = "SilentlyContinue"
$module = 'C:\Office365'
$users = Import-CSV "C:\user.csv"
$output = "C:\ResultsPPAccountsNotIn365.txt"

<#
The first thing you have to do is log into Proofpoint and export the users to csv
Then change the location on line 3 to where you stored that csv
Then you can change the location of line 4 to where you want to store the results file
The results file will be a list of emails that are not found on the Office 365 account as a user, DL, or Shared Mailbox

#>


# ensure that the Office 365 module is installed
$msonline = Get-Module msonline
if ($msonline -eq $null){
    Save-Module -Name MSOnline -Path $module -Force
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

# check to see if users are in Office 365
foreach ($user in $users){
    $email = $user.email
    if((Get-MsolUser -UserPrincipalName $email).IsLicensed){
    } else {
        $dl = Get-MsolGroup | where {$_.emailaddress -match $email}
        if ($dl -ne $null){
            
        } else {
            $smb = Get-Mailbox -Filter '(RecipientTypeDetails -eq "SharedMailbox")' -Identity $email
            if ($smb -ne $null){

            } else {
                $email | Out-File $output -Append
            }
        }
    }    
}

$result = Get-Content $output
$result.count
