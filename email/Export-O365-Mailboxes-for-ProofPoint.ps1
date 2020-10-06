Function Get-Folder($env:USERPROFILE)

{
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.rootfolder = "MyComputer"

    if($foldername.ShowDialog() -eq "OK")
    {
        $folder = $foldername.SelectedPath
    }
    return $folder
}

$folderpath = get-folder

$folderpath

out-default -InputObject $folderpath


$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session




$userString = ""
$users = Get-User | where-object {$_.RecipientTypeDetails -eq 'UserMailbox'} | Get-Mailbox


foreach ($user in $users){
    
    #$addresses = $user | select-object @{Name='EmailAddresses';Expression={$_.EmailAddresses |Where-Object {$_ -like "SMTP:*" -and $_ -notlike "*.onmicrosoft.com" }}}
    $addressline = ""
    foreach($address in $user.EmailAddresses){
        if($address -like "SMTP:*" -and $address -notlike "*.onmicrosoft.com" -and $user.PrimarySmtpAddress -notlike $address.Substring(5)){
            $addressline = $addressline + "," + $address.Substring(5)
        }
    }
    $useracc = $user | get-user
    
  $userString = $userString + $useracc.FirstName + "," + $useracc.LastName + "," + $user.PrimarySmtpAddress + $addressline + "`r`n"
    
}
Out-Default -InputObject $userstring
$userFile = $folderpath.GetValue(1) + "\ProofPoint-Users.csv"
out-file -Encoding "UTF8" -FilePath $userFile -InputObject $userString

$acctString = ""

$SharedAccounts = get-mailbox | Where-Object {$_.RecipientTypeDetails -eq 'SharedMailbox' -or $_.RecipientTypeDetails -eq 'RoomMailbox' -or $_.RecipientTypeDetails -eq 'ResourceMailbox'}


foreach ($acct in $SharedAccounts){
    
    #$addresses = $user | select-object @{Name='EmailAddresses';Expression={$_.EmailAddresses |Where-Object {$_ -like "SMTP:*" -and $_ -notlike "*.onmicrosoft.com" }}}
    $addressline = ""
    foreach($address in $acct.EmailAddresses){
        if($address -like "SMTP:*" -and $address -notlike "*.onmicrosoft.com" -and $acct.PrimarySmtpAddress -notlike $address.Substring(5)){
            $addressline = $addressline + "," + $address.Substring(5)
        }
    }
    
  $acctString = $acctString + $acct.DisplayName + "," + $acct.PrimarySmtpAddress + $addressline + "`r`n"
    
}


$distroGroups = Get-DistributionGroup
foreach ($group in $distroGroups){
    
    #$addresses = $user | select-object @{Name='EmailAddresses';Expression={$_.EmailAddresses |Where-Object {$_ -like "SMTP:*" -and $_ -notlike "*.onmicrosoft.com" }}}
    $addressline = ""
    foreach($address in $group.EmailAddresses){
        if($address -like "SMTP:*" -and $address -notlike "*.onmicrosoft.com" -and $group.PrimarySmtpAddress -notlike $address.Substring(5)){
            $addressline = $addressline + "," + $address.Substring(5)
        }
    }
    
  $acctString = $acctString + $group.DisplayName + "," + $group.PrimarySmtpAddress + $addressline + "`r`n"
    
}

Out-Default -InputObject $acctString
$acctFile = $folderpath.GetValue(1) + "\ProofPoint-Functional-Accounts.csv"
out-file -Encoding "UTF8" -FilePath $acctFile -InputObject $acctString




Remove-PSSession $Session

