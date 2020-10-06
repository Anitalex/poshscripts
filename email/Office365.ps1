$verbosepreference = "continue"
$csvs = 'C:\Sync\Scripts\Office365Script'


##############################################
#  Functions
##############################################

function SetPSEnvEXC{
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
    "Microsoft Exchange Server 2013" = "15.0.516.032";
    "Microsoft Exchange Server 2016" = "15.1.669.32"
    }

    $installver = (get-wmiobject win32_product | where {$_.name -match "exchange server" -and $_.name -notmatch "Language Pack"}).version
    $installname = ($versions.GetEnumerator() | Where {$_.value -eq $installver}).name

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

}

function SetPSEnv365 {
    #Connect to Office 365
    $credential = Get-Credential
    Import-Module MsOnline
    Connect-MsolService -Credential $credential
    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://outlook.office365.com/powershell-liveid/" -Credential $credential -Authentication "Basic" -AllowRedirection
    Import-PSSession $exchangeSession -DisableNameChecking

}

$folders = 'C:\Sync\Scripts\Altuscio Scripts\Office365Script'

function ImportCSVs {
    param($folders)
    foreach ($folder in $folders){
        $items = Get-ChildItem $folder | where {$_.name -match '.csv'}
        foreach ($item in $items){
            $name = $item.BaseName
            $path = $item.FullName
            $csv = Import-CSV $path
            New-Variable -name $name -value $csv
        }
    }
}

##############################################
#  Code Execution
##############################################

$mailboxes = Get-Mailbox
$count = $mailboxes.count

foreach ($mailbox in $mailboxes){
    $upn = $mailbox.UserPrincipalName
    $dn = $mailbox.DistinguishedName
    $name = $mailbox.Name
    $isvalid = $mailbox.IsValid
    $email = $mailbox.PrimarySmtpAddress
    $type = $mailbox.RecipientType
    $emails = $mailbox.EmailAddresses
    $ou = $mailbox.OrganizationalUnit
    $disabled = $mailbox.AccountDisabled
}


ImportCSVs $csvs


