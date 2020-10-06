param ($to = "support@email.net",$machine_name,$groupName,$dc)
$poshversion = $PSVersionTable.psversion.Major
$outputfile = 'c:\leapfrog_mm
#########################################################
#   variables for kaseya testing

#$to = "carlos.mccray@email.net"
#$machine_name = $env:computername
#$groupName = "test"
#$dc = 4

##########################################################
#   Functions

function Get-LocalAdmin {
    $members = invoke-command {
        net localgroup administrators | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4
    }
    foreach ($item in $members) {
        New-Object PSObject -Property @{
            Computername = $env:COMPUTERNAME
            Group = "BUILTIN\Administrators"
            Members=$item
        }

     }
}

function Get-DomainAdmin {
    $members = (Get-ADGroupMember "Domain Admins") | select name
    foreach ($item in $members) {
        New-Object PSObject -Property @{
            Computername = $env:COMPUTERNAME
            Group = "Domain\Administrators"
            Members=$item.name
        }

    }
}

function Get-EnterpriseAdmin {
    $members = (Get-ADGroupMember "Enterprise Admins") | select name
    foreach ($item in $members) {
        New-Object PSObject -Property @{
            Computername = $env:COMPUTERNAME
            Group = "Enterprise\Administrators"
            Members=$item.name
        }

    }
}

function Get-SchemaAdmin {
    $members = (Get-ADGroupMember "Schema Admins") | select name
    foreach ($item in $members) {
        New-Object PSObject -Property @{
            Computername = $env:COMPUTERNAME
            Group = "Schema\Administrators"
            Members=$item.name
        }

    }
}

###########################################################################
#   Getting the results

$localadmins = Get-LocalAdmin

if ($dc -eq 4) {
    Import-Module activedirectory
    $domainadmins = Get-DomainAdmin
    $enterpriseadmins = Get-EnterpriseAdmin
    $schemaadmins = Get-SchemaAdmin
}

###########################################################################
#   Outputting the results

if ($poshversion -ge 3) {
    $localadmins | Export-Csv $outputfile -Append -NoTypeInformation
    if ($domainadmins -ne $null) {
        $domainadmins | Export-Csv $outputfile -Append -NoTypeInformation
    }
    if ($domainadmins -ne $null) {
        $enterpriseadmins | Export-Csv $outputfile -Append -NoTypeInformation
    }
    if ($domainadmins -ne $null) {
        $schemaadmins | Export-Csv $outputfile -Append -NoTypeInformation
    }
} else {
    $localadmins | ConvertTo-Csv -NoTypeInformation | Foreach-Object {$_ -replace '"',''} | Select-Object -Skip 1 | Out-File -Append -FilePath $outputfile
    if ($domainadmins -ne $null) {
        $domainadmins | ConvertTo-Csv -NoTypeInformation | Foreach-Object {$_ -replace '"',''} | Select-Object -Skip 1 | Out-File -Append -FilePath $outputfile
    }
    if ($domainadmins -ne $null) {
        $enterpriseadmins | ConvertTo-Csv -NoTypeInformation | Foreach-Object {$_ -replace '"',''} | Select-Object -Skip 1 | Out-File -Append -FilePath $outputfile
    }
    if ($domainadmins -ne $null) {
        $schemaadmins | ConvertTo-Csv -NoTypeInformation | Foreach-Object {$_ -replace '"',''} | Select-Object -Skip 1 | Out-File -Append -FilePath $outputfile
    }
}

###########################################################################
#   Emailing the results

$from = "Group Members <support@email.net>"
$subj = "Administrators Audit -- $groupName -- "
$body = "
    See the attached document for Full Control output of shares.
    
    Machine Name: $machine_name
    Kaseya Group: $groupName
           

    "
$attachment = $outputfile
$smtpsvr = "yoursmtpserver.net"

Send-MailMessage -from $from -to $to -subject $subj -body $body -smtpserver $smtpsvr -attachments $attachment -priority high



