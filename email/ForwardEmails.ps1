$VerbosePreference = 'continue'

Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null

$olFolders = "Microsoft.Office.Interop.Outlook.OlDefaultFolders" -as [type]

$outlook = new-object -comobject outlook.application

$namespace = $outlook.GetNameSpace("MAPI")

$store = ($namespace.accounts.Session.stores | where {$_.displayname -match "cmccray@altuscio.com"}).storeid

$emails = (($namespace.GetStoreFromID($store).getrootFolder()).folders | where {$_.folderpath -match "archived"}).items | where {$_.to -match "Technical Team" -and $_.receivedtime -gt "7/1/2016"}

$count = $emails.count

$x = 1

foreach ($email in $emails) {
    Write-Verbose "Sending email $X of $count"
    $fwd = $email.Forward()
	$fwd.Recipients.Add("tstandard@altuscio.com")
	$fwd.Send()    
    $x++
}






