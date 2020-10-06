$xml = Get-Content C:\ts.xml
[xml]$ts = $xml

$installs =  $ts.sequence.group.group | where name -match "Install Applications and Updates"
$reader = $installs.step | Where name -match "Install Adobe Flash Plugin"
$installs.removechild($reader)
$ts.save("c:\ts.xml")