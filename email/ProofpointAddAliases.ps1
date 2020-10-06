$url = 'https://us1.proofpointessentials.com'

###############################################################################
#     Open an IE browser window and navigate to vo.leapfrogservices.com

$ie = New-Object -ComObject InternetExplorer.Application
$ie.Navigate2($url)
$ie.Visible = $true
while ($ie.Busy -eq $true) {Start-Sleep -Milliseconds 10000 }
$ie.Document.getElementsByName("email")[0].value = 'spamadmin@w3-llc.com'
$ie.Document.getElementsByName("password")[0].value = 'Pr0v1dyn!!W3LLC'
$ie.Document.getElementsByTagName("input")[2].click()
while ($ie.Busy -eq $true) {Start-Sleep -Milliseconds 10000 }

$ie.Document.getElementById("main-nav_users-and-groups").click()
while ($ie.Busy -eq $true) {Start-Sleep -Milliseconds 10000 }

$links = $ie.Document.getElementsByTagName("a")