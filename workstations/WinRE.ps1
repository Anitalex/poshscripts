$image = read-host

$net = New-Object -ComObject WScript.Network
$net.MapNetworkDrive( "Z:", "\\192.168.30.205\deploymentshare$", "$true", "br\tech", "Lfs123!" )

new-item r:\recovery\windowsre -type directory

copy-item z:\captures\$image r:\recovery\windowsre\

$commandline = "c:\windows\system32\reagentc.exe /setosimage /path r:\recovery\windowsre /target c:\windows"

Invoke-Expression $commandline

$acl = Get-Acl r:\recovery
$directory = "r:\recovery"
$isProtected = $true
$preserveInheritance = $true
$acl.SetAccessRuleProtection($isProtected, $preserveInheritance)
Set-Acl -Path $directory -AclObject $acl 

$permission2 = "Authenticated Users","FullControl","Allow"
$accessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule $permission2
$acl.RemoveAccessRuleAll($accessRule2)
$acl | Set-Acl r:\recovery

$permission = "sage","FullControl","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
$acl | Set-Acl e:\recovery

$permission1 = "Administrators","FullControl","Allow"
$accessRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule $permission1
$acl.RemoveAccessRuleAll($accessRule1)
$acl | Set-Acl r:\recovery

Remove-Item -Path hklm:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -recurse
