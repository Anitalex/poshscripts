sl hklm:
cd "software\microsoft\security center"
Set-ItemProperty . -name AntiVirusDisableNotify -value "00000001"
Set-ItemProperty . -name FirewallDisableNotify -value "00000001"
Set-ItemProperty . -name UpdatesDisableNotify -value "00000001"

$firewall = New-Object -com HNetCfg.FwMgr
$firewall.LocalPolicy.CurrentProfile.FirewallEnabled = $false