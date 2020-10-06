function Get-WindowsKey {
$hklm = 2147483650
$regPath = "Software\Microsoft\Windows NT\CurrentVersion\DefaultProductKey"
$regValue = "DigitalProductId"

$productKey = $null
$win32os = $null
$wmi = [WMIClass]"\\$target\root\default:stdRegProv"
$data = $wmi.GetBinaryValue($hklm,$regPath,$regValue)
$binArray = ($data.uValue)[52..66]
$charsArray = "B","C","D","F","G","H","J","K","M","P","Q","R","T","V","W","X","Y","2","3","4","6","7","8","9"
## decrypt base24 encoded binary data
For ($i = 24; $i -ge 0; $i--) {
    $k = 0
    For ($j = 14; $j -ge 0; $j--) {
        $k = $k * 256 -bxor $binArray[$j]
        $binArray[$j] = [math]::truncate($k / 24)
        $k = $k % 24
    }
    $productKey = $charsArray[$k] + $productKey
    If (($i % 5 -eq 0) -and ($i -ne 0)) {
        $productKey = "-" + $productKey
    }
}

return $productKey 
}


Get-WindowsKey






