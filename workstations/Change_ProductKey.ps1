$VerbosePreference = "Continue"
$machine_name = Get-Content env:computername
#########################################
#
#   Functions
#
#########################################

function Get-WindowsKey {
    param ($targets = ".")
    $hklm = 2147483650
    $regPath = "Software\Microsoft\Windows NT\CurrentVersion\DefaultProductKey"
    $regValue = "DigitalProductId"
    Foreach ($target in $targets) {
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
        $win32os = Get-WmiObject Win32_OperatingSystem -computer $target
        $obj = New-Object Object
        $obj | Add-Member Noteproperty Computer -value $target
        $obj | Add-Member Noteproperty Caption -value $win32os.Caption
        $obj | Add-Member Noteproperty CSDVersion -value $win32os.CSDVersion
        $obj | Add-Member Noteproperty OSArch -value $win32os.OSArchitecture
        $obj | Add-Member Noteproperty BuildNumber -value $win32os.BuildNumber
        $obj | Add-Member Noteproperty RegisteredTo -value $win32os.RegisteredUser
        $obj | Add-Member Noteproperty ProductID -value $win32os.SerialNumber
        $obj | Add-Member Noteproperty ProductKey -value $productkey
        $obj
        

    }
}

#########################################
#
#   Get the current Key
#
#########################################

$licenseinfo = Get-WindowsKey
$currentkey = $licenseinfo.productkey

Write-Verbose "The current key is $currentkey"

#########################################
#
#   Import CSV and change Key
#
#########################################

$LicenseKeys = Import-Csv 'C:\management\License\LicenseKey.csv'

foreach($item in $LicenseKeys)
    {
    $server = $item.server
    $key = $item.key
    if($machine_name -eq $server)
        {
        Write-Verbose "Changing the key to $key"
        & cscript.exe 'C:\management\License\ChangeVLKeySP1.vbs' $key
        }
    else
        {
        Write-Verbose "$machine_name was not on the list"
        }
    } 

#########################################
#
#   Get the new key
#
#########################################

$newlicenseinfo = Get-WindowsKey
$newkey = $newlicenseinfo.productkey
Write-Verbose "The key after changing is $newkey"


