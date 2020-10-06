 function Disable-NicPower { 
        [CmdletBinding()]
                param ()
        BEGIN {}
        PROCESS {
                Write-Verbose "Disabling NIC Power"  
                $namespace = "root\WMI"
                $computer = "localhost"
                    Get-WmiObject Win32_NetworkAdapter -filter "AdapterTypeId=0" | 
                    Foreach-Object {
                        $strNetworkAdapterID=$_.PNPDeviceID.ToUpper()
                        Get-WmiObject -class MSPower_DeviceEnable -computername $computer -Namespace $namespace | 
                            Foreach-Object {
                            if($_.InstanceName.ToUpper().startsWith($strNetworkAdapterID))
                                {
                                if($_.Enable = $true)
                                    {
                                    $_.Enable = $false
                                    $_.Put() | Out-Null
                                    }
                                    else
                                    {
                                    }
                        
                                }
                            }
                    }
                }
        END {}
        }

Disable-NicPower












