$verbosepreference = 'continue'

#region Login 
    $login = Get-AzureRmContext
    if ($login.Account -eq $null){
        Write-Verbose "Logging in to Azure"
        Login-AzureRmAccount
    } else {
        Write-Verbose "Already Logged into Azure"
    }
    
#endregion

#region Create resource group
    
    $locname = "centralus"
    $rgname = "PowerShellVM"
    $rgs = Get-AzureRmResourceGroup
    if ($rgs -eq $null){
        Write-Verbose "Creating resource group named $rgname"
        New-AzureRmResourceGroup -Name $rgname -Location $locname
        Write-Verbose "Checking to see if resource group $rgname was created properly"
        $rgsValidate = Get-AzureRmResourceGroup
        foreach ($item in $rgsValidate){
            if ($item.ResourceGroupName -match $rgname){
                Write-Verbose "Resource group named $rgname was created properly!"
            } else {
                Write-Verbose "Resource group $rgname was not created!  Please validate manually"
            }
        }
    } else {
        foreach ($rg in $rgs){
            if ($rg.ResourceGroupName -match $rgname){
                Write-Verbose "Resource group named $rgname already exsits!"
            } else {
                Write-Verbose "Creating resource group named $rgname"
                New-AzureRmResourceGroup -Name $rgname -Location $locname
                Write-Verbose "Checking to see if resource group $rgname was created properly"
                $rgsValidate = Get-AzureRmResourceGroup
                foreach ($item in $rgsValidate){
                    if ($item.ResourceGroupName -match $rgname){
                        Write-Verbose "Resource group named $rgname was created properly!"
                    } else {
                        Write-Verbose "Resource group $rgname was not created!  Please validate manually"
                    }
                }
            }
        }
    }

#endregion

#region Create a storage account
    
    $resourcegroup = Get-AzureRmResourceGroup
    if ($resourcegroup.ResourceGroupName -eq $rgname){
        Write-Verbose "Creating Storage Account"
        $stname = "hscjhstore01"
        $SAavailable = Get-AzureRmStorageAccountNameAvailability $stname
        if ($SAavailable.NameAvailable -eq $true){
            Write-Verbose "Creating Storage Account $stname"
            $storageAcc = New-AzureRmStorageAccount -ResourceGroupName $rgname -Name $stname -SkuName "Standard_LRS" -Kind "Storage" -Location $locname
            $SAvalidate = Get-AzureRmStorageAccount
            if ($SAvalidate.StorageAccountName -eq $stname){
                Write-Verbose "The storage account was created"
            } else {
                Write-Verbose "The storage account $stname was not created"
            }
        } else {
            Write-Verbose $SAavailable.Message
            $storageAcc = Get-AzureRmStorageAccount -ResourceGroupName $rgname -Name $stname
        }
    } else {
        Write-Verbose "Cannot create storage account because the resource group does not exists"
    }

#endregion

#region Configuring Networking
    $resourcegroup = Get-AzureRmResourceGroup
    if ($resourcegroup -ne $null){
        Write-Verbose "Configuring Networking"
        $subnetname = "VMSubnet"
        $ipname = "VMIPAddress"
        $vnetname = "VMNetwork"
        $nicname = "VMNic"

        $singlesubnet = New-AzureRmVirtualNetworkSubnetConfig -Name $subnetname -AddressPrefix 10.0.0.0/24
        Write-Verbose "Checking for public IP"
        $publicIPs = Get-AzureRmPublicIpAddress
        $IPexists = $false
        foreach ($publicIP in $publicIPs){
            if ($publicIP.name -match $ipname){
                Write-Verbose "The public IP for $ipname has already been created"
                $IPexists = $true
            }
        }
        if ($IPexists -eq $false){
            Write-Verbose "Creating public IP $ipname"
            $pip = New-AzureRmPublicIpAddress -Name $ipname -ResourceGroupName $rgname -Location $locname -AllocationMethod Dynamic
        }

        Write-Verbose "Checking for virtual network"
        $vnets = Get-AzureRmVirtualNetwork
        $Vnetexists = $false
        foreach ($vnet in $vnets){
            if ($vnet.name -match $vnetname){
                Write-Verbose "The virtual network for $vnetname has already been created"
                $Vnetexists = $true
            }
        }
        if ($Vnetexists -eq $false){
            Write-Verbose "Creating virtual network $vnetname"
            $vnet = New-AzureRmVirtualNetwork -Name $vnetname -ResourceGroupName $rgname -Location $locname -AddressPrefix 10.0.0.0/16 -Subnet $singlesubnet
        }

        Write-Verbose "Checking for network interface"
        $netinterfaces = Get-AzureRmNetworkInterface
        $netinterfaceexists = $false
        foreach ($netinterface in $netinterfaces){
            if ($netinterface.name -match $nicname){
                Write-Verbose "The network interface $nicname has already been created"
                $netinterfaceexists = $true
            }
        }
        if ($netinterfaceexists -eq $false){
            Write-Verbose "Creating network interface $nicname"
            $nic = New-AzureRmNetworkInterface -Name $nicname -ResourceGroupName $rgname -Location $locname -SubnetId $vnet.Subnets[0].Id -PublicIpAddressId $pip.Id
        }
    } else {
        Write-Verbose "Cannot configure networking because the resource group is not there"
    }

#endregion

#region Configure the VM itself
    Write-Verbose "Checking to see if the VM has already been created"
    $vms = Get-AzureRmVM
    $vmname = "vmFS02"
    $compname = "FileServer02"
    foreach ($vm in $vms){
        if ($vm.Name -match $vmname){
            Write-Verbose "A VM with the name of $vmname already exists"
        } else {
            Write-Verbose "Configuring the VM"
            $cred = Get-Credential -Message "Type the name and password of the local administrator account"
            $vm = New-AzureRmVMConfig -VMName $vmname -VMSize "Standard_A1"
            $vm = Set-AzureRmVMOperatingSystem -vm $vm -Windows -ComputerName $compname -Credential $cred -ProvisionVMAgent -EnableAutoUpdate
            $vm = Set-AzureRmVMSourceImage -VM $vm -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus 2012-R2-Datacenter -Version "latest"
            $vm = Add-AzureRmVMNetworkInterface -VM $vm -Id $nic.Id

            Write-Verbose "Attaching Storage"
            $blobpath = "vhds/WindowsVMosDisk.vhd"
            $osDiskuri = $storageAcc.PrimaryEndpoints.Blob.ToString() + $blobpath
            $diskname = "windowsvmosdisk"
            $vm = Set-AzureRmVMOSDisk -VM $vm -Name $diskname -VhdUri $osDiskuri -CreateOption FromImage

            Write-Verbose "Deploying VM"
            New-AzureRmVM -ResourceGroupName $rgname -Location $locname -VM $vm

            Write-Verbose "Validating that the VM was created"
            $vmsvalidate = Get-AzureRmVM
            $exists = $false
            foreach ($item in $vmsvalidate){
                if ($item.name -match $vmname){
                    $exists = $true
                }
            }
            if ($exists -eq $true){
                Write-Verbose "A VM called $vmname exists"
            } else {
                Write-Verbose "A VM called $vmname was not created"
            }
        }
    }
#endregion