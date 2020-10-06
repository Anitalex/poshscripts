Start-Transcript -Path "C:\leapfrog_management\builds\Default_Build_Transcript.txt" -append -NoClobber

###############################################################################################
#
#        Recovery Partition script for Leapfrog Services Deployments
#        Created by Carlos McCray and Richard Mead
#        Last Update 4/13/2012
#
###############################################################################################

$VerbosePreference = "Continue"
$machine_name = gc env:computername
$OperatingSystem = (get-wmiobject win32_operatingsystem).caption
$OSArchitecture = (get-wmiobject win32_operatingsystem).OSArchitecture


#################################################################################################
#
#      Determine if the drive has enough free space
#
#
################################################################################################

$vol = Get-WmiObject win32_volume
$sysroot = ($env:systemroot).remove(3)

foreach ($item in $vol)
    {
    if ($item.caption -eq $sysroot)
        {
        $percentfree = [math]::truncate(($($item.freespace)/$($item.capacity))*100)
        Write-Host "$percentfree `%"
        $sysvol = $item
        $syscap = [math]::truncate($sysvol.capacity / 1gb)
        $sysfree = [math]::truncate($sysvol.freespace / 1gb)
        Write-Host "Capacity is $syscap Gbs"
        Write-Host "Free space is $sysfree Gbs"
        if ($sysfree -le "25" -and $percentfree -le "20")
            {
            Write-Verbose "There is NOT enough free space"
            $drivestatus = $false
            }
        else
            {
            Write-Verbose "There is enough free space"
            $drivestatus = $true
            }
        }
    }

if ($drivestatus -eq $false)
    {
    Write-Verbose "Ending script as there is mot enough free space"
    }
else
    {
    $partitions = "sel disk 0","list par" | diskpart
    [string]$partition = $partitions -match $syscap
    $part = $partition.Split(" ")[3]
    $part


    #################################################################################################
    #
    #      Diskpart Scripts                                            303859494912
    #
    #
    ################################################################################################


    $parttext = @"
    Select disk 0
    select partition $part
    shrink desired = 15360
    create partition primary
    format fs=ntfs label="Recovery" Quick
    assign letter = r
    exit
"@

    if(Test-Path "C:\leapfrog_management\builds\parttext.txt")
        {
        Write-Verbose "parttext.txt has aleady been created."
        }
    else
        {
        Write-Verbose "Creating parttext.txt."
        New-Item -Path "C:\leapfrog_management\builds\parttext.txt" -ItemType file
        Set-Content -Path "C:\leapfrog_management\builds\parttext.txt" -Value $parttext
        }



    $hidetext = @"
    Select disk 0
    select partition $part
    remove letter = r
    set id 27 override
    exit
"@

    if(Test-Path "C:\leapfrog_management\builds\hidetext.txt")
        {
        Write-Verbose "hidetext.txt has aleady been created."
        }
    else
        {
        Write-Verbose "Creating hidetext.txt."
        New-Item -Path "C:\leapfrog_management\builds\hidetext.txt" -ItemType file
        Set-Content -Path "C:\leapfrog_management\builds\hidetext.txt" -Value $hidetext
        }

    #################################################################################################
    #
    #      Shrink the current drive and create recovery partition
    #
    #
    ################################################################################################

    DISKPART /S "C:\leapfrog_management\builds\parttext.txt"

    #################################################################################################
    #
    #      Setup Recovery folders
    #
    #
    ################################################################################################

    New-Item "R:\Recovery\WindowsRE" -ItemType directory

    #################################################################################################
    #
    #      REAgentC commands
    #
    #
    ################################################################################################

    $recimage = "c:\windows\system32\reagentc.exe /setosimage /path r:\recovery\windowsre /target c:\windows"
    $REEnable = "c:\windows\system32\reagentc.exe /enable"

    Invoke-Expression $recimage
    Invoke-Expression $REEnable

    #################################################################################################
    #
    #      Hide the recovery partition
    #
    #
    ################################################################################################

    DISKPART /S "C:\leapfrog_management\builds\hidetext.txt"

    #################################################################################################
    #
    #      Cleanup after script
    #
    #
    ################################################################################################


    Write-Verbose "The build script ended successfully"
    }

    Stop-Transcript

    #################################################################################################
    #
    #      End Script
    #
    #
    ################################################################################################ 

Get-Process | Where {$_.processname -match "cmd"} | Stop-Process

  
