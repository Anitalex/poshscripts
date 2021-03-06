#############################################################
#      Script to remove OEM Preinstalled Software
#############################################################

$verbosePreference = 'Continue'


$machine_name = gc env:computername
$htmlfile = "C:\Uninstall_$machine_name.html"
        $Uninstall_header = "
        <html>
        <head>
            <style type=`"text/css`">
            .good {color:green;}
            .bad {color:red;}
            </style>
            <title>Uninstall Report for [$machine_name]</title>
        </head>
        <body>
        <h2 align=center>Uninstall Report for [$machine_name]</h2>
        <table align=center border=1 width=80%>
        <tr>
            <td><b><center>Task</center></b></td>
            <td><b><center>Result (Green=GOOD, Red=BAD)</center></b></td>
            <td><b><center>Notes/Fix</center></b></td>
        "
$Uninstall_header | Out-File -FilePath $htmlfile

#############################################################
#       MSIEXEC INSTALLER APPLICATIONS
#############################################################


[ARRAY]$apps = ("Bing BAR", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
("Dell Backup and Recovery Manager", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
("Dell Feature Enhancement Pack", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
("Dell Digital Delivery", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
("Dell System Manager", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
("Trend Micro Client/Server Security Agent", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
("Message Center Plus", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
("ThinkVantage Active Protection System", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode"),
("AT&T Service Activation", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
("Sonic Icons for Lenovo", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
("Client Security Solution", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode"),
("Verizon Wireless Mobile Broadband Self Activation", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
("Client Security - Password Manager", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode")

foreach($item in $apps)
    {
    $firstitem = $item[0]
    #Write-Verbose "`$firstitem is $firstitem"

    $app = get-wmiobject win32_product | where {$_.name -match "$firstitem"}
    $appname = $app.name
    #Write-Verbose "`$appname is $appname"
    
    $appid = $app.IdentifyingNumber
    #Write-Verbose "`$appid is $appid"
    
    $seconditem = $item[1]
    $installcommand = $seconditem.Replace("{}","$appid")
    #Write-Verbose "`$installcommand is $installcommand"
    
    if($appname -contains $firstitem)
        {
        Write-Verbose "$firstitem is installed"
        Invoke-Expression $installcommand     
        Write-Verbose 'Will sleep for 20 seconds before rechecking if the app is still installed.'   
        Start-Sleep -s 20
        if(($app2 = get-wmiobject win32_product | where {$_.name -match "$firstitem"}).name -contains $firstitem)
                {
                Write-Verbose "$firstitem did not uninstall and is still installed"
                $item_Uninstall = "$firstitem did not uninstall and is still installed"
                $item_output = "
                    <tr>
                        <td>$firstitem Removal</td>
                        <td class=bad>$item_Uninstall</td>
                        <td class=bad>You need to manually remove it</td>
                    </tr>
                    "
                $item_output | out-file -filepath $htmlfile -append
                }
                else
                {
                Write-Verbose "$firstitem has been uninstalled properly"
                $item_Uninstall = "$firstitem has been uninstalled properly"
                $item_output = "
                <tr>
                    <td>$firstitem Removal</td>
                    <td class=good>$item_Uninstall</td>
                    <td class=good>Uninstalled!</td>
                </tr>
                "
                $item_output | out-file -filepath $htmlfile -append
                }

            }
        else
            {
            Write-Verbose "$firstitem was not installed in the first place"
            $item_Uninstall = "$firstitem was not installed in the first place"
            $item_output = "
                    <tr>
                        <td>$firstitem Removal</td>
                        <td class=neither>$item_Uninstall</td>
                        <td class=neither>No need to do anything</td>
                    </tr>
                    "
            $item_output | out-file -filepath $htmlfile -append
            }
         
        }




#######################################################
#   CMD Installer Apps
#######################################################


        #Uninstall VNC Enterprise Edition E4.4.3
        #This has been successfully tested
        $VNC = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
            Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "VNC"}
            
        if($VNC)
            {
            & "C:\Program Files\RealVNC\VNC4\unins000.exe" /SILENT
            }


        #Uninstall Lenovo Registration 
        #This has been successfully tested
        $LenovoReg = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
            Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "Lenovo Registration"}
            
        if($LenovoReg)
            {
            & "C:\Program Files\Lenovo Registration\uninstall.exe" /qn
            }








##################################################################
#         CMD INSTALLER APPLICATIONS WITH RUNDLL32
##################################################################























