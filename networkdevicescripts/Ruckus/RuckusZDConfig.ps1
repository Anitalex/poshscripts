########################################################################
###	Create a GUI box for user input of Ruckus configuration items

########################################################################
###   Functions

function Return-DropDown {
    $Form.Close()
    }

function New-Button { 
[CmdletBinding()]
        param (

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $Vertical,
        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $Horizontal,
                
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $Width,
        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $Height,

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $Label
        )

BEGIN {}
PROCESS {
        $Button = new-object System.Windows.Forms.Button
        $Button.Location = new-object System.Drawing.Size($Horizontal,$Vertical)
        $Button.Size = new-object System.Drawing.Size($Width,$Height)
        $Button.Text = $Label
        $Button.Add_Click({Return-DropDown})
        $form.Controls.Add($Button)
        }
END {}
} 

########################################################################
###  Main Form

####  Create form object
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
$Form = New-Object System.Windows.Forms.Form
$Form.Size = New-Object Drawing.Size @(500,700) 
$form.Location = new-object System.Drawing.Size(500,0)

###################################################################

$TextBoxLabel = new-object System.Windows.Forms.Label
$TextBoxLabel.Location = new-object System.Drawing.Size(10,10)
$TextBoxLabel.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel.Text = 'What is the password to the Lfs.Admin account?'
$Form.Controls.Add($TextBoxLabel)

$TextBox = New-Object System.Windows.Forms.TextBox 
$TextBox.Location = New-Object System.Drawing.Size(225,10) 
$TextBox.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox)

###################################################################

$TextBoxLabel2 = new-object System.Windows.Forms.Label
$TextBoxLabel2.Location = new-object System.Drawing.Size(10,40)
$TextBoxLabel2.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel2.Text = 'What would you like to name the ZD?'
$Form.Controls.Add($TextBoxLabel2)

$TextBox2 = New-Object System.Windows.Forms.TextBox 
$TextBox2.Location = New-Object System.Drawing.Size(225,40) 
$TextBox2.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox2)

###################################################################

$TextBoxLabel3 = new-object System.Windows.Forms.Label
$TextBoxLabel3.Location = new-object System.Drawing.Size(10,70)
$TextBoxLabel3.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel3.Text = 'What is the static IP of the ZD?'
$Form.Controls.Add($TextBoxLabel3)

$TextBox3 = New-Object System.Windows.Forms.TextBox 
$TextBox3.Location = New-Object System.Drawing.Size(225,70) 
$TextBox3.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox3)

###################################################################

$TextBoxLabel4 = new-object System.Windows.Forms.Label
$TextBoxLabel4.Location = new-object System.Drawing.Size(10,100)
$TextBoxLabel4.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel4.Text = 'What is the static subnet mask of the ZD?'
$Form.Controls.Add($TextBoxLabel4)

$TextBox4 = New-Object System.Windows.Forms.TextBox 
$TextBox4.Location = New-Object System.Drawing.Size(225,100) 
$TextBox4.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox4)

###################################################################

$TextBoxLabel16 = new-object System.Windows.Forms.Label
$TextBoxLabel16.Location = new-object System.Drawing.Size(10,130)
$TextBoxLabel16.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel16.Text = 'What is the static gateway of the ZD?'
$Form.Controls.Add($TextBoxLabel16)

$TextBox16 = New-Object System.Windows.Forms.TextBox 
$TextBox16.Location = New-Object System.Drawing.Size(225,130) 
$TextBox16.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox16)

###################################################################

$TextBoxLabel5 = new-object System.Windows.Forms.Label
$TextBoxLabel5.Location = new-object System.Drawing.Size(10,160)
$TextBoxLabel5.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel5.Text = 'What is the static IP of the primary DNS?'
$Form.Controls.Add($TextBoxLabel5)

$TextBox5 = New-Object System.Windows.Forms.TextBox 
$TextBox5.Location = New-Object System.Drawing.Size(225,160) 
$TextBox5.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox5)

###################################################################

$TextBoxLabel6 = new-object System.Windows.Forms.Label
$TextBoxLabel6.Location = new-object System.Drawing.Size(10,190)
$TextBoxLabel6.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel6.Text = 'What is the static IP of the secondary DNS?'
$Form.Controls.Add($TextBoxLabel6)

$TextBox6 = New-Object System.Windows.Forms.TextBox 
$TextBox6.Location = New-Object System.Drawing.Size(225,190) 
$TextBox6.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox6)

###################################################################

$TextBoxLabel7 = new-object System.Windows.Forms.Label
$TextBoxLabel7.Location = new-object System.Drawing.Size(10,220)
$TextBoxLabel7.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel7.Text = 'What email would you like to send alerts to?'
$Form.Controls.Add($TextBoxLabel7)

$TextBox7 = New-Object System.Windows.Forms.TextBox 
$TextBox7.Location = New-Object System.Drawing.Size(225,220) 
$TextBox7.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox7)

###################################################################

$TextBoxLabel8 = new-object System.Windows.Forms.Label
$TextBoxLabel8.Location = new-object System.Drawing.Size(10,250)
$TextBoxLabel8.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel8.Text = 'What email would you like to send alerts from?'
$Form.Controls.Add($TextBoxLabel8)

$TextBox8 = New-Object System.Windows.Forms.TextBox 
$TextBox8.Location = New-Object System.Drawing.Size(225,250) 
$TextBox8.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox8)

###################################################################

$TextBoxLabel9 = new-object System.Windows.Forms.Label
$TextBoxLabel9.Location = new-object System.Drawing.Size(10,280)
$TextBoxLabel9.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel9.Text = 'What email server would you like to use to send alerts?'
$Form.Controls.Add($TextBoxLabel9)

$TextBox9 = New-Object System.Windows.Forms.TextBox 
$TextBox9.Location = New-Object System.Drawing.Size(225,280) 
$TextBox9.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox9)

###################################################################

$TextBoxLabel10 = new-object System.Windows.Forms.Label
$TextBoxLabel10.Location = new-object System.Drawing.Size(10,310)
$TextBoxLabel10.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel10.Text = 'What is the LAN SSID?'
$Form.Controls.Add($TextBoxLabel10)

$TextBox10 = New-Object System.Windows.Forms.TextBox 
$TextBox10.Location = New-Object System.Drawing.Size(225,310) 
$TextBox10.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox10)

###################################################################

$TextBoxLabel11 = new-object System.Windows.Forms.Label
$TextBoxLabel11.Location = new-object System.Drawing.Size(10,340)
$TextBoxLabel11.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel11.Text = 'What is the LAN passphrase?'
$Form.Controls.Add($TextBoxLabel11)

$TextBox11 = New-Object System.Windows.Forms.TextBox 
$TextBox11.Location = New-Object System.Drawing.Size(225,340) 
$TextBox11.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox11)

###################################################################

$TextBoxLabel12 = new-object System.Windows.Forms.Label
$TextBoxLabel12.Location = new-object System.Drawing.Size(10,370)
$TextBoxLabel12.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel12.Text = 'What is the LAN VLAN?'
$Form.Controls.Add($TextBoxLabel12)

$TextBox12 = New-Object System.Windows.Forms.TextBox 
$TextBox12.Location = New-Object System.Drawing.Size(225,370) 
$TextBox12.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox12)

###################################################################

$TextBoxLabel13 = new-object System.Windows.Forms.Label
$TextBoxLabel13.Location = new-object System.Drawing.Size(10,400)
$TextBoxLabel13.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel13.Text = 'What is the guest SSID?'
$Form.Controls.Add($TextBoxLabel13)

$TextBox13 = New-Object System.Windows.Forms.TextBox 
$TextBox13.Location = New-Object System.Drawing.Size(225,400) 
$TextBox13.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox13)

###################################################################

$TextBoxLabel14 = new-object System.Windows.Forms.Label
$TextBoxLabel14.Location = new-object System.Drawing.Size(10,430)
$TextBoxLabel14.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel14.Text = 'What is the guest passphrase?'
$Form.Controls.Add($TextBoxLabel14)

$TextBox14 = New-Object System.Windows.Forms.TextBox 
$TextBox14.Location = New-Object System.Drawing.Size(225,430) 
$TextBox14.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox14)

###################################################################

$TextBoxLabel15 = new-object System.Windows.Forms.Label
$TextBoxLabel15.Location = new-object System.Drawing.Size(10,460)
$TextBoxLabel15.size = new-object System.Drawing.Size(200,30)
$TextBoxLabel15.Text = 'What is the guest VLAN?'
$Form.Controls.Add($TextBoxLabel15)

$TextBox15 = New-Object System.Windows.Forms.TextBox 
$TextBox15.Location = New-Object System.Drawing.Size(225,460) 
$TextBox15.Size = New-Object System.Drawing.Size(250,30) 
$Form.Controls.Add($TextBox15)

###################################################################

New-Button -horizontal 100 -vertical 520 -width 100 -height 50 -label 'Click to Close'

####  Initiate form object
$Form.Add_Shown({$Form.Activate()})
$Form.ShowDialog()

########################################################################
###  Creating output text file

$adminpswd = $TextBox.Text
$hostname = $TextBox2.Text
$ip = $TextBox3.Text
$subnetmask = $TextBox4.Text
$gateway = $TextBox16.Text
$dns1 = $TextBox5.Text
$dns2 = $TextBox6.Text
$smtpTo = $TextBox7.Text
$smtpFrom = $TextBox8.Text
$smtpServer = $TextBox9.Text
$lanSSID = $TextBox10.Text
$lanPassphrase = $TextBox11.Text
$lanVLAN = $TextBox12.Text
$guestSSID = $TextBox13.Text
$guestPassphrase = $TextBox14.Text
$guestVLAN = $TextBox15.Text

$output = @"
enable
config
admin
name sage password we1c0me!
end
role lfs.admin
description adminrole
wlan-allowed all
guest-pass-generation
admin super
end
user lfs.admin
user-name lfs.admin
full-name lfs.admin
password $adminpswd
role lfs.admin
end
role lfs.readonly
description readONLYrole
wlan-allowed all
guest-pass-generation
admin monitoring
end
user lfs.readonly
user-name lfs.readonly
full-name lfs.readonly
password we1c0me!
role lfs.readonly
end
system
hostname $hostname
interface
ip mode static
ip enable
ip route gateway $gateway
ip name-server $dns1 $dns2
ip addr $ip $subnetmask
end
ntp pool.ntp.org
end
alarm
email $smtpTo
from $smtpFrom
smtp-server-name $smtpServer
smtp-server-port 25
no event all
event AP-lost-contacted
event temporary-license-expired
event temporary-license-will-expire
event ap-has-hardware-problem
event Sensor-has-problem
end
services
auto-adjust-ap-power
auto-adjust-ap-channel
protect-excessive-wireless-request
end
wlan $lanSSID
ssid $lanSSID
name $lanSSID
type standard-usage
open wpa2 passphrase $lanPassphrase algorithm AES
vlan $lanVLAN
end
wlan $guestSSID
ssid $guestSSID
name $guestSSID
type guest-access
open wpa2 passphrase $guestPassphrase algorithm AES
vlan $guestVLAN
end
"@

if (test-path 'C:\Temp'){
    
    $output  | Out-File "C:\Temp\RuckusConfig.txt"

} else {

    New-Item -Path 'C:\Temp' -ItemType directory
    $output  | Out-File "C:\Temp\RuckusConfig.txt"

}



notepad "C:\Temp\RuckusConfig.txt"



