###############################################################################################
#   This script was created to automate the creation of Outlook appointments on the Field 
#	Services calendar from tickets in Service Desk.
#	Created by Carlos McCray
#	Last edited on 3/10/2016

[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

$global:x = 0

function schedulingForm {

    [array]$technicians = "","Adam Seaver","Cameron Thayer","Jeff Dyess","Harif Marzan","KP Phounsavath","Johnny Sims","Carlos McCray","Matt Turnipseed","3rd Party Vendor"
    [array]$durationTimes = "","30","60","90","120","150","180","210","240","270","300","480"

    ###############################################################################################
    #   Main Form

    $Form = New-Object System.Windows.Forms.Form
    $Form.Size = New-Object Drawing.Size @(500,520) 
    $Form.Text = ”Field Services Scheduling Script”
    $form.Location = new-object System.Drawing.Size(500,0)

    ###############################################################################################
    #   Add the Calendar

    $Calendar = New-Object System.Windows.Forms.MonthCalendar 
    $calendar.Location = new-object System.Drawing.Size(30,10)
    $Calendar.ShowTodayCircle = $True
    $Calendar.MaxSelectionCount = 1
    $Form.Controls.Add($Calendar) 

    ###############################################################################################
    #   Time of Day

    $timebox = New-Object System.Windows.Forms.TextBox 
    $timebox.Location = New-Object System.Drawing.Size(100,180) 
    $timebox.Size = New-Object System.Drawing.Size(130,30) 
    $Form.Controls.Add($timebox)

    $timeboxLabel = new-object System.Windows.Forms.Label
    $timeboxLabel.Location = new-object System.Drawing.Size(10,180)
    $timeboxLabel.size = new-object System.Drawing.Size(100,30)
    $timeboxLabel.Text = "What Time would you like"
    $Form.Controls.Add($timeboxLabel)

    ###############################################################################################
    #   Tech Assignment Drop Down

    $techAssigned = new-object System.Windows.Forms.ComboBox
    $techAssigned.Location = new-object System.Drawing.Size(100,220)
    $techAssigned.Size = new-object System.Drawing.Size(130,30)

    ForEach ($person in $technicians) {
	    $techAssigned.Items.Add($person)
    }

    $Form.Controls.Add($techAssigned)

    $techAssignedLabel = new-object System.Windows.Forms.Label
    $techAssignedLabel.Location = new-object System.Drawing.Size(10,220)
    $techAssignedLabel.size = new-object System.Drawing.Size(100,20)
    $techAssignedLabel.Text = "Available Techs"
    $Form.Controls.Add($techAssignedLabel)

    ###############################################################################################
    #   Additional Tech Assignment

    $additionalAssigned = New-Object System.Windows.Forms.TextBox 
    $additionalAssigned.Location = New-Object System.Drawing.Size(100,260) 
    $additionalAssigned.Size = New-Object System.Drawing.Size(130,30) 
    $Form.Controls.Add($additionalAssigned)

    $additionalAssignedLabeled = new-object System.Windows.Forms.Label
    $additionalAssignedLabeled.Location = new-object System.Drawing.Size(10,260)
    $additionalAssignedLabeled.size = new-object System.Drawing.Size(100,30)
    $additionalAssignedLabeled.Text = "Who else would you like to notify"
    $Form.Controls.Add($additionalAssignedLabeled)

    ###############################################################################################
    #   Appointment Duration Drop Down

    $apptDuration = new-object System.Windows.Forms.ComboBox
    $apptDuration.Location = new-object System.Drawing.Size(100,300)
    $apptDuration.Size = new-object System.Drawing.Size(130,30)

    ForEach ($min in $durationTimes) {
	    $apptDuration.Items.Add($min)
    }

    $Form.Controls.Add($apptDuration)

    $apptDurationLabel = new-object System.Windows.Forms.Label
    $apptDurationLabel.Location = new-object System.Drawing.Size(10,300)
    $apptDurationLabel.size = new-object System.Drawing.Size(100,30)
    $apptDurationLabel.Text = "How long will it be(mins)?"
    $Form.Controls.Add($apptDurationLabel)

    ###############################################################################################
    #   Ticket Number Box

    $ticketNumber = New-Object System.Windows.Forms.TextBox 
    $ticketNumber.Location = New-Object System.Drawing.Size(100,340) 
    $ticketNumber.Size = New-Object System.Drawing.Size(130,20) 
    $Form.Controls.Add($ticketNumber)

    $ticketNumberLabel = new-object System.Windows.Forms.Label
    $ticketNumberLabel.Location = new-object System.Drawing.Size(10,340)
    $ticketNumberLabel.size = new-object System.Drawing.Size(100,30)
    $ticketNumberLabel.Text = "What's the Ticket Number?"
    $Form.Controls.Add($ticketNumberLabel)

    ###############################################################################################
    #   Equipment to bring

    $EquipmentToBring = New-Object System.Windows.Forms.RichTextBox 
    $EquipmentToBring.Location = New-Object System.Drawing.Size(275,30) 
    $EquipmentToBring.Size = New-Object System.Drawing.Size(200,100) 
    $Form.Controls.Add($EquipmentToBring)

    $EquipmentToBringLabel = new-object System.Windows.Forms.Label
    $EquipmentToBringLabel.Location = new-object System.Drawing.Size(275,10)
    $EquipmentToBringLabel.size = new-object System.Drawing.Size(200,150)
    $EquipmentToBringLabel.Text = "Location of Equipment "
    $Form.Controls.Add($EquipmentToBringLabel)

    ###############################################################################################
    #   Notes from Scheduler

    $NotesFromScheduler = New-Object System.Windows.Forms.RichTextBox 
    $NotesFromScheduler.Location = New-Object System.Drawing.Size(275,180) 
    $NotesFromScheduler.Size = New-Object System.Drawing.Size(200,200) 
    $Form.Controls.Add($NotesFromScheduler)

    $NotesFromSchedulerLabel = new-object System.Windows.Forms.Label
    $NotesFromSchedulerLabel.Location = new-object System.Drawing.Size(275,160)
    $NotesFromSchedulerLabel.size = new-object System.Drawing.Size(200,150)
    $NotesFromSchedulerLabel.Text = "Notes From Scheduler"
    $Form.Controls.Add($NotesFromSchedulerLabel)

    ###############################################################################################
    #   Button to Schedule Appointment

    $Button = new-object System.Windows.Forms.Button
    $Button.Location = new-object System.Drawing.Size(100,420)
    $Button.Size = new-object System.Drawing.Size(100,50)
    $Button.Text = "Click To Schedule"
    $Button.Add_Click({$form.Close()})
    $form.Controls.Add($Button)

    ###############################################################################################
    #   Button to Close Form

    $stop = new-object System.Windows.Forms.Button
    $stop.Location = new-object System.Drawing.Size(300,420)
    $stop.Size = new-object System.Drawing.Size(100,50)
    $stop.Text = "Click To Close"
    $stop.Add_Click({$global:x = 2; $form.Close()})
    $form.Controls.Add($stop)

    ###############################################################################################
    #   Start The Form

    $Form.Add_Shown({$Form.Activate()})
    $Form.ShowDialog()

    ###############################################################################################
    #   Get the data

    $theTime = $timebox.Lines
    $TheDate = $Calendar.SelectionStart.ToShortDateString()
    $Tech = $techAssigned.SelectedItem.ToString()
    $Tech2 = $additionalAssigned.Lines
    $Duration = $apptDuration.SelectedItem.ToString()
    $Start = "$TheDate $TheTime"
    if ($3DropDown.SelectedItem.ToString() -ne $null){
    $reason = $3DropDown.SelectedItem.ToString()
    }
    $Ticket = $ticketNumber.text
    $ticketnumber = "`'$ticket`'"
    $TheEquipment = $EquipmentToBring.text
    $datetime = "$thedate $thetime"
    $TheNotes = $NotesFromScheduler.text

    ###############################################################################################
    #   Get the information on the ticket out of Service Desk database backend

    [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo")
    [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")

    $serverName = "10.10.2.91"
    $server = New-Object -typeName Microsoft.SqlServer.Management.Smo.Server -argumentList "$serverName"

    $server.ConnectionContext.LoginSecure=$false;
    #$server.ConnectionContext.set_Login('renuntio')
    #$securePassword = ConvertTo-SecureString 'CryM34R1v3r*' -AsPlainText –Force
    $server.ConnectionContext.set_Login('field.serv')
    $securePassword = ConvertTo-SecureString '@P0t0fG0ld!' -AsPlainText –Force
    $server.ConnectionContext.set_SecurePassword($securePassword)
    $database = "mdb"
    $db = new-object ("Microsoft.sqlServer.Management.Smo.Database") ($server, $database)

    $sqlquery1 = "SELECT DISTINCT z_INPRCO.last_name + `',`' + z_INPRCO.first_name as cust_name, org_name, z_INPRCO.summary, case [z_INPRCO].[type] when `'C`' then CAST`(CO.description as varchar`(5000`)`) else CAST`(IP.description as varchar`(5000`)`) end as `'desc`', con.pri_phone_number, con.alt_phone_number, email_address, z_INPRCO.location_name as loc_name, address_1, address_2, z_INPRCO.city, st.symbol as State_abv ,zip FROM z_INPRCO INNER JOIN ca_location loc on z_INPRCO.location_name = loc.location_name INNER JOIN ca_contact con on z_INPRCO.customer = con.contact_uuid INNER JOIN ca_state_province st on [loc].[state]=st.id LEFT JOIN call_req IP on z_INPRCO.ticket = IP.ref_num LEFT JOIN chg CO on z_INPRCO.ticket = CO.chg_ref_num WHERE ticket = $ticketnumber AND loc.inactive <>1"
    $sqlquery2="UPDATE call_req SET call_back_date = DATEDIFF(s, `'1970-01-01 00:00:00`',DATEADD(hh,5,`'$datetime`')) WHERE ref_num = $ticketnumber"

    $ds = $db.ExecuteWithResults("$sqlquery1")
    $db.ExecuteNonQuery("$sqlquery2")
    $table = $ds.tables[0]

    foreach ($item in $table) 
        {
        $summary = $item.summary
        $description = $item.desc
        $user = $item.cust_name
        $client = $item.org_name
        $locationname = $item.loc_name 
        $primarynumber = $item.pri_phone_number
        $secondarynumber = $item.alt_phone_number
        $customeremail = $item.email_address
        $locationname = $item.loc_name 
        $address1 = $item.address_1
        $address2 = $item.address_2
        $city = $item.city 
        $state = $item.State_abv
        $zip = $item.zip
        }


    ###############################################################################################
    #   Get tech's email

    if ($tech -match "3rd Party Vendor")
        {
        $techemail = "calendar@email.net"
        }
    else
        {
        $techlogon = $tech.replace(" ",".")
        $techemail = "$techlogon@email.net"
        }


    ###############################################################################################
    #   Get second tech's email

    if ($tech2 ){
    $tech2 = $tech2.Replace(" ",".")

    if ($tech2 -match '@' -and ($tech2 -match '.com' -or $tech2 -match '.net'))
        {
        $techemail2 = $tech2
        }
    elseif ($tech2 -notmatch "." -or $tech2 -notmatch '@')
        {
        $techemail2 = "$tech2@email.net"
        }
    }

    ###############################################################################################
    #   Create the appointment

    $notes = ""

    #format the body
    $body = @"

    Equipment Location

    $TheEquipment

    ----------------------------------------------

    Notes from Scheduler and/or 

    $TheNotes

    ----------------------------------------------

    User's Contact Information

    User:  $user
    Client: $client
    Location: $locationname
    Primary Number: $primarynumber
    Alternate Number: $secondarynumber
    Email: $customeremail

    ----------------------------------------------

    User's Location

    $address1
    $address2
    $city
    $state
    $zip

    ----------------------------------------------

    Summary Of Issue

    $summary

    ----------------------------------------------

    Description Of The Issue

    $description

    ----------------------------------------------


"@

     
    #USE THIS SECTION TO WORK WITH OWA

    Add-Type -Path ‘C:\Program Files\Microsoft\Exchange\Web Services\1.1\Microsoft.Exchange.WebServices.dll’
    $service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService -ArgumentList ([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP1)

    $service.AutodiscoverUrl('calendar@email.net')
    $Impersonate = 'calendar@email.net'
    $ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId -ArgumentList ([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress),$Impersonate
    $service.ImpersonatedUserId = $ImpersonatedUserId

    $appt = New-Object Microsoft.Exchange.WebServices.Data.Appointment -ArgumentList $service

    $appt.Start = $Start
    $appt.End = $appt.Start.AddMinutes($duration)
    #Adding required attendees
    $appt.RequiredAttendees.Add("$techemail")
    if($techemail2)
        {
        $appt.OptionalAttendees.Add("$techemail2")
        }
    $appt.Subject = "$tech - $client - $summary - $ticket"
    $appt.Location = "$address1 $address2 $city $zip"
    $appt.Body = $body
    $appt.Body.BodyType = "Text"
    $appt.Save([Microsoft.Exchange.WebServices.Data.SendInvitationsMode]::SendToAllAndSaveCopy)


    $outfile = "C:\Scheduling\$ticket-$tech.txt"


    $Ticket | out-file $outfile
    $Duration | out-file $outfile -Append
    $Tech | out-file $outfile -Append
    $TheTime | out-file $outfile -Append
    $TheDate | out-file $outfile -Append
    $summary | out-file $outfile -Append
    $description | out-file $outfile -Append
    $user | out-file $outfile -Append
    $client | out-file $outfile -Append
    $locationname | out-file $outfile -Append
    $primarynumber | out-file $outfile -Append
    $secondarynumber | out-file $outfile -Append
    $customeremail | out-file $outfile -Append
    $locationname | out-file $outfile -Append
    $address1 | out-file $outfile -Append
    $address2 | out-file $outfile -Append
    $city | out-file $outfile -Append
    $state | out-file $outfile -Append
    $zip | out-file $outfile -Append
    $body | out-file $outfile -Append


}

do {
    schedulingForm 
} until ($x -eq 2)


