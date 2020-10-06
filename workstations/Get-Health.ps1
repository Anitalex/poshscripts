$verbosepreference = "Continue"
$machine_name = get-content env:computername
$outfile = "C:\HealthStatus_$machine_name.txt"


# Enforce the error trap by stopping on all errors
$ErrorActionPreference = "stop"

# Generic error logger
Trap {
    "-------------------------------------------------------------------------------"
    "Error."
    $Error
    "-------------------------------------------------------------------------------"
    $Error.Clear()
    Continue
}

# Reset the error array
$Error.Clear()

# Echo the suggested syntax if no parameters are specified
If ($Args[0]) 
    {
    $PC = $Args[0]
    } 
Else 
    {
    $PC = "$machine_name"
    }

function Get-PCHealth{
"-------------------------------------------------------------------------------"
"Checking client health for $PC"

"-------------------------------------------------------------------------------"
# Ping
Write-Progress -Activity "Ping" -Status $PC -PercentComplete (1/7*100)
# Tests connection and displays IP addresses
Test-Connection $PC | Format-Table -AutoSize

"-------------------------------------------------------------------------------"
# Local time on PC
Write-Progress -Activity "Time" -Status $PC -PercentComplete (2/7*100)
"Local time on $PC"
Get-WmiObject Win32_LocalTime |
Format-Table Month, Day, Year, Hour, Minute, Second -AutoSize

"-------------------------------------------------------------------------------"
Write-Progress -Activity "C$ share" -Status $PC -PercentComplete (3/7*100)
"C$ share"
Get-WmiObject Win32_Share -Filter "Name='C$'" -ComputerName $PC |
Format-Table __Server, Name, Path, Description -AutoSize
"UNC access to C$"
"----------------"
Test-Path "\\$PC\c`$\"

"-------------------------------------------------------------------------------"
Write-Progress -Activity "Perf stats" -Status $PC -PercentComplete (4/7*100)
"Disk, Memory, and CPU"
"---------------------"
# Free C: space in MB
$CFree   = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -Property FreeSpace -ComputerName $PC |
Select-Object @{name="CFreeMB";expression={$_.FreeSpace/1MB}} |
Select-Object -ExpandProperty CFreeMB
If     ($CFree -gt 1000) { "C drive is OK at $($CFree)MB free" }
ElseIf ($CFree -lt 1000) { "C drive is low at $($CFree)MB free" }
ElseIf ($CFree -lt 100)  { "C drive is critically low at $($CFree)MB free" }

# Free memory in MB
$MemFree = Get-WmiObject Win32_PerfFormattedData_PerfOS_Memory -Property AvailableMBytes -ComputerName $PC |
Select-Object -ExpandProperty AvailableMBytes
If     ($MemFree -gt 1000) { "Memory is OK at $($MemFree)MB" }
ElseIf ($MemFree -lt 1000) { "Memory is low at $($MemFree)MB" }
ElseIf ($MemFree -lt 100)  { "Memory is critically low at $($MemFree)MB" }

# CPU
$CPU = Get-WmiObject Win32_PerfFormattedData_PerfOS_Processor -Property Name, PercentProcessorTime -ComputerName $PC -Filter "Name='_Total'" |
Select-Object -ExpandProperty PercentProcessorTime
If     ($CPU -gt 95) { "CPU is pegged at $CPU%" }
ElseIf ($CPU -gt 50) { "CPU is high at $CPU%" }
Else                 { "CPU is OK at $CPU%" }

Write-Progress -Activity "Event logs" -Status $PC -PercentComplete (5/7*100)
# Event log alerts
# We are using the cmdlet "Get-EventLog" to support older operating systems
$Logs  = "System", "Application"
$Types = "Error", "Warning"
ForEach ($Log in $Logs) {
    "-------------------------------------------------------------------------------"
    "$Log event log last ten alerts:"
    Get-EventLog -LogName $Log -Newest 10 -ComputerName $PC -EntryType $Types |
     Select-Object TimeGenerated, EntryType, Source, EventID, Message |
     Format-List *
}

"-------------------------------------------------------------------------------"
# Run the SYSTEMINFO utility
Write-Progress -Activity "SystemInfo" -Status $PC -PercentComplete (6/7*100)
SYSTEMINFO /S $PC

"-------------------------------------------------------------------------------"
}

Get-PCHealth | Out-File $outfile




########################################

        function send_email { 
        [CmdletBinding()]

                    <#
                    This function allows you to email a file

                    There are 3 parameters that are all mandatory

                    --From -- This is the email that you want to send from

                    --To -- This is the email you want to send too

                    --File -- This is the file you would like to send

                    Example:
                    send_email -from "support@ribbit.net" -to "test@ribbit.net" -file "c:\file.txt"

                    #>
                param (

                [Parameter(Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                $From,
        
                [Parameter(Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                $To,
                
                [Parameter(Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                $File

               )

        BEGIN {}
        PROCESS {
                $mailmessage = New-Object system.net.mail.mailmessage
                $mailmessage.from = ($from)
                $mailmessage.To.add($to)
                $mailmessage.Subject = $emailsubject
                $mailmessage.Body = $emailbody

                $EmailSubject = "$file" 
                $emailbody = ""

                $SMTPServer = "ironmail.1sourcing.net"
                $SMTPAuthUsername = ""
                $SMTPAuthPassword = ""

                $emailattachment = $file 

                $attachment = New-Object System.Net.Mail.Attachment($emailattachment, 'text/plain')
                  $mailmessage.Attachments.Add($attachment)


                #$mailmessage.IsBodyHTML = $true
                $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 25) 
                $SMTPClient.Credentials = New-Object System.Net.NetworkCredential("$SMTPAuthUsername", "$SMTPAuthPassword")
                $SMTPClient.Send($mailmessage)
                }
        END {}
        } 



send_email -from "support@ribbit.net" -to "cm@ribbit.net" -file $outfile










