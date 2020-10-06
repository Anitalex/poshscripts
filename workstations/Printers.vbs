'--------------------TSI Home Printers----------------------
'
'strComputer = "."
'Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
'
'Set colInstalledPrinters =  objWMIService.ExecQuery _    
'  ("Select * from Win32_Printer Where Network = TRUE")
'
'For Each objPrinter in colInstalledPrinters    
'  objPrinter.Delete_
'Next


Set objnetwork = CreateObject("WScript.Network")
objnetwork.AddWindowsPrinterConnection "\\DSM-SVR1-TSI\AP"
objnetwork.AddWindowsPrinterConnection "\\DSM-SVR1-TSI\CFO"
objnetwork.AddWindowsPrinterConnection "\\DSM-SVR1-TSI\Executive"
objnetwork.AddWindowsPrinterConnection "\\DSM-SVR1-TSI\Customer Service"
objnetwork.AddWindowsPrinterConnection "\\DSM-SVR1-TSI\Shipping"
objnetwork.AddWindowsPrinterConnection "\\DSM-SVR1-TSI\Color Printer"
objnetwork.AddWindowsPrinterConnection "\\DSM-SVR1-TSI\Receptionist"

WScript.Quit


'--------------------TSI Home Printers----------------------

'Created 07/30/2011 - CM
