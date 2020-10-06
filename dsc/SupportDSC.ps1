Configuration SupportDSC
{
    Import-DscResource -ModuleName cChoco,xPrinter

    Node "localhost"
    {
        xPrinter XeroxPrinter
        {
            DirverName = "Xerox Phaser 6180MFP-D PS"
            Ensure = "Present"
            PortIP = "10.100.10.10"
            PrinterName = "Xerox Phaser 6180MFP-D PS"
            PrinterPort = "10.100.10.10"
        }

        xPrinter KMPrinter
        {
            DirverName = "KONICA MINOLTA C360SeriesPCL"
            Ensure = "Present"
            PortIP = "10.100.10.12"
            PrinterName = "KONICA MINOLTA C360"
            PrinterPort = "10.100.10.12"
        }

        cChocoInstaller installChoco
		{
			InstallDir = "C:\choco"
		}

		cChocoPackageInstaller installCoreExtension
		{
			Name = "chocolatey-core.extension"
            Ensure  = 'Present'
			DependsOn = "[cChocoInstaller]installChoco"
        }
   
        cChocoPackageInstaller installadobereader
		{
			Name = "adobereader"
            Ensure  = 'Present'
			DependsOn = "[cChocoInstaller]installChoco"
		}
    }
}
