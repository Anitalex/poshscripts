[DSCLocalConfigurationManager()]

configuration LCMPUSH {

    Node $env:computername {
    
        settings {

        AllowModuleOverwrite = $true
        ConfigurationMode = 'ApplyAndAutoCorrect'
        RefreshMode = 'Push'
        }

    }

}

LCMPUSH -OutputPath 'C:\management\dsc' -ConfigurationData $ConfigData
