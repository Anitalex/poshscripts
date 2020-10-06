Const UAC_ENABLE = 1

Const UAC_DISABLE = 0

Const UAC_REGKEY = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"

 

If Wscript.Arguments.Count <> 1 Then

    Wscript.Echo "Usage: " & Wscript.ScriptName & " Enable|Disable|Status"

    Wscript.Quit

End If

 

Set Shell = CreateObject( "WScript.Shell" )

 

If UCase(Wscript.Arguments.Item(0)) = "ENABLE" Then

    Shell.RegWrite UAC_REGKEY, UAC_ENABLE, "REG_DWORD"

    Wscript.Echo "UAC Enabled, please reboot..."

    Wscript.Quit

End If

 

If UCase(Wscript.Arguments.Item(0)) = "DISABLE" Then

    Shell.RegWrite UAC_REGKEY, UAC_DISABLE, "REG_DWORD"

    Wscript.Echo "UAC Disabled, please reboot..."

    Wscript.Quit

End If

 

If UCase(Wscript.Arguments.Item(0)) = "STATUS" Then

    If Shell.RegRead(UAC_REGKEY) = 0 Then

        Wscript.Echo "UAC is Disabled."

    Else

        Wscript.Echo "UAC is Enabled."

    End If

        Wscript.Quit

End If
