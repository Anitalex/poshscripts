@echo off
::
Echo Importing SecurityCenter.reg
%windir%\Regedit.exe /s \\192.168.30.203\scripts\securitycenter.reg
Echo SecurityCenter.reg Imported Successfully

netsh firewall set opmode mode=disable
