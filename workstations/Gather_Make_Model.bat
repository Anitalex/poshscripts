@echo off
for /F "skip=1 delims=" %%j in ('WMIC CSProduct Get Vendor') do (
  set Vendor=%%j
  goto :DONE
)
:DONE
REM echo  Vendor=%Vendor%

for /F "skip=1 delims=" %%j in ('WMIC CSProduct Get Name') do (
  set Name=%%j
  goto :DONE
)
:DONE
REM echo  Name=%Name%
 
mkdir "c:\%vendor%_%NAME%"