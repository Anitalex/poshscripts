powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e

powercfg -change -monitor-timeout-ac 30
powercfg -change -monitor-timeout-dc 15
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 0
powercfg -change -disk-timeout-ac 0 
powercfg -change -disk-timeout-dc 0 
powercfg -change -hibernate-timeout-ac 0
powercfg -change -hibernate-timeout-dc 0
powercfg -h off