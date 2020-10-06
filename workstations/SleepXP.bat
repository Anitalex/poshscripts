powercfg /create custom1
powercfg /change custom1 /monitor-timeout-ac 30
powercfg /change custom1 /monitor-timeout-dc 15
powercfg /change custom1 /standby-timeout-ac 0
powercfg /change custom1 /standby-timeout-dc 0
powercfg /change custom1 /disk-timeout-ac 0 
powercfg /change custom1 /disk-timeout-dc 0 
powercfg /change custom1 /hibernate-timeout-ac 0 
powercfg /change custom1 /hibernate-timeout-dc 0 
powercfg /setactive custom1
Powercfg /hibernate off