get-aznetworkinterface | select name,@{N="Network";E={($_.ipconfigurations.subnet.id).split("/")[10]}},@{N="DNS";E={$_.dnssettings.dnsservers}} | export-csv c:\temp\dnsservers.csv -notypeinformation



