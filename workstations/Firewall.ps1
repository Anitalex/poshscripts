$fw = New-Object -ComObject hnetcfg.fwpolicy2 

$rulegroups = 'windows management instrumentation (wmi)','File and Printer Sharing','Netlogon Service','Network Discovery','windows firewall remote management','windows remote management','Remote assistance','Remote desktop','Remote Desktop - RemoteFX','Remote Administration'

foreach ($rulegroup in $rulegroups){
    #Enabling the Group for all profiles
    if($fw.IsRuleGroupEnabled(1,"$rulegroup")){
    }else{
        $fw.EnableRuleGroup(1,"$rulegroup",$True)
    }

    if($fw.IsRuleGroupEnabled(2,"$rulegroup")){
    }else{
        $fw.EnableRuleGroup(2,"$rulegroup",$True)
    }

    if($fw.IsRuleGroupEnabled(4,"$rulegroup")){
    }else{
        $fw.EnableRuleGroup(4,"$rulegroup",$True)
    }
}



