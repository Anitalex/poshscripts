Connect-AzAccount

$subs = get-azsubscription
$region = 'southcentralus'

foreach ($sub in $subs){
    $subid = $sub.id
    select-azsubscription -subscriptionid $subid
    new-azsubscriptiondeployment -name "Lighthouse" -location $region -templatefile "C:\Lighthouse\delegatedResourceManagement.json" -templateparameterfile "C:\Lighthouse\delegatedResourceManagement.parameters.json" -verbose
}


