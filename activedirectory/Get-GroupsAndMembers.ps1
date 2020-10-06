
install-module msonline
Import-Module msonline
Connect-MsolService
$groups = get-msolgroup -grouptype security

$result = $null
$final = $null
$result = @()
$final = @()

foreach ($group in $groups)
{
        $groupname = $group.displayname
        $desc = $group.description
        $members = get-msolgroupmember -groupobjectid $group.objectid
        if ($members -ne $null)
        {
                $result = new-object -typename psobject -property @{Group="$groupname";Description="$desc"}
                $result | add-member -type noteproperty -name Members -value @($members.displayname)
        }
        else 
        {
                $result = new-object -typename psobject -property @{Group="$groupname";Description="$desc"}
                $result | add-member -type noteproperty -name Members -value 'Empty'
        }
        $final += $result
}
$final | Select-Object group,description,members











