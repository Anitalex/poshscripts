
    
sl 'C:\SoftPaqDownloadDirectory\HP EliteBook 8460p Notebook PC'

$files = GCI

foreach ($file in $files)
    {
    $filename = ($file.name).Split(".")[0]
    new-item ".\$filename" -ItemType directory
    & C:\7za.exe e $file -o".\$filename" -aoa
    }



















