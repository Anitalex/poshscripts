
#Copy install files local
$installs = "Adobe\Air","Adobe\Reader","Adobe\Flash","Java"

foreach($item in $installs)
    {
        if(Test-Path "C:\Leapfrog_Installation_Files\Apps\$item")
        {
        Write-Verbose "$item has already been downloaded"
        }
        else{
            #Write-Verbose "Copying $item locally"
            #Copy-Item -path $source\$item -destination $dest\$item -recurse
            $path = "X:\Installs"
            $dest = "C:\Installation_Files\Apps\"
 
            $files = Get-ChildItem "$path\$item" -recurse

            [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | out-null; 
 
                $counter = 1
                Foreach($file in $files)
                 {
                 $status = "Copy files {0} on {1}: {2}" -f $counter,$files.Count,$file.Name
                 Write-Progress -Activity "Copying Install Files locally" $status -PercentComplete ($counter / $files.count*100)
                 #$restpath = $file.fullname.replace("")
                 Copy-Item  $file.fullname "$dest\$item" -Force
           
                $counter++
                  }

                 #If ($Counter = $files.Count)
                 #{
                 #[System.Windows.Forms.MessageBox]::Show("Backup End.")
                 #}
        }
    }