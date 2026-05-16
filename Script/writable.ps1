param([string]$target = "C:\inetpub")
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$myGroups = $id.Groups.Translate([Security.Principal.NTAccount]).Value + $id.Name

Get-ChildItem $target -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $dir = $_
    try {
        (Get-Acl $dir.FullName).Access | Where-Object { 
            $_.AccessControlType -eq "Allow" -and 
            $_.IdentityReference.Value -in $myGroups -and 
            $_.FileSystemRights -match "Write|Create" -and 
            $_.FileSystemRights -match "Execute" 
        } | ForEach-Object { 
            Write-Host "$($dir.FullName): $($_.IdentityReference.Value)" 
        }
    } catch { }
}
