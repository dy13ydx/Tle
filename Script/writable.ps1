$target = Read-Host "Enter path to check"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$myGroups = $id.Groups.Translate([Security.Principal.NTAccount]).Value
$myGroups += $id.Name

Get-ChildItem $target -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
	if ([console]::KeyAvailable -and [console]::ReadKey($true).KeyChar -eq 'q') { break }
    $dir = $_
    try {
        (Get-Acl $dir.FullName).Access | ForEach-Object {
            if ($_.AccessControlType -eq "Allow" -and $_.IdentityReference.Value -in $myGroups) {
                if (($_.FileSystemRights -like "*Write*" -or $_.FileSystemRights -like "*Create*") -and $_.FileSystemRights -like "*Execute*") {
                    Write-Host "$($dir.FullName): $($_.IdentityReference.Value) ($($_.FileSystemRights))"
                }
            }
        }
    } catch { }
}
