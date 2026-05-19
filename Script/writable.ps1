param([string]$target = "C:\inetpub")
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$myGroups = $id.Groups.Translate([Security.Principal.NTAccount]).Value + $id.Name

$writeData = [System.Security.AccessControl.FileSystemRights]::WriteData

Get-ChildItem $target -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $dir = $_
    try {
        (Get-Acl $dir.FullName).Access | Where-Object { 
            $_.AccessControlType -eq "Allow" -and 
            $_.IdentityReference.Value -in $myGroups -and 
            $_.FileSystemRights.HasFlag($writeData)
        } | ForEach-Object { 
            Write-Host "$($dir.FullName): $($_.IdentityReference.Value)" 
        }
    } catch { }
}
