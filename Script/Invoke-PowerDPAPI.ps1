function Invoke-PowerDPAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$Format="hex",
        [switch]$SaveOutput
    )
    
    Write-Host "[*] Running PowerDPAPI"

    if(Test-Path -Path $Path) {
        # Using -Force here to ensure we see hidden files in the list
        $fileList = Get-ChildItem -Path $Path -File -Force -Recurse | Select-Object -ExpandProperty FullName

        if($fileList) {
            foreach ($file in $fileList) {
                # --- FIX 1: Added -Force to Get-Item ---
                # This ensures we can grab properties of Hidden/System files
                $fileItem = Get-Item $file -Force

                if($VerbosePreference) {
                    Write-Host "[>] Processing file: $file"
                }

                $byteCount = 1024
                $inputBytes = Get-Content -Path $file -Encoding Byte -TotalCount $byteCount        
                $hexInputBytes = ($inputBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ""
                $magicByteIndex = $hexInputBytes.IndexOf("01000000D08C9DDF0115D1118C7A00C04FC297EB")
                
                if($magicByteIndex -ge 0) {        
                    $md5Hash = Get-FileHash -Path $file -Algorithm MD5 | Select-Object -ExpandProperty Hash
                    
                    Write-Host "**********************************************************************"
                    Write-Host "[!] Probable DPAPI blob found"
                    Write-Host "[>] File: $file"
                    Write-Host "[>] MD5 Hash: $md5Hash"

                    if($VerbosePreference) {
                        Write-Host "[>] magicByteIndex: $magicByteIndex"
                    }

                    $blobFileByteArray = [System.IO.File]::ReadAllBytes($file)

                    # --- Parsing Logic ---
                    $dwVersion = New-Object byte[] 4
                    $guidProvider = New-Object byte[] 16
                    $dwMasterKeyVersion = New-Object byte[] 4
                    $guidMasterKey = New-Object byte[] 16
                    $dwFlags = New-Object byte[] 4
                    $dwDescriptionLen = New-Object byte[] 4
                    
                    $ptrBlob = $magicByteIndex / 2
                    $ptrBlob += $dwVersion.Length + $guidProvider.Length + $dwMasterKeyVersion.Length
                    
                    [System.Array]::Copy($blobFileByteArray, $ptrBlob, $guidMasterKey, 0, $guidMasterKey.Length)
                    $ptrBlob += $guidMasterKey.Length
                    $masterKeyGuid = [System.Guid]::new($guidMasterKey)                     
                    Write-Host "[>] Master Key GUID: $masterKeyGuid"

                    $ptrBlob += $dwFlags.Length
                    [System.Array]::Copy($blobFileByteArray, $ptrBlob, $dwDescriptionLen, 0, $dwDescriptionLen.Length)
                    $ptrBlob += $dwDescriptionLen.Length
                    [uint32]$descriptionLength = [System.BitConverter]::ToUInt32($dwDescriptionLen, 0)

                    if($descriptionLength -gt 0) {
                        $szDescription = New-Object byte[] $descriptionLength
                        [System.Array]::Copy($blobFileByteArray, $ptrBlob, $szDescription, 0, $descriptionLength)
                        $readableDescription = [System.Text.Encoding]::UTF8.GetString($szDescription)
                        Write-Host "[>] Blob Description: $readableDescription"
                    }

                    # --- SAVE OUTPUT LOGIC (BLOB) ---
                    if ($SaveOutput) {
                        # --- FIX 2: Explicitly use $PWD.Path ---
                        # Ensures .NET receives a valid string path, not a PowerShell object
                        $blobOutputPath = Join-Path -Path $PWD.Path -ChildPath $fileItem.Name
                        try {
                            [System.IO.File]::WriteAllBytes($blobOutputPath, $blobFileByteArray)
                            Write-Host "[+] SAVED BLOB to: $blobOutputPath" -ForegroundColor Green
                        } catch {
                            Write-Error "Failed to save blob: $_"
                        }
                    } else {
                        Write-Host "-------------- START blob output --------------"
                        if($Format -eq "base64") {
                            $base64EncodedBlob = [System.Convert]::ToBase64String($blobFileByteArray)
                            Write-Host $base64EncodedBlob
                        } else {
                            ($blobFileByteArray | ForEach-Object { "\x{0:X2}" -f $_ }) -join ""
                        }
                        Write-Host "--------------  EOF blob output  --------------"        
                    }

                    Write-Host "[>] Locating corresponding master key file"

                    $protectDirectory = $Env:AppData + "\Microsoft\Protect"
                    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                    
                    if($userSid) {
                        $mkDirectory = $protectDirectory + "\" + $userSid
                        $mkFilePath = $mkDirectory + "\" + $masterKeyGuid
                        
                        if(Test-Path $mkFilePath) {
                            Write-Host "[>] Master Key Found:"
                            Write-Host "    $mkFilePath"

                            $mkByteArray = [System.IO.File]::ReadAllBytes($mkFilePath)

                            # --- SAVE OUTPUT LOGIC (MASTER KEY) ---
                            if ($SaveOutput) {
                                $mkOutputPath = Join-Path -Path $PWD.Path -ChildPath "$masterKeyGuid"
                                try {
                                    [System.IO.File]::WriteAllBytes($mkOutputPath, $mkByteArray)
                                    Write-Host "[+] SAVED MASTER KEY to: $mkOutputPath" -ForegroundColor Green
                                } catch {
                                    Write-Error "Failed to save Master Key: $_"
                                }
                            } else {
                                Write-Host "-------------- START master key --------------"
                                if($Format -eq "base64") {
                                    $base64EncodedMk = [System.Convert]::ToBase64String($mkByteArray)
                                    Write-Host $base64EncodedMk
                                } else {
                                    ($mkByteArray | ForEach-Object { "\x{0:X2}" -f $_ }) -join ""
                                }
                                Write-Host "--------------  EOF master key  --------------"
                            }

                        } else {
                            Write-Host "[!] Unable to find corresponding master key locally."
                        }          
                    } else {
                        Write-Host "[ERROR] Unable to determine user SID"
                    }
                }
                Write-Host "**********************************************************************"
            }
        }
    } else {
        Write-Warning "[!] ERROR: File or directory not found"
    }
    Write-Host "[*] Done."
}
