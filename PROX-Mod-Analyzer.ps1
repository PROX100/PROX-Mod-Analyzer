param(
    [string]$ModsPath = ""
)

$ErrorActionPreference = 'Continue'

# ============================================================
# PROX MOD ANALYZER V6
# Windows PowerShell 5.1 compatible
# Static-only: analyzed JARs are never executed.
# ============================================================

$ScriptVersion = '6.0'
$MaxArchiveEntryMB = 25
$MaxNestedDepth = 2
$WebTimeoutSeconds = 8

function Show-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host '=========================================================='
    Write-Host $Text
    Write-Host '=========================================================='
}

function Get-Hashes {
    param([string]$Path)
    [PSCustomObject]@{
        SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
        SHA1   = (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToLower()
    }
}

function Get-ZoneIdentifier {
    param([string]$Path)
    try {
        $lines = Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -like 'HostUrl=*') { return $line.Substring(8) }
        }
    } catch {}
    return $null
}

function Get-ModrinthInfo {
    param([string]$Sha1)
    try {
        $headers = @{ 'User-Agent' = "PROX-Mod-Analyzer/$ScriptVersion" }
        $version = Invoke-RestMethod -Uri ("https://api.modrinth.com/v2/version_file/" + $Sha1) -Headers $headers -TimeoutSec $WebTimeoutSeconds
        if ($null -eq $version) { return [PSCustomObject]@{Found=$false; Lookup='not_found'} }

        $project = $null
        if ($version.project_id) {
            $project = Invoke-RestMethod -Uri ("https://api.modrinth.com/v2/project/" + $version.project_id) -Headers $headers -TimeoutSec $WebTimeoutSeconds
        }

        $name = 'Unknown'
        $slug = 'Unknown'
        if ($project) {
            if ($project.title) { $name = [string]$project.title }
            if ($project.slug)  { $slug = [string]$project.slug }
        }

        return [PSCustomObject]@{
            Found     = $true
            Lookup    = 'match'
            Name      = $name
            Slug      = $slug
            Version   = [string]$version.version_number
            ProjectID = [string]$version.project_id
        }
    }
    catch {
        return [PSCustomObject]@{Found=$false; Lookup='error'}
    }
}

function Read-EntryBytes {
    param($Entry)
    $stream = $null
    $memory = $null
    try {
        $stream = $Entry.Open()
        $memory = New-Object System.IO.MemoryStream
        $stream.CopyTo($memory)
        return $memory.ToArray()
    }
    catch {
        return $null
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($memory) { $memory.Dispose() }
    }
}

function Read-EntryText {
    param($Entry)
    $bytes = Read-EntryBytes $Entry
    if ($null -eq $bytes) { return '' }
    try {
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        return ''
    }
}

function Get-AsciiStrings {
    param([byte[]]$Bytes)

    $list = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Bytes) { return $list }

    $sb = New-Object System.Text.StringBuilder

    foreach ($b in $Bytes) {
        if ($b -ge 32 -and $b -le 126) {
            [void]$sb.Append([char]$b)
        }
        else {
            if ($sb.Length -ge 4) { $list.Add($sb.ToString()) }
            $sb.Clear() | Out-Null
        }
    }

    if ($sb.Length -ge 4) { $list.Add($sb.ToString()) }
    return $list
}

function Add-Evidence {
    param(
        $List,
        [string]$Text,
        [int]$Limit = 30
    )
    if ($List.Count -lt $Limit -and $List -notcontains $Text) {
        $List.Add($Text)
    }
}

# ============================================================
# HIGH-CONFIDENCE CHEAT FEATURES
# Generic words are intentionally excluded.
# ============================================================

$CheatFeatureGroups = [ordered]@{
    'Combat automation' = @(
        'AimAssist','Aimbot','TriggerBot','AutoClicker','AutoCrystal',
        'AutoHitCrystal','AutoPot','AutoPotRefill','AutoWTap',
        'AutoJumpReset','AutoInventoryTotem','AutoDoubleHand',
        'AutoArmor','ShieldDisabler','ShieldBreaker','TotemOffhand',
        'CrystalOptimizer','AnchorMacro','DoubleAnchor','NoMissDelay',
        'KillAura','TargetStrafe','Reach','Hitboxes','Velocity','Criticals'
    )
    'Movement manipulation' = @(
        'PingSpoof','FakeLag','PacketSpoof','PacketFly','Freecam',
        'NoJumpDelay','NoBreakDelay','NoSlow','Scaffold','TimerHack',
        'Flight','Jesus','LongJump','SpeedHack','NoFall'
    )
    'Targeting / visual cheats' = @(
        'PlayerESP','StorageESP','ItemESP','EntityESP','ChestESP',
        'TargetESP','Tracers','FullBrightHack','Xray','NameTags'
    )
    'Anti-analysis / concealment' = @(
        'SelfDestruct','EncryptedString','DecryptString','AntiDebug',
        'AntiDump','MemoryScanner','HWID','HWIDCheck'
    )
}

$StrongCheatClassTokens = @(
    'AimAssist','Aimbot','TriggerBot','AutoClicker','AutoCrystal',
    'AutoHitCrystal','AutoPot','AutoWTap','AutoInventoryTotem',
    'AutoDoubleHand','AutoArmor','ShieldDisabler','ShieldBreaker',
    'TotemOffhand','CrystalOptimizer','AnchorMacro','DoubleAnchor',
    'PingSpoof','FakeLag','PacketSpoof','PacketFly','Freecam',
    'NoJumpDelay','NoBreakDelay','NoSlow','Scaffold','TimerHack',
    'Flight','Jesus','LongJump','SpeedHack','NoFall','KillAura',
    'TargetStrafe','Reach','Velocity','Criticals','PlayerESP',
    'StorageESP','ItemESP','EntityESP','ChestESP','TargetESP',
    'Tracers','Xray','SelfDestruct','AntiDebug','AntiDump'
)

# High-value architecture clues when correlated with cheat features.
$FrameworkTokens = @(
    'ModuleManager','EventManager','RotationManager','RotatorManager',
    'RotationUtils','MouseSimulation','PacketSendListener',
    'PacketReceiveListener','MovementPacketListener','TargetManager'
)

$HighRiskTokens = @(
    'VirtualAlloc','VirtualProtect','CreateRemoteThread',
    'WriteProcessMemory','ReadProcessMemory','OpenProcess',
    'NtWriteVirtualMemory','JNI_OnLoad','Invoke-Expression',
    'DownloadString','DownloadFile','powershell.exe','cmd.exe'
)

# API names alone are informational. They only score when correlated with stronger evidence.
$CapabilityTokens = @(
    'java/net/Socket','java/net/ServerSocket','java/net/URL',
    'java/net/HttpURLConnection','java/net/http/HttpClient',
    'java/lang/ProcessBuilder','Runtime.exec','java/lang/reflect',
    'java/io/File','java/nio/file'
)

# Things that are common in normal mods and should NOT score as cheats by themselves.
$IgnoreTerms = @(
    'ESP','HUD','Module','Modules','KeyBind','KeyBinding','Sprint',
    'Packet','Mouse','Keyboard','Client','Network','Reflection',
    'URL','File','Render','Target','Inventory','Mixin'
)

# ============================================================
# PATH
# ============================================================

if ([string]::IsNullOrWhiteSpace($ModsPath)) {
    $defaultPath = Join-Path $env:APPDATA '.minecraft\mods'
    $ModsPath = Read-Host "Mods folder [$defaultPath]"
    if ([string]::IsNullOrWhiteSpace($ModsPath)) { $ModsPath = $defaultPath }
}

$ModsPath = [Environment]::ExpandEnvironmentVariables($ModsPath)

if (-not (Test-Path -LiteralPath $ModsPath -PathType Container)) {
    Write-Host "[!] Folder does not exist: $ModsPath" -ForegroundColor Red
    exit 1
}

$jars = @(Get-ChildItem -LiteralPath $ModsPath -Filter '*.jar' -File)

Clear-Host
Show-Section "PROX MOD ANALYZER V$ScriptVersion"
Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

if ($jars.Count -eq 0) {
    Write-Host '[!] No JAR files found.' -ForegroundColor Yellow
    exit 0
}

# ============================================================
# RESULT GROUPS
# ============================================================

$verified = New-Object System.Collections.Generic.List[object]
$low      = New-Object System.Collections.Generic.List[object]
$review   = New-Object System.Collections.Generic.List[object]
$susp     = New-Object System.Collections.Generic.List[object]
$high     = New-Object System.Collections.Generic.List[object]
$unknown  = New-Object System.Collections.Generic.List[object]

# ============================================================
# ANALYSIS
# ============================================================

foreach ($jar in $jars) {

    $zip = $null

    try {
        $hashes = Get-Hashes $jar.FullName
        $mr = Get-ModrinthInfo $hashes.SHA1
        $origin = Get-ZoneIdentifier $jar.FullName

        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($jar.FullName)
        $entries = @($zip.Entries)

        $score = 0
        $reasons = New-Object System.Collections.Generic.List[string]
        $evidence = New-Object System.Collections.Generic.List[string]
        $featureEvidence = @{}
        $frameworkEvidence = New-Object System.Collections.Generic.List[string]
        $highRiskEvidence = New-Object System.Collections.Generic.List[string]

        foreach ($group in $CheatFeatureGroups.Keys) {
            $featureEvidence[$group] = New-Object System.Collections.Generic.List[string]
        }

        # --------------------------------------------------------
        # Metadata
        # --------------------------------------------------------

        $declaredId = ''
        $declaredName = ''
        $declaredVersion = ''
        $entrypoints = New-Object System.Collections.Generic.List[string]
        $mixins = New-Object System.Collections.Generic.List[string]

        foreach ($metadataName in @('fabric.mod.json','quilt.mod.json')) {
            $metaEntry = $zip.GetEntry($metadataName)
            if ($metaEntry) {
                try {
                    $meta = (Read-EntryText $metaEntry) | ConvertFrom-Json

                    if ($meta.id) { $declaredId = [string]$meta.id }
                    if ($meta.name) { $declaredName = [string]$meta.name }
                    if ($meta.version) { $declaredVersion = [string]$meta.version }

                    if ($meta.entrypoints) {
                        foreach ($prop in $meta.entrypoints.PSObject.Properties) {
                            foreach ($value in @($prop.Value)) {
                                if ($value -is [string]) {
                                    $entrypoints.Add([string]$value)
                                }
                                elseif ($value.value) {
                                    $entrypoints.Add([string]$value.value)
                                }
                            }
                        }
                    }

                    if ($meta.mixins) {
                        foreach ($mixin in @($meta.mixins)) {
                            if ($mixin) { $mixins.Add([string]$mixin) }
                        }
                    }
                }
                catch {}
                break
            }
        }

        # --------------------------------------------------------
        # Archive facts
        # --------------------------------------------------------

        $classPaths = @(
            $entries |
            Where-Object { $_.FullName -match '\.class$' } |
            ForEach-Object { [string]$_.FullName }
        )

        $classCount = $classPaths.Count
        $nestedJars = @(
            $entries |
            Where-Object { $_.FullName -match '\.jar$' }
        )

        # --------------------------------------------------------
        # Obfuscation / naming signal
        # --------------------------------------------------------

        $shortCount = 0
        foreach ($path in $classPaths) {
            $simple = ([System.IO.Path]::GetFileNameWithoutExtension($path))
            if ($simple.Length -le 2) { $shortCount++ }
        }

        $shortRatio = 0
        if ($classCount -gt 0) { $shortRatio = $shortCount / $classCount }

        if ($classCount -gt 10 -and $shortRatio -ge 0.35) {
            $score += 5
            $reasons.Add('Strong class-name obfuscation signal')
            Add-Evidence $evidence ("Short classes: $shortCount/$classCount ($([math]::Round($shortRatio * 100,1))%)")
        }

        # --------------------------------------------------------
        # Scan metadata/mixin JSON as text
        # --------------------------------------------------------

        foreach ($entry in $entries) {
            if ($entry.FullName.EndsWith('/')) { continue }
            if ($entry.Length -gt ($MaxArchiveEntryMB * 1MB)) { continue }

            $nameLower = $entry.FullName.ToLowerInvariant()
            $shouldScanText = (
                $nameLower -match '(fabric\.mod\.json|quilt\.mod\.json|mixins?\.json|\.properties$|\.toml$)' -or
                $nameLower -match '\.class$'
            )

            if (-not $shouldScanText) { continue }

            $bytes = Read-EntryBytes $entry
            if ($null -eq $bytes) { continue }

            $ascii = Get-AsciiStrings $bytes

            foreach ($term in $HighRiskTokens) {
                foreach ($s in $ascii) {
                    if ($s.IndexOf($term,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        Add-Evidence $highRiskEvidence "$term -> $($entry.FullName)" 20
                        break
                    }
                }
            }

            # Do not use generic capability tokens for scoring here.
            # They are collected only when a stronger cheat fingerprint exists.
            foreach ($group in $CheatFeatureGroups.Keys) {
                foreach ($term in $CheatFeatureGroups[$group]) {
                    foreach ($s in $ascii) {
                        if ($s.IndexOf($term,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            Add-Evidence $featureEvidence[$group] "$term -> $($entry.FullName)" 15
                            break
                        }
                    }
                }
            }

            foreach ($term in $FrameworkTokens) {
                foreach ($s in $ascii) {
                    if ($s.IndexOf($term,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        Add-Evidence $frameworkEvidence "$term -> $($entry.FullName)" 20
                        break
                    }
                }
            }
        }

        # --------------------------------------------------------
        # Class-path analysis
        # This is intentionally stronger than searching resource text.
        # --------------------------------------------------------

        foreach ($path in $classPaths) {

            $simpleClass = [System.IO.Path]::GetFileNameWithoutExtension($path)

            foreach ($group in $CheatFeatureGroups.Keys) {
                foreach ($term in $StrongCheatClassTokens) {
                    if ($simpleClass.IndexOf($term,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        Add-Evidence $featureEvidence[$group] "CLASS: $path" 15
                    }
                }
            }

            foreach ($term in $FrameworkTokens) {
                if ($simpleClass.IndexOf($term,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    Add-Evidence $frameworkEvidence "CLASS: $path" 20
                }
            }
        }

        # --------------------------------------------------------
        # Detect module/category style package architecture.
        # This only counts when strong cheat features are already present.
        # --------------------------------------------------------

        $modulePathCount = @(
            $classPaths |
            Where-Object {
                $_ -match '(?i)(^|/)module(/|/modules/)' -or
                $_ -match '(?i)/modules/(combat|movement|misc|render|player)/'
            }
        ).Count

        $cheatCategoryCount = 0
        foreach ($group in $featureEvidence.Keys) {
            if ($featureEvidence[$group].Count -gt 0) {
                $cheatCategoryCount++
            }
        }

        # Strong feature-category scoring.
        if ($cheatCategoryCount -ge 3) {
            $score += 55
            $reasons.Add('Multiple independent cheat-feature categories')
        }
        elseif ($cheatCategoryCount -eq 2) {
            $score += 35
            $reasons.Add('Multiple cheat-feature categories')
        }
        elseif ($cheatCategoryCount -eq 1) {
            $score += 15
            $reasons.Add('Specific cheat-feature indicators')
        }

        # A dedicated module architecture makes a collection of cheat features stronger.
        if ($modulePathCount -ge 5 -and $cheatCategoryCount -ge 1) {
            $score += 10
            $reasons.Add('Cheat-style module architecture')
            Add-Evidence $evidence "Module-style class paths: $modulePathCount"
        }

        # Framework clues only matter when paired with a cheat category.
        if ($frameworkEvidence.Count -ge 2 -and $cheatCategoryCount -ge 1) {
            $score += 10
            $reasons.Add('Cheat-client framework indicators')
            foreach ($x in $frameworkEvidence | Select-Object -First 8) {
                Add-Evidence $evidence $x
            }
        }

        # High-risk execution/network indicators are supplemental.
        if ($highRiskEvidence.Count -gt 0) {
            $score += 25
            $reasons.Add('High-risk execution indicator(s)')
            foreach ($x in $highRiskEvidence | Select-Object -First 10) {
                Add-Evidence $evidence $x
            }
        }

        # --------------------------------------------------------
        # Metadata / code identity checks
        # Conservative: only strong mismatch patterns score.
        # --------------------------------------------------------

        $topPackages = @()
        foreach ($path in $classPaths) {
            if ($path -match '^([^/]+/[^/]+)/') {
                $topPackages += $Matches[1]
            }
        }
        $topPackages = @($topPackages | Select-Object -Unique)

        # Suspicious only when the declared identity says one thing but an entrypoint
        # clearly says a cheat/client identity.
        if ($entrypoints.Count -gt 0) {
            foreach ($ep in $entrypoints) {
                if ($ep -match '(?i)argon|cheat|hack|ghostclient|clickgui') {
                    $score += 30
                    $reasons.Add('Suspicious client/cheat entrypoint')
                    Add-Evidence $evidence "Entrypoint: $ep"
                }
            }
        }

        # Argon-specific family fingerprint from the supplied sample.
        $argonPaths = @(
            $classPaths |
            Where-Object { $_ -match '(?i)(^|/)dev/lvstrng/argon/' }
        )

        if ($argonPaths.Count -ge 2) {
            $score += 70
            $reasons.Add('Argon-family namespace detected')
            Add-Evidence $evidence "Argon namespace classes: $($argonPaths.Count)"
        }

        # Mixin surface: only meaningful when focused on client input/network hooks AND cheat features.
        $interestingMixins = @(
            $mixins |
            Where-Object {
                $_ -match '(?i)mouse|keyboard|connection|player|camera|interaction|packet'
            }
        )

        if ($interestingMixins.Count -ge 4 -and $cheatCategoryCount -ge 1) {
            $score += 10
            $reasons.Add('Cheat-relevant client mixin surface')
            foreach ($m in $interestingMixins | Select-Object -First 8) {
                Add-Evidence $evidence "Mixin: $m"
            }
        }

        # Nested jars are evidence only, not risk by themselves.
        if ($nestedJars.Count -gt 0) {
            Add-Evidence $evidence "Embedded JARs: $($nestedJars.Count)"
        }

        # --------------------------------------------------------
        # Reputation handling
        # --------------------------------------------------------

        $score = [Math]::Min(100,[Math]::Max(0,$score))

        # Exact Modrinth match identifies the exact bytes. It does not erase behavior evidence.
        if ($score -ge 75) {
            $verdict = 'HIGH RISK'
        }
        elseif ($score -ge 45) {
            $verdict = 'SUSPICIOUS'
        }
        elseif ($score -ge 20) {
            $verdict = 'REVIEW'
        }
        else {
            $verdict = 'LOW RISK'
        }

        if ($mr.Found -and $score -eq 0) {
            $verdict = 'VERIFIED'
        }
        elseif ($mr.Found -and $score -lt 10) {
            $verdict = 'VERIFIED'
        }

        $displayName = $jar.BaseName
        if ($mr.Found -and $mr.Name -ne 'Unknown') {
            $displayName = $mr.Name
        }
        elseif ($declaredName) {
            $displayName = $declaredName
        }

        $result = [PSCustomObject]@{
            Name       = $displayName
            File       = $jar.Name
            SHA256     = $hashes.SHA256
            SHA1       = $hashes.SHA1
            Score      = $score
            Verdict    = $verdict
            Reasons    = $reasons
            Evidence   = $evidence
            Modrinth   = $mr
            Origin     = $origin
            ClassCount = $classCount
        }

        if ($verdict -eq 'VERIFIED') {
            $verified.Add($result)
        }
        elseif ($score -lt 20) {
            $low.Add($result)
        }
        elseif ($score -lt 45) {
            $review.Add($result)
        }
        elseif ($score -lt 75) {
            $susp.Add($result)
        }
        else {
            $high.Add($result)
        }
    }
    catch {
        $unknown.Add(
            [PSCustomObject]@{
                Name  = $jar.BaseName
                File  = $jar.Name
                Error = $_.Exception.Message
            }
        )
    }
    finally {
        if ($zip) { $zip.Dispose() }
    }
}

# ============================================================
# HABIBI-STYLE COMPACT OUTPUT
# ============================================================

Clear-Host
Show-Section "PROX MOD ANALYZER V$ScriptVersion"
Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

function Print-CompactGroup {
    param(
        [string]$Title,
        $Items,
        [ConsoleColor]$Color,
        [bool]$ShowFile,
        [bool]$ShowScore
    )

    Write-Host ""
    Write-Host "{ $Title }" -ForegroundColor $Color

    if ($Items.Count -eq 0) {
        Write-Host "> None"
        return
    }

    foreach ($item in $Items) {
        $line = "> " + $item.Name

        if ($ShowFile) {
            $line += "  " + $item.File
        }

        if ($ShowScore) {
            $line += "  [$($item.Score)/100]"
        }

        Write-Host $line
    }
}

# Keep normal output extremely short.
Print-CompactGroup "Verified Mods" $verified Green $true $false
Print-CompactGroup "Low Risk" $low Gray $true $true
Print-CompactGroup "Review" $review Yellow $true $true
Print-CompactGroup "Suspicious" $susp DarkYellow $true $true
Print-CompactGroup "High Risk" $high Red $true $true
Print-CompactGroup "Unknown" $unknown Magenta $true $false

# One-line reason for flagged mods only.
$flagged = @()
foreach ($item in $review) { $flagged += $item }
foreach ($item in $susp)   { $flagged += $item }
foreach ($item in $high)   { $flagged += $item }

if ($flagged.Count -gt 0) {
    Write-Host ""
    Write-Host "{ Flags }" -ForegroundColor Yellow

    foreach ($item in $flagged) {
        $reasonText = "static indicators detected"

        if ($item.Reasons.Count -gt 0) {
            $reasonText = (($item.Reasons | Select-Object -Unique) -join ", ")
        }

        Write-Host ("> " + $item.Name + "  -  " + $reasonText)
    }
}

Write-Host ""
Write-Host "{ Summary }"
Write-Host "> Total:      $($jars.Count)"
Write-Host "> Verified:   $($verified.Count)"
Write-Host "> Low Risk:   $($low.Count)"
Write-Host "> Review:     $($review.Count)"
Write-Host "> Suspicious: $($susp.Count)"
Write-Host "> High Risk:  $($high.Count)"
Write-Host "> Unknown:    $($unknown.Count)"

Write-Host ""
Write-Host "Static analysis only. A clean result is not proof of safety."
