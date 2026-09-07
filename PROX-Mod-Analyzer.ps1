param(
    [string]$ModsPath = "",
    [switch]$VerboseOutput
)

$ErrorActionPreference = "Continue"
$script:Version = "3.0"
$script:MaxEntryBytes = 15MB
$script:MaxNestedDepth = 3

function Show-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 58)
    Write-Host $Text
    Write-Host ("=" * 58)
}

function Get-Hashes {
    param([string]$Path)
    [PSCustomObject]@{
        SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
        SHA1   = (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToLower()
    }
}

function Get-FileOrigin {
    param([string]$Path)
    try {
        $lines = Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop
        $h = $lines | Where-Object { $_ -like 'HostUrl=*' } | Select-Object -First 1
        if ($h) { return $h.Substring(8) }
    } catch {}
    return $null
}

function Get-ModrinthInfo {
    param([string]$Sha1)
    try {
        $headers = @{ 'User-Agent' = "PROX-Mod-Analyzer/$script:Version" }
        $v = Invoke-RestMethod -UseBasicParsing -Uri "https://api.modrinth.com/v2/version_file/$Sha1" -Headers $headers -TimeoutSec 8
        if (-not $v) { return [PSCustomObject]@{ Found = $false; Error = 'No result' } }
        $p = $null
        if ($v.project_id) {
            try { $p = Invoke-RestMethod -UseBasicParsing -Uri "https://api.modrinth.com/v2/project/$($v.project_id)" -Headers $headers -TimeoutSec 8 } catch {}
        }
        [PSCustomObject]@{
            Found = $true
            ProjectID = $v.project_id
            VersionID = $v.id
            Name = if ($p) { $p.title } else { 'Unknown' }
            Slug = if ($p) { $p.slug } else { 'Unknown' }
            Version = $v.version_number
        }
    } catch {
        [PSCustomObject]@{ Found = $false; Error = $_.Exception.Message }
    }
}

# Exact fingerprints for known samples. These are evidence, not a universal blacklist.
$KnownFingerprints = @{
    'fd311430c688859bc867e739cddfe709cc8dea13' = 'Argon (known sample)'
}

# Strong semantic names commonly present in cheat clients.
$CheatRules = [ordered]@{
    'Combat automation' = @(
        'AimAssist','TriggerBot','AutoClicker','AutoCrystal','AutoHitCrystal','AutoPot',
        'AutoTotem','AutoInventoryTotem','AutoWTap','AnchorMacro','DoubleAnchor',
        'CrystalOptimizer','ShieldDisabler','TotemOffhand'
    )
    'Movement / manipulation' = @(
        'Freecam','PingSpoof','FakeLag','NoJumpDelay','NoBreakDelay','Velocity',
        'Sprint','PackSpoof','MovementPacket','RotatorManager','RotationUtils'
    )
    'ESP / player targeting' = @(
        'PlayerESP','TargetHud','TargetHUD','FriendManager','Target','EntityESP'
    )
    'Cheat framework' = @(
        '/module/Module.class','/module/modules/','ClickGUI','ModuleManager','BooleanSetting',
        'KeybindSetting','ModeSetting','NumberSetting','MinMaxSetting','MouseSimulation'
    )
    'Packet manipulation' = @(
        'PacketSendListener','PacketReceiveListener','onPacketSend','onPacketReceive',
        'MovementPacketListener','packetQueue','Serverbound','Clientbound'
    )
    'Self protection / cleanup' = @(
        'SelfDestruct','Self-Destruct','deleteOnExit','deleteOnShutdown','shutdownHook'
    )
}

$CapabilityRules = [ordered]@{
    'Process execution' = @(
        'java/lang/ProcessBuilder','java/lang/Runtime','Runtime.exec','ProcessBuilder.start'
    )
    'Network communication' = @(
        'java/net/Socket','java/net/ServerSocket','java/net/HttpURLConnection','java/net/URLConnection',
        'java/net/http/HttpClient','java/net/URL','okhttp','java/nio/channels/SocketChannel'
    )
    'Command shell' = @('cmd.exe','powershell.exe','pwsh','/bin/sh','/bin/bash')
    'Web download / script execution' = @(
        'Invoke-WebRequest','Invoke-RestMethod','DownloadString','DownloadFile',
        'powershell -enc','powershell -encodedcommand','Invoke-Expression'
    )
    'Native / OS interaction' = @(
        'System.loadLibrary','java/lang/ProcessHandle','jnidispatch','jna','kernel32',
        'CreateRemoteThread','WriteProcessMemory','VirtualAlloc','OpenProcess'
    )
}

function Add-Hit {
    param(
        [hashtable]$Table,
        [string]$Category,
        [string]$Indicator,
        [string]$Source
    )
    if (-not $Table.ContainsKey($Category)) { $Table[$Category] = New-Object System.Collections.Generic.List[string] }
    $value = "$Indicator -> $Source"
    if (-not ($Table[$Category] -contains $value)) { $Table[$Category].Add($value) }
}

function Get-PrintableText {
    param([byte[]]$Bytes)
    $sb = New-Object System.Text.StringBuilder
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($b in $Bytes) {
        if ($b -ge 32 -and $b -le 126) {
            [void]$sb.Append([char]$b)
        } elseif ($sb.Length -ge 4) {
            $out.Add($sb.ToString())
            $sb.Clear() | Out-Null
        } else {
            $sb.Clear() | Out-Null
        }
    }
    if ($sb.Length -ge 4) { $out.Add($sb.ToString()) }
    return $out
}

function Get-ClassInfo {
    param([string]$Name)
    $s = $Name -replace '\.class$',''
    $parts = $s -split '/'
    [PSCustomObject]@{ Full = $s; Simple = $parts[-1]; Package = (($parts[0..([Math]::Max(0,$parts.Count-2))]) -join '/') }
}

function Test-ClassNameSignals {
    param(
        [string]$Name,
        [hashtable]$Hits
    )
    $c = Get-ClassInfo $Name
    $low = $c.Full.ToLowerInvariant()
    $cheatWords = @(
        'aimassist','triggerbot','autoclick','autocrystal','autototem','autopot','freecam',
        'pingspoof','fakelag','velocity','playeresp','targethud','selfdestruct','shielddisabler',
        'module/modules/combat','module/modules/misc','module/modules/render','mousesimulation','rotatormanager'
    )
    foreach ($w in $cheatWords) {
        if ($low.Contains($w)) { Add-Hit $Hits 'Cheat-specific class names' $w $Name }
    }
}

function Scan-ZipArchive {
    param(
        [System.IO.Stream]$Stream,
        [int]$Depth,
        [string]$Prefix,
        [hashtable]$Hits,
        [System.Collections.Generic.List[string]]$Embedded,
        [System.Collections.Generic.List[string]]$Metadata,
        [System.Collections.Generic.List[string]]$Classes,
        [System.Collections.Generic.List[string]]$Urls,
        [System.Collections.Generic.List[string]]$Errors
    )

    if ($Depth -gt $script:MaxNestedDepth) { return }

    $zip = $null
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($Stream,[System.IO.Compression.ZipArchiveMode]::Read,$true)
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName.EndsWith('/')) { continue }
            $source = if ($Prefix) { "$Prefix/$($entry.FullName)" } else { $entry.FullName }

            if ($entry.FullName -match '\.class$') {
                $Classes.Add($source)
                Test-ClassNameSignals -Name $source -Hits $Hits
            }

            if ($entry.FullName -in @('fabric.mod.json','quilt.mod.json','META-INF/mods.toml','mcmod.info')) {
                $Metadata.Add($source)
                try {
                    $reader = New-Object System.IO.StreamReader($entry.Open(),[Text.Encoding]::UTF8,$true)
                    $mt = $reader.ReadToEnd(); $reader.Dispose()
                    if ($entry.FullName -match 'fabric|quilt') {
                        try {
                            $j = $mt | ConvertFrom-Json
                            if ($j.name) { Add-Hit $Hits 'Metadata' "mod:$($j.name)" $source }
                            if ($j.id) { Add-Hit $Hits 'Metadata' "id:$($j.id)" $source }
                            if ($j.entrypoints) { Add-Hit $Hits 'Metadata' "entrypoints" $source }
                            if ($j.mixins) { Add-Hit $Hits 'Metadata' "mixins" $source }
                        } catch {}
                    }
                    if ($mt -match 'https?://[^\s"''<>]+') {
                        foreach ($u in [regex]::Matches($mt,'https?://[^\s"''<>]+')) {
                            if ($Urls.Count -lt 25) { $Urls.Add($u.Value) }
                        }
                    }
                } catch {}
                continue
            }

            if ($entry.FullName -match '(MANIFEST\.MF|\.properties|\.json|\.toml|\.cfg|\.txt)$' -and $entry.Length -le $script:MaxEntryBytes) {
                try {
                    $reader = New-Object System.IO.StreamReader($entry.Open(),[Text.Encoding]::UTF8,$true)
                    $txt = $reader.ReadToEnd(); $reader.Dispose()
                    foreach ($cat in $CheatRules.Keys) {
                        foreach ($ind in $CheatRules[$cat]) {
                            if ($txt.IndexOf($ind,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                Add-Hit $Hits $cat $ind $source
                            }
                        }
                    }
                    foreach ($cat in $CapabilityRules.Keys) {
                        foreach ($ind in $CapabilityRules[$cat]) {
                            if ($txt.IndexOf($ind,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                Add-Hit $Hits $cat $ind $source
                            }
                        }
                    }
                    if ($txt -match 'https?://[^\s"''<>]+') {
                        foreach ($u in [regex]::Matches($txt,'https?://[^\s"''<>]+')) {
                            if ($Urls.Count -lt 25) { $Urls.Add($u.Value) }
                        }
                    }
                } catch {}
            }

            if ($entry.Length -le $script:MaxEntryBytes -and $entry.FullName -match '\.(class|jar|dll|so|dylib|exe)$') {
                try {
                    $ms = New-Object IO.MemoryStream
                    $entry.Open().CopyTo($ms)
                    $bytes = $ms.ToArray(); $ms.Dispose()
                    $text = (Get-PrintableText $bytes) -join "`n"
                    foreach ($cat in $CheatRules.Keys) {
                        foreach ($ind in $CheatRules[$cat]) {
                            if ($text.IndexOf($ind,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                Add-Hit $Hits $cat $ind $source
                            }
                        }
                    }
                    foreach ($cat in $CapabilityRules.Keys) {
                        foreach ($ind in $CapabilityRules[$cat]) {
                            if ($text.IndexOf($ind,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                Add-Hit $Hits $cat $ind $source
                            }
                        }
                    }
                    if ($text -match 'https?://[^\s"''<>]+') {
                        foreach ($u in [regex]::Matches($text,'https?://[^\s"''<>]+')) {
                            if ($Urls.Count -lt 25) { $Urls.Add($u.Value) }
                        }
                    }
                } catch {}
            }

            if ($entry.FullName -match '\.jar$' -and $Depth -lt $script:MaxNestedDepth -and $entry.Length -le 50MB) {
                $Embedded.Add($source)
                try {
                    $ms = New-Object IO.MemoryStream
                    $entry.Open().CopyTo($ms)
                    $ms.Position = 0
                    Scan-ZipArchive -Stream $ms -Depth ($Depth+1) -Prefix $source -Hits $Hits -Embedded $Embedded -Metadata $Metadata -Classes $Classes -Urls $Urls -Errors $Errors
                    $ms.Dispose()
                } catch { $Errors.Add("Nested archive ${source}: $($_.Exception.Message)") }
            }
        }
    } catch {
        $Errors.Add("Archive: $($_.Exception.Message)")
    } finally {
        if ($zip) { $zip.Dispose() }
    }
}

# ------------------------------------------------------------
# Locate mods
# ------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($ModsPath)) {
    $default = Join-Path $env:APPDATA '.minecraft\mods'
    $ModsPath = Read-Host "Mods folder [$default]"
    if ([string]::IsNullOrWhiteSpace($ModsPath)) { $ModsPath = $default }
}
$ModsPath = [Environment]::ExpandEnvironmentVariables($ModsPath)

if (-not (Test-Path -LiteralPath $ModsPath -PathType Container)) {
    Write-Host "[!] Folder does not exist: $ModsPath" -ForegroundColor Red
    exit 1
}

$jars = @(Get-ChildItem -LiteralPath $ModsPath -Filter '*.jar' -File)

Clear-Host
Show-Section "PROX MOD ANALYZER V$script:Version"
Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

if ($jars.Count -eq 0) {
    Write-Host '[!] No JAR files found.' -ForegroundColor Yellow
    exit 0
}

$verified = New-Object System.Collections.Generic.List[object]
$low = New-Object System.Collections.Generic.List[object]
$review = New-Object System.Collections.Generic.List[object]
$suspicious = New-Object System.Collections.Generic.List[object]
$high = New-Object System.Collections.Generic.List[object]
$unknown = New-Object System.Collections.Generic.List[object]

foreach ($jar in $jars) {
    try {
        $hashes = Get-Hashes $jar.FullName
        $mr = Get-ModrinthInfo $hashes.SHA1
        $origin = Get-FileOrigin $jar.FullName
        $hits = @{}
        $embedded = New-Object System.Collections.Generic.List[string]
        $metadata = New-Object System.Collections.Generic.List[string]
        $classes = New-Object System.Collections.Generic.List[string]
        $urls = New-Object System.Collections.Generic.List[string]
        $errors = New-Object System.Collections.Generic.List[string]

        $score = 0
        $reasons = New-Object System.Collections.Generic.List[string]

        # Exact known fingerprints are extremely strong evidence.
        if ($KnownFingerprints.ContainsKey($hashes.SHA1)) {
            Add-Hit $hits 'Known fingerprint' $KnownFingerprints[$hashes.SHA1] $jar.Name
            $score += 100
            $reasons.Add('Exact known fingerprint match')
        }

        $fs = [IO.File]::OpenRead($jar.FullName)
        Scan-ZipArchive -Stream $fs -Depth 0 -Prefix '' -Hits $hits -Embedded $embedded -Metadata $metadata -Classes $classes -Urls $urls -Errors $errors
        $fs.Dispose()

        # Package/name based signals; useful against renamed cheat clients.
        $allClassText = ($classes -join "`n").ToLowerInvariant()
        if ($allClassText.Contains('dev/lvstrng/argon/')) {
            Add-Hit $hits 'Known client namespace' 'dev/lvstrng/argon/' 'class paths'
            $score += 80
            $reasons.Add('Known Argon client namespace detected')
        }

        # Count semantic cheat-specific categories.
        $semanticCategories = @('Combat automation','Movement / manipulation','ESP / player targeting','Cheat framework','Packet manipulation','Self protection / cleanup','Cheat-specific class names')
        foreach ($cat in $semanticCategories) {
            if ($hits.ContainsKey($cat)) {
                switch ($cat) {
                    'Combat automation' { $score += 18; $reasons.Add('Cheat-specific combat automation') }
                    'Movement / manipulation' { $score += 12; $reasons.Add('Cheat-specific movement/manipulation') }
                    'ESP / player targeting' { $score += 10; $reasons.Add('ESP/targeting functionality') }
                    'Cheat framework' { $score += 8; $reasons.Add('Client module/settings framework') }
                    'Packet manipulation' { $score += 10; $reasons.Add('Packet interception/manipulation') }
                    'Self protection / cleanup' { $score += 12; $reasons.Add('Self-protection/cleanup behavior') }
                    'Cheat-specific class names' { $score += 10; $reasons.Add('Cheat-specific class names') }
                }
            }
        }

        if ($hits.ContainsKey('Process execution')) { $score += 10; $reasons.Add('Process execution capability') }
        if ($hits.ContainsKey('Network communication')) { $score += 5; $reasons.Add('Network communication capability') }
        if ($hits.ContainsKey('Command shell')) { $score += 20; $reasons.Add('Command shell capability') }
        if ($hits.ContainsKey('Web download / script execution')) { $score += 20; $reasons.Add('Web/script execution capability') }
        if ($hits.ContainsKey('Native / OS interaction')) { $score += 20; $reasons.Add('Native/OS interaction capability') }

        # Metadata mismatch: an unexpected mod name/metadata pairing is worth review.
        $fabricMeta = @($metadata | Where-Object { $_ -match '(?i)(^|/)fabric\.mod\.json$' })
        if ($fabricMeta.Count -gt 0 -and $hits.ContainsKey('Known client namespace')) {
            $reasons.Add('Mod metadata conflicts with detected client code')
            $score += 15
        }

        # Very short class names can be obfuscation, but weak evidence only.
        $short = 0
        foreach ($c in $classes) {
            $name = (Get-ClassInfo $c).Simple
            if ($name.Length -le 2) { $short++ }
        }
        if ($classes.Count -gt 20) {
            $ratio = $short / $classes.Count
            if ($ratio -ge 0.35) {
                $score += 5
                $reasons.Add('Large proportion of very short class names')
            }
        }

        $score = [Math]::Min(100,$score)

        if ($score -ge 75) { $verdict = 'HIGH RISK' }
        elseif ($score -ge 35) { $verdict = 'SUSPICIOUS' }
        elseif ($score -ge 12) { $verdict = 'REVIEW' }
        else { $verdict = 'LOW RISK' }

        $name = $jar.BaseName
        if ($mr.Found -and $mr.Name) { $name = $mr.Name }

        $obj = [PSCustomObject]@{
            Name=$name; File=$jar.Name; SHA256=$hashes.SHA256; SHA1=$hashes.SHA1; Score=$score; Verdict=$verdict
            Reasons=$reasons; Hits=$hits; Modrinth=$mr; Origin=$origin; Embedded=$embedded; Metadata=$metadata
            Classes=$classes; URLs=$urls; Errors=$errors
        }

        # Exact Modrinth match is verified only when the scanner found no meaningful suspicious evidence.
        $hasStrong = ($score -ge 12) -or $hits.ContainsKey('Known fingerprint') -or $hits.ContainsKey('Known client namespace') -or $hits.ContainsKey('Cheat-specific class names')
        if ($mr.Found -and -not $hasStrong) { $verified.Add($obj) }
        elseif ($verdict -eq 'LOW RISK') { $low.Add($obj) }
        elseif ($verdict -eq 'REVIEW') { $review.Add($obj) }
        elseif ($verdict -eq 'SUSPICIOUS') { $suspicious.Add($obj) }
        else { $high.Add($obj) }
    }
    catch {
        $unknown.Add([PSCustomObject]@{ Name=$jar.BaseName; File=$jar.Name; Error=$_.Exception.Message })
    }
}

# ------------------------------------------------------------
# Compact report
# ------------------------------------------------------------
Clear-Host
Show-Section "PROX MOD ANALYZER V$script:Version"
Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

Write-Host "`n{ Verified Mods }" -ForegroundColor Green
if ($verified.Count -eq 0) { Write-Host '> None' }
else { foreach ($m in $verified) { Write-Host ('> ' + $m.Name.PadRight(30) + $m.File) } }

Write-Host "`n{ Low Risk }" -ForegroundColor Green
if ($low.Count -eq 0) { Write-Host '> None' }
else { foreach ($m in $low) { Write-Host ('> ' + $m.Name.PadRight(30) + "$($m.File)  [$($m.Score)/100]") } }

Write-Host "`n{ Review }" -ForegroundColor Yellow
if ($review.Count -eq 0) { Write-Host '> None' }
else { foreach ($m in $review) { Write-Host ('> ' + $m.Name.PadRight(30) + "$($m.File)  [$($m.Score)/100]") } }

Write-Host "`n{ Suspicious }" -ForegroundColor DarkYellow
if ($suspicious.Count -eq 0) { Write-Host '> None' }
else { foreach ($m in $suspicious) { Write-Host ('> ' + $m.Name.PadRight(30) + "$($m.File)  [$($m.Score)/100]") } }

Write-Host "`n{ High Risk }" -ForegroundColor Red
if ($high.Count -eq 0) { Write-Host '> None' }
else { foreach ($m in $high) { Write-Host ('> ' + $m.Name.PadRight(30) + "$($m.File)  [$($m.Score)/100]") } }

Write-Host "`n{ Unknown }" -ForegroundColor Magenta
if ($unknown.Count -eq 0) { Write-Host '> None' }
else { foreach ($m in $unknown) { Write-Host ('> ' + $m.Name.PadRight(30) + $m.File) } }

$flagged = @($review + $suspicious + $high)
if ($flagged.Count -gt 0 -or $unknown.Count -gt 0) {
    Show-Section 'FLAGGED DETAILS'
    foreach ($m in $flagged) {
        Write-Host "`n$($m.File)" -ForegroundColor Yellow
        Write-Host "    Score: $($m.Score)/100  Verdict: $($m.Verdict)"
        if ($m.Modrinth.Found) { Write-Host "    Modrinth: $($m.Modrinth.Name) $($m.Modrinth.Version)" }
        else { Write-Host '    Modrinth: No exact SHA-1 match' }
        Write-Host "    SHA-1:   $($m.SHA1)"
        Write-Host "    SHA-256: $($m.SHA256)"
        if ($m.Origin) { Write-Host "    Origin:  $($m.Origin)" }
        if ($m.Reasons.Count -gt 0) { Write-Host '    Reasons:'; $m.Reasons | Select-Object -Unique | ForEach-Object { Write-Host "        - $_" } }
        foreach ($cat in $m.Hits.Keys) {
            if ($cat -eq 'Metadata') { continue }
            Write-Host "    ${cat}:`n" -NoNewline
            foreach ($hit in @($m.Hits[$cat] | Select-Object -First 8)) { Write-Host "        $hit" }
        }
        if ($m.Embedded.Count -gt 0) { Write-Host "    Embedded JARs: $($m.Embedded.Count)" }
        if ($m.Errors.Count -gt 0) { Write-Host "    Analyzer warnings: $($m.Errors.Count)" }
    }
    foreach ($m in $unknown) {
        Write-Host "`n$($m.File)" -ForegroundColor Magenta
        Write-Host "    Analysis failed: $($m.Error)"
    }
}

Show-Section 'SUMMARY'
Write-Host "Total:       $($jars.Count)"
Write-Host "Verified:    $($verified.Count)" -ForegroundColor Green
Write-Host "Low Risk:    $($low.Count)" -ForegroundColor Green
Write-Host "Review:      $($review.Count)" -ForegroundColor Yellow
Write-Host "Suspicious:  $($suspicious.Count)" -ForegroundColor DarkYellow
Write-Host "High Risk:   $($high.Count)" -ForegroundColor Red
Write-Host "Unknown:     $($unknown.Count)" -ForegroundColor Magenta
Write-Host ""
Write-Host 'IMPORTANT:'
Write-Host '    This tool performs static analysis and reputation checks.'
Write-Host '    No static scanner can guarantee that every future or obfuscated threat will be detected.'
Write-Host '    A clean result is not proof that a mod is safe.'
Show-Section 'Analysis complete.'
