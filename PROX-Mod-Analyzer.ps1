param(
    [string]$ModsPath = ""
)

$ErrorActionPreference = "Continue"

# ============================================================
# PROX MOD ANALYZER
# Windows PowerShell 5.1 compatible
# ============================================================

function Show-Section {
    param(
        [string]$Text
    )

    Write-Host ""
    Write-Host "=========================================================="
    Write-Host $Text
    Write-Host "=========================================================="
}

function Get-FileHashes {
    param(
        [string]$Path
    )

    $sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
    $sha1   = (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToLower()

    return [PSCustomObject]@{
        SHA256 = $sha256
        SHA1   = $sha1
    }
}

function Get-ZoneIdentifier {
    param(
        [string]$Path
    )

    try {
        $lines = Get-Content `
            -LiteralPath $Path `
            -Stream Zone.Identifier `
            -ErrorAction Stop

        foreach ($line in $lines) {
            if ($line -like "HostUrl=*") {
                return $line.Substring(8)
            }
        }
    }
    catch {
    }

    return $null
}

function Get-ModrinthInfo {
    param(
        [string]$Sha1
    )

    try {
        $headers = @{
            "User-Agent" = "PROX-Mod-Analyzer/1.0"
        }

        $version = Invoke-RestMethod `
            -Uri ("https://api.modrinth.com/v2/version_file/" + $Sha1) `
            -Headers $headers `
            -TimeoutSec 8

        if ($null -eq $version) {
            return [PSCustomObject]@{
                Found = $false
            }
        }

        $project = $null

        if ($version.project_id) {
            $project = Invoke-RestMethod `
                -Uri ("https://api.modrinth.com/v2/project/" + $version.project_id) `
                -Headers $headers `
                -TimeoutSec 8
        }

        $projectName = "Unknown"

        if ($null -ne $project) {
            if ($project.title) {
                $projectName = [string]$project.title
            }
        }

        return [PSCustomObject]@{
            Found     = $true
            Name      = $projectName
            Slug      = if ($project) { [string]$project.slug } else { "Unknown" }
            Version   = [string]$version.version_number
            ProjectID = [string]$version.project_id
        }
    }
    catch {
        return [PSCustomObject]@{
            Found = $false
        }
    }
}

function Read-JarEntryText {
    param(
        $Entry
    )

    try {
        $stream = $Entry.Open()

        $reader = New-Object System.IO.StreamReader(
            $stream,
            [System.Text.Encoding]::UTF8,
            $true
        )

        $text = $reader.ReadToEnd()

        $reader.Dispose()
        $stream.Dispose()

        return $text
    }
    catch {
        return ""
    }
}

# ============================================================
# CHEAT INDICATORS
# ============================================================

$CheatNames = [ordered]@{

    "Combat automation" = @(
        "AimAssist",
        "AimBot",
        "TriggerBot",
        "AutoClicker",
        "AutoClick",
        "AutoCrystal",
        "AutoHitCrystal",
        "AutoPot",
        "AutoPotRefill",
        "AutoWTap",
        "AutoJumpReset",
        "AutoInventoryTotem",
        "AutoDoubleHand",
        "AutoArmor",
        "ShieldDisabler",
        "ShieldBreaker",
        "TotemOffhand",
        "CrystalOptimizer",
        "AnchorMacro",
        "DoubleAnchor",
        "NoMissDelay",
        "Hitboxes",
        "Velocity"
    )

    "Movement/network manipulation" = @(
        "PingSpoof",
        "FakeLag",
        "PacketSpoof",
        "PackSpoof",
        "PacketFly",
        "Freecam",
        "NoJumpDelay",
        "NoBreakDelay",
        "NoSlow",
        "Step",
        "FastPlace",
        "Sprint"
    )

    "ESP/targeting" = @(
        "PlayerESP",
        "StorageESP",
        "ItemESP",
        "EntityESP",
        "ChestESP",
        "TargetESP",
        "TargetHud",
        "ClickGUI",
        "ClickGui",
        "ESP"
    )

    "Self-destruct/anti-analysis" = @(
        "SelfDestruct",
        "Self-Destruct",
        "EncryptedString",
        "DecryptString",
        "AntiDebug",
        "AntiDump"
    )
}

$SuspiciousFrameworkNames = @(
    "MouseSimulation",
    "MouseSimulator",
    "RotationUtils",
    "RotatorManager",
    "RotationManager",
    "PacketSendListener",
    "PacketReceiveListener",
    "MovementPacketListener",
    "ClientConnectionMixin",
    "KeyboardMixin",
    "MouseMixin",
    "ClientPlayerEntityMixin",
    "AttackListener",
    "TargetManager",
    "ModuleManager",
    "ModuleCategory",
    "Module",
    "KeyBind"
)

$NativeRiskNames = @(
    "VirtualAlloc",
    "VirtualProtect",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "OpenProcess",
    "NtWriteVirtualMemory",
    "JNI_OnLoad"
)

$ShellRiskNames = @(
    "cmd.exe",
    "powershell.exe",
    "powershell ",
    "pwsh",
    "Invoke-Expression",
    "DownloadString",
    "DownloadFile",
    "Runtime.exec",
    "ProcessBuilder.start"
)

# ============================================================
# GET MODS FOLDER
# ============================================================

if ([string]::IsNullOrWhiteSpace($ModsPath)) {

    $defaultPath = Join-Path $env:APPDATA ".minecraft\mods"

    $ModsPath = Read-Host "Mods folder [$defaultPath]"

    if ([string]::IsNullOrWhiteSpace($ModsPath)) {
        $ModsPath = $defaultPath
    }
}

$ModsPath = [Environment]::ExpandEnvironmentVariables($ModsPath)

if (-not (Test-Path -LiteralPath $ModsPath -PathType Container)) {

    Write-Host ""
    Write-Host "[!] Folder does not exist:" -ForegroundColor Red
    Write-Host "    $ModsPath"

    exit 1
}

$jars = @(

    Get-ChildItem `
        -LiteralPath $ModsPath `
        -Filter "*.jar" `
        -File

)

Clear-Host

Show-Section "PROX MOD ANALYZER V5"

Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

if ($jars.Count -eq 0) {

    Write-Host ""
    Write-Host "[!] No JAR files found." -ForegroundColor Yellow

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
# ANALYZE EACH JAR
# ============================================================

foreach ($jar in $jars) {

    try {

        $hashes = Get-FileHashes -Path $jar.FullName
        $modrinth = Get-ModrinthInfo -Sha1 $hashes.SHA1
        $origin = Get-ZoneIdentifier -Path $jar.FullName

        Add-Type -AssemblyName System.IO.Compression.FileSystem

        $zip = [System.IO.Compression.ZipFile]::OpenRead(
            $jar.FullName
        )

        $entries = @($zip.Entries)

        $names = @(
            $entries |
            ForEach-Object {
                [string]$_.FullName
            }
        )

        $classEntries = @(
            $entries |
            Where-Object {
                $_.FullName -match "\.class$"
            }
        )

        $classPaths = @(
            $classEntries |
            ForEach-Object {
                [string]$_.FullName
            }
        )

        $classCount = $classPaths.Count

        $score = 0

        $reasons = New-Object System.Collections.Generic.List[string]
        $evidence = New-Object System.Collections.Generic.List[string]

        # ====================================================
        # METADATA
        # ====================================================

        $metadataEntry = $null

        foreach ($candidate in @(
            "fabric.mod.json",
            "quilt.mod.json"
        )) {

            $candidateEntry = $zip.GetEntry($candidate)

            if ($candidateEntry) {
                $metadataEntry = $candidateEntry
                break
            }
        }

        $declaredId = ""
        $declaredName = ""
        $declaredVersion = ""

        $entrypoints = New-Object System.Collections.Generic.List[string]
        $mixins = New-Object System.Collections.Generic.List[string]

        if ($metadataEntry) {

            try {

                $metadataText = Read-JarEntryText $metadataEntry

                $metadata = $metadataText | ConvertFrom-Json

                if ($metadata.id) {
                    $declaredId = [string]$metadata.id
                }

                if ($metadata.name) {
                    $declaredName = [string]$metadata.name
                }

                if ($metadata.version) {
                    $declaredVersion = [string]$metadata.version
                }

                if ($metadata.entrypoints) {

                    foreach (
                        $property in
                        $metadata.entrypoints.PSObject.Properties
                    ) {

                        $value = $property.Value

                        foreach ($entrypoint in @($value)) {

                            if ($entrypoint -is [string]) {

                                $entrypoints.Add(
                                    [string]$entrypoint
                                )
                            }
                            elseif ($entrypoint.value) {

                                $entrypoints.Add(
                                    [string]$entrypoint.value
                                )
                            }
                        }
                    }
                }

                if ($metadata.mixins) {

                    foreach ($mixin in @($metadata.mixins)) {

                        if ($mixin) {
                            $mixins.Add([string]$mixin)
                        }
                    }
                }
            }
            catch {
            }
        }

        # ====================================================
        # SHORT CLASS NAME / OBFUSCATION SIGNAL
        # ====================================================

        $shortClassCount = 0

        foreach ($classPath in $classPaths) {

            $simpleName =
                ($classPath -replace "\.class$", "") -split "/"

            $simpleName = $simpleName[-1]

            if ($simpleName.Length -le 2) {
                $shortClassCount++
            }
        }

        $shortRatio = 0

        if ($classCount -gt 0) {
            $shortRatio = $shortClassCount / $classCount
        }

        if ($shortRatio -ge 0.20) {

            $score += 7

            $reasons.Add(
                "High proportion of short class names"
            )
        }

        # ====================================================
        # INDICATOR STORAGE
        # ====================================================

        $cheatHits = @{}
        $frameworkHits = New-Object System.Collections.Generic.List[string]
        $riskHits = @{}

        foreach ($category in $CheatNames.Keys) {

            $cheatHits[$category] =
                New-Object System.Collections.Generic.List[string]
        }

        # ====================================================
        # CONTENT SCAN
        # ====================================================

        foreach ($entry in $entries) {

            if ($entry.FullName.EndsWith("/")) {
                continue
            }

            if ($entry.Length -gt 20MB) {
                continue
            }

            $text = Read-JarEntryText $entry

            if ([string]::IsNullOrEmpty($text)) {
                continue
            }

            # -----------------------------------------------
            # Cheat indicators
            # -----------------------------------------------

            foreach ($category in $CheatNames.Keys) {

                foreach ($term in $CheatNames[$category]) {

                    if (
                        $text.IndexOf(
                            $term,
                            [System.StringComparison]::OrdinalIgnoreCase
                        ) -ge 0
                    ) {

                        if (
                            $cheatHits[$category].Count -lt 15
                        ) {

                            $cheatHits[$category].Add(
                                "$term -> $($entry.FullName)"
                            )
                        }
                    }
                }
            }

            # -----------------------------------------------
            # Framework indicators
            # -----------------------------------------------

            foreach ($term in $SuspiciousFrameworkNames) {

                if (
                    $text.IndexOf(
                        $term,
                        [System.StringComparison]::OrdinalIgnoreCase
                    ) -ge 0
                ) {

                    if ($frameworkHits.Count -lt 20) {

                        $frameworkHits.Add(
                            "$term -> $($entry.FullName)"
                        )
                    }
                }
            }

            # -----------------------------------------------
            # Native indicators
            # -----------------------------------------------

            foreach ($term in $NativeRiskNames) {

                if (
                    $text.IndexOf(
                        $term,
                        [System.StringComparison]::OrdinalIgnoreCase
                    ) -ge 0
                ) {

                    $riskHits[
                        "$term -> $($entry.FullName)"
                    ] = $true
                }
            }

            # -----------------------------------------------
            # Shell indicators
            # -----------------------------------------------

            foreach ($term in $ShellRiskNames) {

                if (
                    $text.IndexOf(
                        $term,
                        [System.StringComparison]::OrdinalIgnoreCase
                    ) -ge 0
                ) {

                    $riskHits[
                        "$term -> $($entry.FullName)"
                    ] = $true
                }
            }
        }

        # ====================================================
        # CLASS NAME SCAN
        # ====================================================

        foreach ($classPath in $classPaths) {

            $className =
                [System.IO.Path]::GetFileNameWithoutExtension(
                    $classPath
                )

            foreach ($category in $CheatNames.Keys) {

                foreach ($term in $CheatNames[$category]) {

                    if (
                        $className.IndexOf(
                            $term,
                            [System.StringComparison]::OrdinalIgnoreCase
                        ) -ge 0
                    ) {

                        if (
                            $cheatHits[$category].Count -lt 15
                        ) {

                            $cheatHits[$category].Add(
                                "CLASS NAME: $classPath"
                            )
                        }
                    }
                }
            }
        }

        # ====================================================
        # COUNT CHEAT CATEGORIES
        # ====================================================

        $cheatCategoryCount = 0

        foreach ($category in $cheatHits.Keys) {

            if ($cheatHits[$category].Count -gt 0) {

                $cheatCategoryCount++

                $evidence.Add(
                    "${category}: $($cheatHits[$category].Count) indicator(s)"
                )
            }
        }

        if ($cheatCategoryCount -eq 1) {

            $score += 20

            $reasons.Add(
                "Cheat-client feature indicators"
            )
        }
        elseif ($cheatCategoryCount -eq 2) {

            $score += 40

            $reasons.Add(
                "Multiple cheat-client feature categories"
            )
        }
        elseif ($cheatCategoryCount -ge 3) {

            $score += 65

            $reasons.Add(
                "Strong multi-category cheat-client fingerprint"
            )
        }

        # ====================================================
        # FRAMEWORK CORRELATION
        # ====================================================

        if ($frameworkHits.Count -ge 2) {

            $score += 10

            $reasons.Add(
                "Client automation/packet framework indicators"
            )

            foreach (
                $item in
                $frameworkHits |
                Select-Object -First 8
            ) {

                $evidence.Add($item)
            }
        }

        # ====================================================
        # NATIVE / SHELL RISK
        # ====================================================

        if ($riskHits.Count -gt 0) {

            $score += 25

            $reasons.Add(
                "High-risk execution indicator(s)"
            )

            foreach (
                $item in
                $riskHits.Keys |
                Select-Object -First 10
            ) {

                $evidence.Add($item)
            }
        }

        # ====================================================
        # PACKAGE ANALYSIS
        # ====================================================

        $packageHints = New-Object System.Collections.Generic.List[string]

        foreach ($classPath in $classPaths) {

            if ($classPath -match "^([^/]+/[^/]+)/") {

                if ($Matches[1]) {
                    $packageHints.Add(
                        [string]$Matches[1]
                    )
                }
            }
        }

        $distinctPackages = @(
            $packageHints |
            Select-Object -Unique
        )

        $namespaceMismatch = 0

        if (-not [string]::IsNullOrWhiteSpace($declaredId)) {

            foreach ($package in $distinctPackages) {

                $normalizedPackage =
                    $package.Replace("/", "").
                    Replace("_", "").
                    Replace("-", "").
                    ToLower()

                $normalizedId =
                    $declaredId.Replace("_", "").
                    Replace("-", "").
                    ToLower()

                if (
                    $normalizedPackage.Length -gt 5 -and
                    $normalizedPackage -notmatch
                    [regex]::Escape($normalizedId)
                ) {

                    $namespaceMismatch++
                }
            }
        }

        if ($namespaceMismatch -ge 2) {

            $score += 20

            $reasons.Add(
                "Declared mod identity does not match code namespace"
            )

            $packageExample = "unknown"

            if ($distinctPackages.Count -gt 0) {
                $packageExample = $distinctPackages[0]
            }

            $evidence.Add(
                "Namespace mismatch: declared '$declaredId' vs code package '$packageExample'"
            )
        }

        # ====================================================
        # ENTRYPOINT ANALYSIS
        # ====================================================

        foreach ($entrypoint in $entrypoints) {

            $entrypointLower = $entrypoint.ToLower()

            if (
                $entrypointLower -match
                "argon|cheat|hack|clickgui|module"
            ) {

                $score += 25

                $reasons.Add(
                    "Suspicious entrypoint identity"
                )

                $evidence.Add(
                    "Entrypoint: $entrypoint"
                )
            }
        }

        # ====================================================
        # MIXIN SURFACE
        # ====================================================

        $interestingMixins = @(
            $mixins |
            Where-Object {
                $_ -match
                "(?i)mouse|keyboard|connection|player|camera|interaction|inventory|packet"
            }
        )

        if (
            $interestingMixins.Count -ge 3 -and
            $cheatCategoryCount -ge 1
        ) {

            $score += 15

            $reasons.Add(
                "Cheat-related client mixin surface"
            )

            foreach (
                $mixin in
                $interestingMixins |
                Select-Object -First 8
            ) {

                $evidence.Add(
                    "Mixin: $mixin"
                )
            }
        }

        # ====================================================
        # ARGON-SPECIFIC NAMESPACE FINGERPRINT
        # ====================================================

        $argonClasses = @(
            $classPaths |
            Where-Object {
                $_ -match "(?i)lvstrng/argon|argon/"
            }
        )

        $argonFiles = @(
            $names |
            Where-Object {
                $_ -match "(?i)argon"
            }
        )

        if ($argonClasses.Count -ge 2) {

            $score += 60

            $reasons.Add(
                "Argon-family code namespace detected"
            )

            $evidence.Add(
                "Argon namespace classes: $($argonClasses.Count)"
            )
        }

        if ($argonFiles.Count -ge 2) {

            $score += 10

            $reasons.Add(
                "Argon-related archive artifacts detected"
            )
        }

        # ====================================================
        # EMBEDDED JARS
        # ====================================================

        $embeddedJars = @(
            $entries |
            Where-Object {
                $_.FullName -match "\.jar$"
            }
        )

        if ($embeddedJars.Count -gt 0) {

            $evidence.Add(
                "Embedded JARs: $($embeddedJars.Count)"
            )
        }

        # ====================================================
        # FINAL SCORE
        # ====================================================

        $score = [Math]::Min(
            100,
            $score
        )

        if ($score -ge 75) {

            $verdict = "HIGH RISK"
        }
        elseif ($score -ge 45) {

            $verdict = "SUSPICIOUS"
        }
        elseif ($score -ge 20) {

            $verdict = "REVIEW"
        }
        else {

            $verdict = "LOW RISK"
        }

        # ====================================================
        # DISPLAY NAME
        # ====================================================

        if ($modrinth.Found) {

            $displayName = $modrinth.Name
        }
        elseif (-not [string]::IsNullOrWhiteSpace($declaredName)) {

            $displayName = $declaredName
        }
        else {

            $displayName = $jar.BaseName
        }

        # ====================================================
        # RESULT OBJECT
        # ====================================================

        $result = [PSCustomObject]@{
            Name       = $displayName
            File       = $jar.Name
            SHA256     = $hashes.SHA256
            SHA1       = $hashes.SHA1
            Score      = $score
            Verdict    = $verdict
            Reasons    = $reasons
            Evidence   = $evidence
            Modrinth   = $modrinth
            Origin     = $origin
            ClassCount = $classCount
        }

        # ====================================================
        # CLASSIFICATION
        # ====================================================

        if (
            $modrinth.Found -and
            $score -lt 20
        ) {

            $verified.Add($result)

        }
        elseif ($score -lt 10) {

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

        $zip.Dispose()

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
}

# ============================================================
# OUTPUT
# ============================================================

Clear-Host

Show-Section "PROX MOD ANALYZER V5"

Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

function Print-Group {
    param(
        [string]$Title,
        $Items,
        [ConsoleColor]$Color,
        [bool]$ShowScore
    )

    Write-Host ""
    Write-Host "{ $Title }" -ForegroundColor $Color

    if ($Items.Count -eq 0) {

        Write-Host "> None"

    }
    else {

        foreach ($item in $Items) {

            if ($ShowScore) {

                $suffix =
                    "  [$($item.Score)/100]"

            }
            else {

                $suffix = ""
            }

            $display =
                "> " +
                $item.Name.PadRight(30) +
                $item.File +
                $suffix

            Write-Host $display
        }
    }
}

Print-Group "Verified Mods" $verified Green $true
Print-Group "Low Risk" $low Gray $true
Print-Group "Review" $review Yellow $true
Print-Group "Suspicious" $susp DarkYellow $true
Print-Group "High Risk" $high Red $true
Print-Group "Unknown" $unknown Magenta $false

# ============================================================
# FLAGGED DETAILS
# ============================================================

$flagged = @()

foreach ($item in $review) {
    $flagged += $item
}

foreach ($item in $susp) {
    $flagged += $item
}

foreach ($item in $high) {
    $flagged += $item
}

if ($flagged.Count -gt 0) {

    Show-Section "FLAGGED DETAILS"

    foreach ($item in $flagged) {

        Write-Host ""
        Write-Host $item.File -ForegroundColor Yellow

        Write-Host "    Score:   $($item.Score)/100"
        Write-Host "    Verdict: $($item.Verdict)"

        if ($item.Reasons.Count -gt 0) {

            Write-Host "    Reasons:"

            foreach (
                $reason in
                ($item.Reasons | Select-Object -Unique)
            ) {

                Write-Host "        - $reason"
            }
        }

        if ($item.Evidence.Count -gt 0) {

            Write-Host "    Evidence:"

            foreach (
                $evidenceItem in
                ($item.Evidence | Select-Object -First 15)
            ) {

                Write-Host "        $evidenceItem"
            }
        }

        Write-Host "    SHA-256: $($item.SHA256)"
        Write-Host "    SHA-1:   $($item.SHA1)"

        if ($item.Modrinth.Found) {

            Write-Host (
                "    Modrinth: " +
                $item.Modrinth.Name +
                " " +
                $item.Modrinth.Version
            )
        }
        else {

            Write-Host "    Modrinth: No exact SHA-1 match"
        }

        if ($item.Origin) {

            Write-Host "    Origin:   $($item.Origin)"
        }
    }
}

# ============================================================
# SUMMARY
# ============================================================

Show-Section "SUMMARY"

Write-Host "Total:       $($jars.Count)"
Write-Host "Verified:    $($verified.Count)" -ForegroundColor Green
Write-Host "Low Risk:    $($low.Count)"
Write-Host "Review:      $($review.Count)" -ForegroundColor Yellow
Write-Host "Suspicious:  $($susp.Count)" -ForegroundColor DarkYellow
Write-Host "High Risk:   $($high.Count)" -ForegroundColor Red
Write-Host "Unknown:     $($unknown.Count)" -ForegroundColor Magenta

Write-Host ""
Write-Host "IMPORTANT:"
Write-Host "    This is static analysis and reputation checking."
Write-Host "    A detection is evidence, not absolute proof."
Write-Host "    A clean result is not proof that a mod is safe."

Show-Section "Analysis complete."
