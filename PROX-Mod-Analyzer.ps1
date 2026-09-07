param(
    [string]$ModsPath = ""
)

$ErrorActionPreference = "Stop"

# ============================================================
# PROX MOD ANALYZER
# ============================================================

function Show-Section {
    param([string]$Text)

    Write-Host ""
    Write-Host ("=" * 58)
    Write-Host $Text
    Write-Host ("=" * 58)
}

function Get-Hashes {
    param([string]$Path)

    return [PSCustomObject]@{
        SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
        SHA1   = (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToLower()
    }
}

function Get-ModrinthInfo {
    param([string]$Sha1)

    try {
        $headers = @{
            "User-Agent" = "PROX-Mod-Analyzer/1.0"
        }

        $version = Invoke-RestMethod `
            -Uri "https://api.modrinth.com/v2/version_file/$Sha1" `
            -Headers $headers `
            -TimeoutSec 8

        if (-not $version) {
            return [PSCustomObject]@{ Found = $false }
        }

        $project = $null

        if ($version.project_id) {
            $project = Invoke-RestMethod `
                -Uri "https://api.modrinth.com/v2/project/$($version.project_id)" `
                -Headers $headers `
                -TimeoutSec 8
        }

        return [PSCustomObject]@{
            Found     = $true
            Name      = if ($project) { $project.title } else { "Unknown" }
            Slug      = if ($project) { $project.slug } else { "Unknown" }
            Version   = $version.version_number
            ProjectID = $version.project_id
        }
    }
    catch {
        return [PSCustomObject]@{
            Found = $false
        }
    }
}

function Get-ZoneIdentifier {
    param([string]$Path)

    try {
        $lines = Get-Content `
            -LiteralPath $Path `
            -Stream Zone.Identifier `
            -ErrorAction Stop

        $hostLine = $lines |
            Where-Object { $_ -like "HostUrl=*" } |
            Select-Object -First 1

        if ($hostLine) {
            return $hostLine.Substring(8)
        }
    }
    catch {
    }

    return $null
}

# These are indicators only.
# Their presence does NOT prove malware.
$Rules = [ordered]@{

    "Process execution" = @(
        "java/lang/ProcessBuilder",
        "Runtime.exec",
        "ProcessBuilder.start"
    )

    "Network communication" = @(
        "java/net/Socket",
        "java/net/ServerSocket",
        "java/net/HttpURLConnection",
        "java/net/URLConnection",
        "java/net/http/HttpClient",
        "java/net/URL",
        "okhttp",
        "socket"
    )

    "Command shell" = @(
        "cmd.exe",
        "/bin/sh",
        "/bin/bash",
        "powershell.exe",
        "pwsh"
    )

    "PowerShell / web execution" = @(
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "DownloadString",
        "DownloadFile",
        "powershell -enc",
        "powershell -encodedcommand",
        "Invoke-Expression"
    )

    "File-system access" = @(
        "java/io/File",
        "java/nio/file",
        "FileOutputStream",
        "FileInputStream"
    )

    "Reflection" = @(
        "java/lang/reflect",
        "Class.forName",
        "getDeclaredMethod",
        "getDeclaredField",
        "setAccessible"
    )
}

$HighRisk = @(
    "VirtualAlloc",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "OpenProcess",
    "NtWriteVirtualMemory",
    "powershell -enc",
    "powershell -encodedcommand",
    "Invoke-Expression"
)

# ============================================================
# FIND MODS FOLDER
# ============================================================

if (-not $ModsPath) {

    $defaultModsPath = Join-Path $env:APPDATA ".minecraft\mods"

    $ModsPath = Read-Host "Mods folder [$defaultModsPath]"

    if ([string]::IsNullOrWhiteSpace($ModsPath)) {
        $ModsPath = $defaultModsPath
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

Show-Section "PROX MOD ANALYZER"

Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

if ($jars.Count -eq 0) {

    Write-Host ""
    Write-Host "[!] No JAR files found." -ForegroundColor Yellow

    exit 0
}

# ============================================================
# RESULT STORAGE
# ============================================================

$verifiedMods = New-Object System.Collections.Generic.List[object]
$reviewMods = New-Object System.Collections.Generic.List[object]
$suspiciousMods = New-Object System.Collections.Generic.List[object]
$highRiskMods = New-Object System.Collections.Generic.List[object]
$unknownMods = New-Object System.Collections.Generic.List[object]

# ============================================================
# ANALYZE EACH MOD
# ============================================================

foreach ($jar in $jars) {

    try {

        $hashes = Get-Hashes $jar.FullName

        $modrinth = Get-ModrinthInfo $hashes.SHA1

        $score = 0

        $reasons = New-Object System.Collections.Generic.List[string]

        $found = @{}

        $highHits = @{}

        $classCount = 0
        $shortClassCount = 0

        # --------------------------------------------------------
        # OPEN JAR
        # --------------------------------------------------------

        Add-Type -AssemblyName System.IO.Compression.FileSystem

        $zip = [IO.Compression.ZipFile]::OpenRead($jar.FullName)

        # --------------------------------------------------------
        # COUNT CLASSES
        # --------------------------------------------------------

        $classes = @(
            $zip.Entries |
            Where-Object {
                $_.FullName -match "\.class$"
            }
        )

        $classCount = $classes.Count

        if ($classCount -gt 0) {

            foreach ($class in $classes) {

                $className = $class.FullName -replace "\.class$", ""

                $simpleName = ($className -split "/")[-1]

                if ($simpleName.Length -le 2) {
                    $shortClassCount++
                }
            }

            $ratio = $shortClassCount / $classCount

            if ($ratio -ge 0.20) {

                $score += 7

                $reasons.Add(
                    "High proportion of short class names"
                )
            }
        }

        # --------------------------------------------------------
        # SCAN FILE CONTENT
        # --------------------------------------------------------

        foreach ($entry in $zip.Entries) {

            if ($entry.FullName.EndsWith("/")) {
                continue
            }

            # Skip huge files.
            if ($entry.Length -gt 10MB) {
                continue
            }

            try {

                $reader = New-Object IO.StreamReader(
                    $entry.Open(),
                    [Text.Encoding]::UTF8,
                    $true
                )

                $text = $reader.ReadToEnd()

                $reader.Dispose()

                # --------------------------------------------
                # NORMAL INDICATORS
                # --------------------------------------------

                foreach ($category in $Rules.Keys) {

                    foreach ($indicator in $Rules[$category]) {

                        if (
                            $text.IndexOf(
                                $indicator,
                                [StringComparison]::OrdinalIgnoreCase
                            ) -ge 0
                        ) {

                            if (-not $found.ContainsKey($category)) {
                                $found[$category] = @()
                            }

                            if ($found[$category].Count -lt 8) {

                                $found[$category] +=
                                    "$indicator -> $($entry.FullName)"
                            }
                        }
                    }
                }

                # --------------------------------------------
                # HIGH-RISK INDICATORS
                # --------------------------------------------

                foreach ($indicator in $HighRisk) {

                    if (
                        $text.IndexOf(
                            $indicator,
                            [StringComparison]::OrdinalIgnoreCase
                        ) -ge 0
                    ) {

                        $highHits[
                            "$indicator -> $($entry.FullName)"
                        ] = 1
                    }
                }

            }
            catch {
                # Ignore unreadable entries.
            }
        }

        $zip.Dispose()

        # ========================================================
        # SCORE
        # ========================================================

        if ($found.ContainsKey("Process execution")) {

            $score += 10
            $reasons.Add("Process execution capability")
        }

        if ($found.ContainsKey("Network communication")) {

            $score += 5
            $reasons.Add("Network communication capability")
        }

        if ($found.ContainsKey("Command shell")) {

            $score += 15
            $reasons.Add("Command shell capability")
        }

        if ($found.ContainsKey("PowerShell / web execution")) {

            $score += 20
            $reasons.Add(
                "PowerShell/web execution indicator"
            )
        }

        if ($found.ContainsKey("File-system access")) {

            $score += 3
            $reasons.Add("File-system API usage")
        }

        if ($found.ContainsKey("Reflection")) {

            $score += 2
            $reasons.Add("Reflection API usage")
        }

        if ($highHits.Count -gt 0) {

            foreach ($hit in $highHits.Keys) {
                $score += 15
            }

            $reasons.Add(
                "High-risk execution indicator(s)"
            )
        }

        $score = [Math]::Min(100, $score)

        # ========================================================
        # VERDICT
        # ========================================================

        if ($score -le 10) {
            $verdict = "LOW RISK"
        }
        elseif ($score -le 25) {
            $verdict = "REVIEW"
        }
        elseif ($score -le 45) {
            $verdict = "SUSPICIOUS"
        }
        else {
            $verdict = "HIGH RISK"
        }

        # ========================================================
        # CLASSIFY MOD
        # ========================================================

        $modName = $jar.BaseName

        if ($modrinth.Found) {
            $modName = $modrinth.Name
        }

        $result = [PSCustomObject]@{
            Name     = $modName
            File     = $jar.Name
            SHA256   = $hashes.SHA256
            SHA1     = $hashes.SHA1
            Score    = $score
            Verdict  = $verdict
            Reasons  = $reasons
            HighHits = $highHits.Keys
            Modrinth = $modrinth
            Origin   = Get-ZoneIdentifier $jar.FullName
        }

        # Exact Modrinth hash match is considered verified
        # only when no suspicious static indicators were found.
        if (
            $modrinth.Found -and
            $score -le 10
        ) {

            $verifiedMods.Add($result)
        }
        elseif ($score -le 25) {

            $reviewMods.Add($result)
        }
        elseif ($score -le 45) {

            $suspiciousMods.Add($result)
        }
        else {

            $highRiskMods.Add($result)
        }

    }
    catch {

        $unknownMods.Add(
            [PSCustomObject]@{
                Name = $jar.BaseName
                File = $jar.Name
                Error = $_.Exception.Message
            }
        )
    }
}

# ============================================================
# COMPACT RESULTS
# ============================================================

Clear-Host

Show-Section "PROX MOD ANALYZER"

Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

# ============================================================
# VERIFIED
# ============================================================

Write-Host ""
Write-Host "{ Verified Mods }" -ForegroundColor Green

if ($verifiedMods.Count -eq 0) {

    Write-Host "> None"
}
else {

    foreach ($mod in $verifiedMods) {

        Write-Host (
            "> " +
            $mod.Name.PadRight(30) +
            $mod.File
        )
    }
}

# ============================================================
# REVIEW
# ============================================================

Write-Host ""
Write-Host "{ Review }" -ForegroundColor Yellow

if ($reviewMods.Count -eq 0) {

    Write-Host "> None"
}
else {

    foreach ($mod in $reviewMods) {

        Write-Host (
            "> " +
            $mod.Name.PadRight(30) +
            "$($mod.File)  [$($mod.Score)/100]"
        )
    }
}

# ============================================================
# SUSPICIOUS
# ============================================================

Write-Host ""
Write-Host "{ Suspicious }" -ForegroundColor DarkYellow

if ($suspiciousMods.Count -eq 0) {

    Write-Host "> None"
}
else {

    foreach ($mod in $suspiciousMods) {

        Write-Host (
            "> " +
            $mod.Name.PadRight(30) +
            "$($mod.File)  [$($mod.Score)/100]"
        )
    }
}

# ============================================================
# HIGH RISK
# ============================================================

Write-Host ""
Write-Host "{ High Risk }" -ForegroundColor Red

if ($highRiskMods.Count -eq 0) {

    Write-Host "> None"
}
else {

    foreach ($mod in $highRiskMods) {

        Write-Host (
            "> " +
            $mod.Name.PadRight(30) +
            "$($mod.File)  [$($mod.Score)/100]"
        )
    }
}

# ============================================================
# UNKNOWN
# ============================================================

Write-Host ""
Write-Host "{ Unknown }" -ForegroundColor Magenta

if ($unknownMods.Count -eq 0) {

    Write-Host "> None"
}
else {

    foreach ($mod in $unknownMods) {

        Write-Host (
            "> " +
            $mod.Name.PadRight(30) +
            $mod.File
        )
    }
}

# ============================================================
# DETAILS FOR NON-VERIFIED MODS
# ============================================================

$needsDetails = @(
    $reviewMods
    $suspiciousMods
    $highRiskMods
    $unknownMods
)

if ($needsDetails.Count -gt 0) {

    Show-Section "DETAILS"

    foreach ($mod in $needsDetails) {

        if (-not $mod.Score -and $unknownMods -contains $mod) {

            Write-Host ""
            Write-Host $mod.File -ForegroundColor Magenta
            Write-Host "    [!] Analysis failed"
            Write-Host "        $($mod.Error)"

            continue
        }

        Write-Host ""
        Write-Host $mod.File -ForegroundColor Yellow

        Write-Host "    Score:   $($mod.Score)/100"
        Write-Host "    Verdict: $($mod.Verdict)"

        if ($mod.Reasons.Count -gt 0) {

            Write-Host "    Reasons:"

            $mod.Reasons |
                Select-Object -Unique |
                ForEach-Object {
                    Write-Host "        - $_"
                }
        }

        if ($mod.HighHits.Count -gt 0) {

            Write-Host "    High-risk indicators:"

            foreach ($hit in $mod.HighHits) {

                Write-Host "        [!!!] $hit" `
                    -ForegroundColor Red
            }
        }

        Write-Host "    SHA-256: $($mod.SHA256)"
        Write-Host "    SHA-1:   $($mod.SHA1)"

        if ($mod.Modrinth.Found) {

            Write-Host ""
            Write-Host "    Modrinth:"
            Write-Host "        Project: $($mod.Modrinth.Name)"
            Write-Host "        Version: $($mod.Modrinth.Version)"
        }
        else {

            Write-Host ""
            Write-Host "    Modrinth:"
            Write-Host "        No exact SHA-1 match found."
        }

        if ($mod.Origin) {

            Write-Host ""
            Write-Host "    Origin:"
            Write-Host "        $($mod.Origin)"
        }
    }
}

# ============================================================
# FINAL SUMMARY
# ============================================================

Show-Section "SUMMARY"

Write-Host "Total:       $($jars.Count)"
Write-Host "Verified:    $($verifiedMods.Count)" -ForegroundColor Green
Write-Host "Review:      $($reviewMods.Count)" -ForegroundColor Yellow
Write-Host "Suspicious:  $($suspiciousMods.Count)" -ForegroundColor DarkYellow
Write-Host "High Risk:   $($highRiskMods.Count)" -ForegroundColor Red
Write-Host "Unknown:     $($unknownMods.Count)" -ForegroundColor Magenta

Write-Host ""
Write-Host "IMPORTANT:"
Write-Host "    This is static analysis only."
Write-Host "    A detection is not proof of malware."
Write-Host "    A clean result is not proof that a mod is safe."

Show-Section "Analysis complete."
