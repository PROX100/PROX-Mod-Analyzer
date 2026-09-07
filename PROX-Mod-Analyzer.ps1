param(
    [string]$ModsPath = ""
)

$ErrorActionPreference = "Stop"

function Show-Section {
    param([string]$Text)

    Write-Host ""
    Write-Host ("=" * 58)
    Write-Host $Text
    Write-Host ("=" * 58)
}

function Get-Hashes {
    param([string]$Path)

    $sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
    $sha1   = (Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToLower()

    return [PSCustomObject]@{
        SHA256 = $sha256
        SHA1   = $sha1
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

if (-not $ModsPath) {
    $defaultModsPath = Join-Path $env:APPDATA ".minecraft\mods"

    $ModsPath = Read-Host "Mods folder [$defaultModsPath]"

    if ([string]::IsNullOrWhiteSpace($ModsPath)) {
        $ModsPath = $defaultModsPath
    }
}

$ModsPath = [Environment]::ExpandEnvironmentVariables($ModsPath)

if (-not (Test-Path -LiteralPath $ModsPath -PathType Container)) {
    Write-Host "[!] Folder does not exist: $ModsPath" -ForegroundColor Red
    exit 1
}

$jars = @(Get-ChildItem -LiteralPath $ModsPath -Filter "*.jar" -File)

Clear-Host

Show-Section "PROX MOD ANALYZER"

Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

if ($jars.Count -eq 0) {
    Write-Host "[!] No JAR files found." -ForegroundColor Yellow
    exit 0
}

foreach ($jar in $jars) {

    Show-Section "Analyzing: $($jar.Name)"

    Write-Host "File size: $([math]::Round($jar.Length / 1MB, 2)) MB"

    $hashes = Get-Hashes $jar.FullName

    Write-Host ""
    Write-Host "SHA-256: $($hashes.SHA256)"
    Write-Host "SHA-1:   $($hashes.SHA1)"

    $origin = Get-ZoneIdentifier $jar.FullName

    if ($origin) {
        Write-Host ""
        Write-Host "[ORIGIN]"
        Write-Host "    Host URL: $origin"
    }

    $score = 0

    $reasons = New-Object System.Collections.Generic.List[string]
    $found = @{}
    $highHits = @{}

    try {

        Add-Type -AssemblyName System.IO.Compression.FileSystem

        $zip = [IO.Compression.ZipFile]::OpenRead($jar.FullName)

        Write-Host "[+] JAR structure: Valid"
        Write-Host "[+] Files inside JAR: $($zip.Entries.Count)"

        Show-Section "[MOD METADATA]"

        $metadataFiles = @(
            "fabric.mod.json",
            "quilt.mod.json",
            "META-INF/mods.toml",
            "mcmod.info"
        )

        $metadata = @(
            $zip.Entries |
            Where-Object {
                $_.FullName -in $metadataFiles
            }
        )

        if ($metadata.Count -gt 0) {

            foreach ($entry in $metadata) {

                Write-Host "    [+] Found: $($entry.FullName)"

                if ($entry.FullName -match "fabric|quilt") {

                    try {

                        $reader = New-Object IO.StreamReader($entry.Open())

                        $text = $reader.ReadToEnd()

                        $reader.Dispose()

                        $json = $text | ConvertFrom-Json

                        Write-Host "        Name:    $($json.name)"
                        Write-Host "        Mod ID:  $($json.id)"
                        Write-Host "        Version: $($json.version)"
                    }
                    catch {
                    }
                }
            }

        }
        else {
            Write-Host "    [i] No common mod metadata file found."
        }

        Show-Section "[MANIFEST]"

        $manifest = $zip.GetEntry("META-INF/MANIFEST.MF")

        if ($manifest) {

            $reader = New-Object IO.StreamReader($manifest.Open())

            $manifestText = $reader.ReadToEnd()

            $reader.Dispose()

            $entries = $manifestText -split "`r?`n" |
                Where-Object {
                    $_ -match "^(Main-Class|Premain-Class|Agent-Class):"
                }

            if ($entries) {

                foreach ($line in $entries) {
                    Write-Host "    [i] $line"
                }

            }
            else {
                Write-Host "    [+] No executable manifest entry."
            }

        }
        else {
            Write-Host "    [+] No manifest."
        }

        Show-Section "[EMBEDDED JARS]"

        $embedded = @(
            $zip.Entries |
            Where-Object {
                $_.FullName -match "\.jar$"
            }
        )

        if ($embedded.Count -eq 0) {
            Write-Host "    None found."
        }
        else {

            foreach ($entry in $embedded) {
                Write-Host "    $($entry.FullName)"
            }
        }

        Show-Section "[STATIC INDICATORS]"

        $classes = @(
            $zip.Entries |
            Where-Object {
                $_.FullName -match "\.class$"
            }
        )

        Write-Host "    Java classes: $($classes.Count)"

        $shortCount = @(
            $classes |
            ForEach-Object {
                $name = $_.FullName -replace "\.class$", ""
                ($name -split "/")[-1]
            } |
            Where-Object {
                $_.Length -le 2
            }
        ).Count

        $ratio = if ($classes.Count -gt 0) {
            $shortCount / $classes.Count
        }
        else {
            0
        }

        if ($ratio -ge 0.20) {

            Write-Host (
                "    [!] High proportion of very short class names: " +
                "$shortCount/$($classes.Count) " +
                "($([math]::Round($ratio * 100, 1))%)"
            ) -ForegroundColor Yellow

            $score += 7
            $reasons.Add("High proportion of short class names")

        }
        else {
            Write-Host "    [+] Class names look relatively normal."
        }

        foreach ($entry in $zip.Entries) {

            if (
                $entry.FullName.EndsWith("/") -or
                $entry.Length -gt 10MB
            ) {
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
            }
        }

        foreach ($category in $Rules.Keys) {

            if ($found.ContainsKey($category)) {

                Write-Host "    [!] $category" -ForegroundColor Yellow

                foreach ($hit in $found[$category]) {
                    Write-Host "        $hit"
                }

            }
            else {
                Write-Host "    [+] $category`: Not detected"
            }
        }

        Show-Section "[HIGH-RISK INDICATORS]"

        if ($highHits.Count -eq 0) {

            Write-Host "    None found."

        }
        else {

            foreach ($hit in $highHits.Keys) {

                Write-Host "    [!!!] $hit" -ForegroundColor Red

                $score += 15
            }

            $reasons.Add("High-risk execution indicator(s)")
        }

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
            $reasons.Add("PowerShell/web execution indicator")
        }

        if ($found.ContainsKey("File-system access")) {
            $score += 3
            $reasons.Add("File-system API usage")
        }

        if ($found.ContainsKey("Reflection")) {
            $score += 2
            $reasons.Add("Reflection API usage")
        }

        $score = [Math]::Min(100, $score)

        Show-Section "[HASH REPUTATION (MODRINTH)]"

        $modrinth = Get-ModrinthInfo $hashes.SHA1

        if ($modrinth.Found) {

            Write-Host "    [+] Exact SHA-1 match found on Modrinth." -ForegroundColor Green
            Write-Host "        Project: $($modrinth.Name)"
            Write-Host "        Mod ID:  $($modrinth.Slug)"
            Write-Host "        Version: $($modrinth.Version)"
            Write-Host "        Project ID: $($modrinth.ProjectID)"

        }
        else {

            Write-Host "    [!] SHA-1 not found on Modrinth." -ForegroundColor Yellow
            Write-Host "        This does NOT mean the mod is malicious."
        }

        Show-Section "RISK ASSESSMENT"

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

        Write-Host "Score:   $score/100"
        Write-Host "Verdict: $verdict"

        Write-Host ""
        Write-Host "Reasons:"

        if ($reasons.Count -gt 0) {

            $reasons |
                Select-Object -Unique |
                ForEach-Object {
                    Write-Host "    - $_"
                }

        }
        else {
            Write-Host "    - No basic static indicators detected"
        }

        Write-Host ""
        Write-Host "IMPORTANT:"
        Write-Host "    This is static analysis only."
        Write-Host "    A capability is not proof of malware."
        Write-Host "    A clean result is not proof that a mod is safe."

        $zip.Dispose()

    }
    catch {

        Write-Host "[!] Could not analyze archive: $($_.Exception.Message)" `
            -ForegroundColor Red
    }
}

Show-Section "Analysis complete."
