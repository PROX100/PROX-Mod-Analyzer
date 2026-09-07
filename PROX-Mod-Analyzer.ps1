param([string]$ModsPath="")
$ErrorActionPreference='SilentlyContinue'
function H($s){Write-Host "`n==========================================================`n$s`n=========================================================="}
function Hashes($p){[pscustomobject]@{SHA256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower();SHA1=(Get-FileHash -LiteralPath $p -Algorithm SHA1).Hash.ToLower()}}
function MR($sha1){try{$h=@{'User-Agent'='PROX-Mod-Analyzer/1.0'};$v=Invoke-RestMethod "https://api.modrinth.com/v2/version_file/$sha1" -Headers $h -TimeoutSec 8;if($v){$p=if($v.project_id){Invoke-RestMethod "https://api.modrinth.com/v2/project/$($v.project_id)" -Headers $h -TimeoutSec 8};return [pscustomobject]@{Found=$true;Name=if($p){$p.title}else{'Unknown'};Slug=if($p){$p.slug}else{'Unknown'};Version=$v.version_number;ProjectID=$v.project_id}}}catch{};[pscustomobject]@{Found=$false}}
function Zone($p){try{(($x=Get-Content -LiteralPath $p -Stream Zone.Identifier -ErrorAction Stop|?{$_ -like 'HostUrl=*'}|select -First 1));if($x){return $x.Substring(8)}}catch{};return $null}
$rules=[ordered]@{
 'Process execution'=@('java/lang/ProcessBuilder','Runtime.exec','ProcessBuilder.start')
 'Network communication'=@('java/net/Socket','java/net/ServerSocket','java/net/HttpURLConnection','java/net/URLConnection','java/net/http/HttpClient','java/net/URL','okhttp','socket')
 'Command shell'=@('cmd.exe','/bin/sh','/bin/bash','powershell.exe','pwsh')
 'PowerShell / web execution'=@('Invoke-WebRequest','Invoke-RestMethod','DownloadString','DownloadFile','powershell -enc','powershell -encodedcommand','Invoke-Expression')
 'File-system access'=@('java/io/File','java/nio/file','FileOutputStream','FileInputStream')
 'Reflection'=@('java/lang/reflect','Class.forName','getDeclaredMethod','getDeclaredField','setAccessible')
}
$high=@('VirtualAlloc','CreateRemoteThread','WriteProcessMemory','OpenProcess','NtWriteVirtualMemory','powershell -enc','powershell -encodedcommand','Invoke-Expression')
if(!$ModsPath){$d=Join-Path $env:APPDATA '.minecraft\mods';$ModsPath=Read-Host "Mods folder [$d]";if([string]::IsNullOrWhiteSpace($ModsPath)){$ModsPath=$d}}
$ModsPath=[Environment]::ExpandEnvironmentVariables($ModsPath)
if(!(Test-Path -LiteralPath $ModsPath -PathType Container)){Write-Host "[!] Folder does not exist: $ModsPath" -ForegroundColor Red;exit 1}
$jars=@(Get-ChildItem -LiteralPath $ModsPath -Filter '*.jar' -File)
Clear-Host
H 'PROX MOD ANALYZER'
Write-Host "Folder: $ModsPath`nMods found: $($jars.Count)"
if(!$jars.Count){Write-Host '[!] No JAR files found.' -ForegroundColor Yellow;exit}
foreach($jar in $jars){
 H "Analyzing: $($jar.Name)"
 Write-Host "File size: $([math]::Round($jar.Length/1MB,2)) MB"
 $hh=Hashes $jar.FullName;Write-Host "`nSHA-256: $($hh.SHA256)`nSHA-1:   $($hh.SHA1)"
 if($z=Zone $jar.FullName){Write-Host "`n[ORIGIN]`n    Host URL: $z"}
 $score=0;$reasons=New-Object System.Collections.Generic.List[string];$found=@{};$highHits=@{}
 try{
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip=[IO.Compression.ZipFile]::OpenRead($jar.FullName)
  Write-Host "[+] JAR structure: Valid";Write-Host "[+] Files inside JAR: $($zip.Entries.Count)"
  H '[MOD METADATA]'
  $md=$zip.Entries|?{$_.FullName -in @('fabric.mod.json','quilt.mod.json','META-INF/mods.toml','mcmod.info')}
  if($md){foreach($e in $md){Write-Host "    [+] Found: $($e.FullName)";if($e.FullName -match 'fabric|quilt'){try{$sr=New-Object IO.StreamReader($e.Open());$t=$sr.ReadToEnd();$sr.Dispose();$j=$t|ConvertFrom-Json;Write-Host "        Name:    $($j.name)";Write-Host "        Mod ID:  $($j.id)";Write-Host "        Version: $($j.version)"}catch{}}}}else{Write-Host '    [i] No common mod metadata file found.'}
  H '[MANIFEST]';$mf=$zip.GetEntry('META-INF/MANIFEST.MF');if($mf){$sr=New-Object IO.StreamReader($mf.Open());$mt=$sr.ReadToEnd();$sr.Dispose();$x=$mt-split "`r?`n"|?{$_-match '^(Main-Class|Premain-Class|Agent-Class):'};if($x){$x|%{Write-Host "    [i] $_"}}else{Write-Host '    [+] No executable manifest entry.'}}else{Write-Host '    [+] No manifest.'}
  H '[EMBEDDED JARS]';$emb=@($zip.Entries|?{$_.FullName -match '\.jar$'});if(!$emb.Count){Write-Host '    None found.'}else{$emb|%{Write-Host "    $($_.FullName)"}}
  H '[STATIC INDICATORS]';$classes=@($zip.Entries|?{$_.FullName -match '\.class$'});Write-Host "    Java classes: $($classes.Count)"
  $short=@($classes|%{($_.FullName-replace '\.class$',''-split '/')[-1]}|?{$_.Length -le 2}).Count;$ratio=if($classes.Count){$short/$classes.Count}else{0};if($ratio -ge .2){Write-Host "    [!] High proportion of very short class names: $short/$($classes.Count) ($([math]::Round($ratio*100,1))%)" -ForegroundColor Yellow;$score+=7;$reasons.Add('High proportion of short class names')}else{Write-Host '    [+] Class names look relatively normal.'}
  foreach($e in $zip.Entries){if($e.FullName.EndsWith('/') -or $e.Length -gt 10MB){continue};try{$sr=New-Object IO.StreamReader($e.Open(),[Text.Encoding]::UTF8,$true);$txt=$sr.ReadToEnd();$sr.Dispose();foreach($cat in $rules.Keys){foreach($ind in $rules[$cat]){if($txt.IndexOf($ind,[StringComparison]::OrdinalIgnoreCase)-ge 0){if(!$found.ContainsKey($cat)){$found[$cat]=@()};if($found[$cat].Count-lt 8){$found[$cat]+="$ind -> $($e.FullName)"}}};foreach($ind in $high){if($txt.IndexOf($ind,[StringComparison]::OrdinalIgnoreCase)-ge 0){$highHits["$ind -> $($e.FullName)"]=1}}}}catch{}}
  foreach($cat in $rules.Keys){if($found.ContainsKey($cat)){Write-Host "    [!] $cat" -ForegroundColor Yellow;$found[$cat]|%{Write-Host "        $_"}}else{Write-Host "    [+] $cat`: Not detected"}}
  H '[HIGH-RISK INDICATORS]';if(!$highHits.Count){Write-Host '    None found.'}else{$highHits.Keys|%{Write-Host "    [!!!] $_" -ForegroundColor Red;$score+=15};$reasons.Add('High-risk execution indicator(s)')}
  if($found.ContainsKey('Process execution')){$score+=10;$reasons.Add('Process execution capability')};if($found.ContainsKey('Network communication')){$score+=5;$reasons.Add('Network communication capability')};if($found.ContainsKey('Command shell')){$score+=15;$reasons.Add('Command shell capability')};if($found.ContainsKey('PowerShell / web execution')){$score+=20;$reasons.Add('PowerShell/web execution indicator')};if($found.ContainsKey('File-system access')){$score+=3;$reasons.Add('File-system API usage')};if($found.ContainsKey('Reflection')){$score+=2;$reasons.Add('Reflection API usage')};$score=[Math]::Min(100,$score)
  H 'HASH REPUTATION (MODRINTH)';$mr=MR $hh.SHA1;if($mr.Found){Write-Host '    [+] Exact SHA-1 match found on Modrinth.' -ForegroundColor Green;Write-Host "        Project: $($mr.Name)";Write-Host "        Mod ID:  $($mr.Slug)";Write-Host "        Version: $($mr.Version)"}else{Write-Host '    [!] SHA-1 not found on Modrinth.' -ForegroundColor Yellow;Write-Host '        This does NOT mean the mod is malicious.'}
  H 'RISK ASSESSMENT';$v=if($score -le 10){'LOW RISK'}elseif($score -le 25){'REVIEW'}elseif($score -le 45){'SUSPICIOUS'}else{'HIGH RISK'};Write-Host "Score:   $score/100`nVerdict: $v";Write-Host "`nReasons:";if($reasons.Count){$reasons|select -Unique|%{Write-Host "    - $_"}}else{Write-Host '    - No basic static indicators detected'};Write-Host "`nIMPORTANT:`n    This is static analysis only.`n    A capability is not proof of malware.`n    A clean result is not proof that a mod is safe.";$zip.Dispose()
 }catch{Write-Host "[!] Could not analyze archive: $($_.Exception.Message)" -ForegroundColor Red}
}
H 'Analysis complete.'
