param([string]$ModsPath="")
$ErrorActionPreference='Stop'

function Section([string]$t){Write-Host "`n==========================================================`n$t`n=========================================================="}
function Hashes([string]$p){[pscustomobject]@{SHA256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower();SHA1=(Get-FileHash -LiteralPath $p -Algorithm SHA1).Hash.ToLower()}}
function Zone([string]$p){try{$x=Get-Content -LiteralPath $p -Stream Zone.Identifier -ErrorAction Stop|Where-Object {$_ -like 'HostUrl=*'}|Select-Object -First 1;if($x){return $x.Substring(8)}}catch{};return $null}
function Modrinth([string]$sha1){try{$h=@{'User-Agent'='PROX-Mod-Analyzer/1.0'};$v=Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$sha1" -Headers $h -TimeoutSec 8;if(-not $v){return [pscustomobject]@{Found=$false}};$p=$null;if($v.project_id){$p=Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($v.project_id)" -Headers $h -TimeoutSec 8};return [pscustomobject]@{Found=$true;Name=if($p){$p.title}else{'Unknown'};Slug=if($p){$p.slug}else{'Unknown'};Version=$v.version_number;ProjectID=$v.project_id}}catch{return [pscustomobject]@{Found=$false}}}
function ReadEntryText($entry){$r=New-Object IO.StreamReader($entry.Open(),[Text.Encoding]::UTF8,$true);$t=$r.ReadToEnd();$r.Dispose();return $t}

# High-confidence cheat-client fingerprints observed in real client architectures.
$CheatNames=@{
  'Combat automation'=@('AimAssist','TriggerBot','AutoClicker','AutoCrystal','AutoHitCrystal','AutoPot','AutoPotRefill','AutoWTap','AutoJumpReset','AutoInventoryTotem','AutoDoubleHand','ShieldDisabler','TotemOffhand','CrystalOptimizer','AnchorMacro','DoubleAnchor','NoMissDelay')
  'Movement/network manipulation'=@('PingSpoof','FakeLag','PackSpoof','Freecam','NoJumpDelay','NoBreakDelay','Sprint')
  'ESP/targeting'=@('PlayerESP','StorageEsp','TargetHud','ClickGUI','HUD')
  'Self-destruct/anti-analysis'=@('SelfDestruct','EncryptedString')
}
$SuspiciousClasses=@('MouseSimulation','RotationUtils','RotatorManager','PacketSendListener','PacketReceiveListener','MovementPacketListener','ClientConnectionMixin','KeyboardMixin','MouseMixin','ClientPlayerEntityMixin')
$NativeRisk=@('VirtualAlloc','CreateRemoteThread','WriteProcessMemory','OpenProcess','NtWriteVirtualMemory','JNI_OnLoad')
$ShellRisk=@('cmd.exe','powershell.exe','pwsh','Invoke-Expression','DownloadString','DownloadFile','ProcessBuilder.start','Runtime.exec')

if(!$ModsPath){$d=Join-Path $env:APPDATA '.minecraft\mods';$ModsPath=Read-Host "Mods folder [$d]";if([string]::IsNullOrWhiteSpace($ModsPath)){$ModsPath=$d}}
$ModsPath=[Environment]::ExpandEnvironmentVariables($ModsPath)
if(!(Test-Path -LiteralPath $ModsPath -PathType Container)){Write-Host "[!] Folder does not exist: $ModsPath" -ForegroundColor Red;exit 1}
$jars=@(Get-ChildItem -LiteralPath $ModsPath -Filter '*.jar' -File)
Clear-Host
Section 'PROX MOD ANALYZER V5'
Write-Host "Folder: $ModsPath";Write-Host "Mods found: $($jars.Count)"
if(!$jars.Count){Write-Host '[!] No JAR files found.' -ForegroundColor Yellow;exit 0}

$verified=New-Object System.Collections.Generic.List[object]
$low=New-Object System.Collections.Generic.List[object]
$review=New-Object System.Collections.Generic.List[object]
$susp=New-Object System.Collections.Generic.List[object]
$high=New-Object System.Collections.Generic.List[object]
$unknown=New-Object System.Collections.Generic.List[object]

foreach($jar in $jars){
  try{
    $h=Hashes $jar.FullName
    $mr=Modrinth $h.SHA1
    $origin=Zone $jar.FullName
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip=[IO.Compression.ZipFile]::OpenRead($jar.FullName)
    $entries=@($zip.Entries)
    $names=@($entries|ForEach-Object {$_.FullName})
    $score=0;$reasons=New-Object System.Collections.Generic.List[string];$evidence=New-Object System.Collections.Generic.List[string]

    # ---- Metadata ----
    $meta=$null;$metaPath=$null
    foreach($candidate in @('fabric.mod.json','quilt.mod.json')){ $x=$zip.GetEntry($candidate); if($x){$meta=$x;$metaPath=$candidate;break} }
    $declaredId=$null;$declaredName=$null;$declaredVersion=$null;$entrypoints=@();$mixins=@()
    if($meta){
      try{$j=(ReadEntryText $meta)|ConvertFrom-Json;$declaredId=[string]$j.id;$declaredName=[string]$j.name;$declaredVersion=[string]$j.version
        if($j.entrypoints){foreach($p in $j.entrypoints.PSObject.Properties.Value){foreach($ep in @($p)){if($ep -is [string]){$entrypoints+=[string]$ep}elseif($ep.value){$entrypoints+=[string]$ep.value}}}}
        if($j.mixins){$mixins=@($j.mixins|ForEach-Object {[string]$_})}
      }catch{}
    }

    # ---- Cheap archive facts ----
    $classEntries=@($entries|Where-Object {$_.FullName -match '\.class$'})
    $classPaths=@($classEntries|ForEach-Object {$_.FullName})
    $classCount=$classEntries.Count
    $short=0
    foreach($c in $classPaths){$n=(($c -replace '\.class$','') -split '/')[-1];if($n.Length -le 2){$short++}}
    $shortRatio=if($classCount){$short/$classCount}else{0}
    if($shortRatio -ge .20){$score+=7;$reasons.Add('High proportion of short class names')}

    # ---- Content scanning ----
    $cheatHits=@{}
    $capHits=@{}
    $riskHits=@{}
    $classNameHits=New-Object System.Collections.Generic.List[string]
    foreach($cat in $CheatNames.Keys){$cheatHits[$cat]=New-Object System.Collections.Generic.List[string]}
    $capHits['Suspicious framework']=New-Object System.Collections.Generic.List[string]
    foreach($e in $entries){
      if($e.FullName.EndsWith('/') -or $e.Length -gt 15MB){continue}
      $text=''
      try{$text=ReadEntryText $e}catch{continue}
      foreach($cat in $CheatNames.Keys){foreach($term in $CheatNames[$cat]){if($text.IndexOf($term,[StringComparison]::OrdinalIgnoreCase)-ge 0 -and $cheatHits[$cat].Count -lt 12){$cheatHits[$cat].Add("$term -> $($e.FullName)")}}}
      foreach($term in $SuspiciousClasses){if($text.IndexOf($term,[StringComparison]::OrdinalIgnoreCase)-ge 0 -and $capHits['Suspicious framework'].Count -lt 20){$capHits['Suspicious framework'].Add("$term -> $($e.FullName)")}}
      foreach($term in $NativeRisk){if($text.IndexOf($term,[StringComparison]::OrdinalIgnoreCase)-ge 0){$riskHits["$term -> $($e.FullName)"]=1}}
      foreach($term in $ShellRisk){if($text.IndexOf($term,[StringComparison]::OrdinalIgnoreCase)-ge 0){$riskHits["$term -> $($e.FullName)"]=1}}
    }

    # Scan class path names separately. This catches renamed/opaque string use less dependent on readable bytecode strings.
    foreach($path in $classPaths){foreach($cat in $CheatNames.Keys){foreach($term in $CheatNames[$cat]){if(([IO.Path]::GetFileNameWithoutExtension($path)).IndexOf($term,[StringComparison]::OrdinalIgnoreCase)-ge 0 -and $cheatHits[$cat].Count -lt 12){$cheatHits[$cat].Add("CLASS NAME: $path")}}}}

    # ---- Strong architecture signals ----
    $cheatCategories=0
    foreach($cat in $cheatHits.Keys){if($cheatHits[$cat].Count -gt 0){$cheatCategories++;$evidence.Add("$cat: $($cheatHits[$cat].Count) indicator(s)")}}
    if($cheatCategories -eq 1){$score+=20;$reasons.Add('Cheat-client feature indicators')}
    elseif($cheatCategories -eq 2){$score+=40;$reasons.Add('Multiple cheat-client feature categories')}
    elseif($cheatCategories -ge 3){$score+=65;$reasons.Add('Strong multi-category cheat-client fingerprint')}

    if($capHits['Suspicious framework'].Count -ge 2){$score+=10;$reasons.Add('Client automation/packet framework indicators')}
    if($riskHits.Count -gt 0){$score+=25;$reasons.Add('High-risk execution indicator(s)')}

    # ---- Namespace / metadata mismatch detection ----
    $packageHints=@()
    foreach($p in $classPaths){if($p -match '^([^/]+/[^/]+)/'){ $packageHints += $Matches[1] }}
    $distinctHints=@($packageHints|Select-Object -Unique)
    $mismatchCount=0
    if($declaredId){foreach($hint in $distinctHints){$normalized=$hint.Replace('/','').Replace('_','').Replace('-','').ToLower();$idnorm=$declaredId.Replace('_','').Replace('-','').ToLower();if($normalized -notmatch [regex]::Escape($idnorm) -and $normalized.Length -gt 5){$mismatchCount++}}}
    if($mismatchCount -ge 2){$score+=20;$reasons.Add('Declared mod identity does not match code namespace');$evidence.Add("Namespace mismatch: declared '$declaredId' vs code packages such as '$($distinctHints[0])'")}

    # Entrypoint mismatch is extremely useful against masquerading mods.
    if($declaredId -and $entrypoints.Count -gt 0){
      foreach($ep in $entrypoints){$epNorm=$ep.ToLower();if($declaredId.ToLower() -notmatch ($epNorm -replace '\..*$','') -and $epNorm -match 'argon|cheat|hack|client|clickgui|module'){ $score+=25;$reasons.Add('Suspicious entrypoint identity mismatch');$evidence.Add("Entrypoint: $ep")}}
    }

    # Mixin naming: suspicious client-control hooks are stronger when combined with cheat categories.
    $mixinHits=@($mixins|Where-Object {$_ -match '(?i)mouse|keyboard|connection|player|camera|interaction|inventory|packet'})
    if($mixinHits.Count -ge 3 -and $cheatCategories -ge 1){$score+=15;$reasons.Add('Cheat-related client mixin surface');foreach($m in $mixinHits|Select-Object -First 8){$evidence.Add("Mixin: $m")}}

    # Known masquerading pattern found in supplied sample: metadata/assets can point at another legitimate mod.
    $argHints=@($classPaths|Where-Object {$_ -match '(?i)lvstrng/argon|argon/'})
    $argFiles=@($names|Where-Object {$_ -match '(?i)argon'})
    if($argHints.Count -ge 2){$score+=60;$reasons.Add('Argon-family code namespace detected');$evidence.Add("Argon namespace classes: $($argHints.Count)")}
    if($argFiles.Count -ge 2){$score+=10;$reasons.Add('Argon-related archive artifacts detected')}

    # ---- Final reputation ----
    $score=[Math]::Min(100,$score)
    if($score -ge 75){$verdict='HIGH RISK'}elseif($score -ge 45){$verdict='SUSPICIOUS'}elseif($score -ge 20){$verdict='REVIEW'}else{$verdict='LOW RISK'}

    $name=if($mr.Found){$mr.Name}else{if($declaredName){$declaredName}else{$jar.BaseName}}
    $result=[pscustomobject]@{Name=$name;File=$jar.Name;SHA256=$h.SHA256;SHA1=$h.SHA1;Score=$score;Verdict=$verdict;Reasons=$reasons;Evidence=$evidence;Modrinth=$mr;Origin=$origin;ClassCount=$classCount}

    # Exact hash match is useful reputation evidence, but NEVER overrides a strong static finding.
    if($mr.Found -and $score -lt 20){$verified.Add($result)}elseif($score -lt 10){$low.Add($result)}elseif($score -lt 45){$review.Add($result)}elseif($score -lt 75){$susp.Add($result)}else{$high.Add($result)}
    
    $zip.Dispose()
  }
  catch{$unknown.Add([pscustomobject]@{Name=$jar.BaseName;File=$jar.Name;Error=$_.Exception.Message})}
}

Clear-Host
Section 'PROX MOD ANALYZER V5'
Write-Host "Folder: $ModsPath";Write-Host "Mods found: $($jars.Count)"

function PrintGroup($title,$items,$color,[bool]$showScore){Write-Host "`n{ $title }" -ForegroundColor $color;if($items.Count -eq 0){Write-Host '> None'}else{foreach($m in $items){$suffix=if($showScore){"  [$($m.Score)/100]"}else{""};Write-Host ("> " + $m.Name.PadRight(30) + $m.File + $suffix)}}}
PrintGroup 'Verified Mods' $verified Green $true
PrintGroup 'Low Risk' $low Gray $true
PrintGroup 'Review' $review Yellow $true
PrintGroup 'Suspicious' $susp DarkYellow $true
PrintGroup 'High Risk' $high Red $true
PrintGroup 'Unknown' $unknown Magenta $false

$flagged=@($review+$susp+$high)
if($flagged.Count -gt 0){Section 'FLAGGED DETAILS';foreach($m in $flagged){Write-Host "`n$m.File" -ForegroundColor Yellow;Write-Host "    Score:   $($m.Score)/100";Write-Host "    Verdict: $($m.Verdict)";if($m.Reasons.Count){Write-Host '    Reasons:';$m.Reasons|Select-Object -Unique|ForEach-Object{Write-Host "        - $_"}};if($m.Evidence.Count){Write-Host '    Evidence:';$m.Evidence|Select-Object -First 15|ForEach-Object{Write-Host "        $_"}};Write-Host "    SHA-256: $($m.SHA256)";Write-Host "    SHA-1:   $($m.SHA1)";if($m.Modrinth.Found){Write-Host "    Modrinth: $($m.Modrinth.Name) $($m.Modrinth.Version)"}else{Write-Host '    Modrinth: No exact SHA-1 match'};if($m.Origin){Write-Host "    Origin:   $($m.Origin)"}}}

Section 'SUMMARY'
Write-Host "Total:       $($jars.Count)";Write-Host "Verified:    $($verified.Count)" -ForegroundColor Green;Write-Host "Low Risk:    $($low.Count)";Write-Host "Review:      $($review.Count)" -ForegroundColor Yellow;Write-Host "Suspicious:  $($susp.Count)" -ForegroundColor DarkYellow;Write-Host "High Risk:   $($high.Count)" -ForegroundColor Red;Write-Host "Unknown:     $($unknown.Count)" -ForegroundColor Magenta
Write-Host "`nIMPORTANT:";Write-Host '    Static analysis and reputation checks can provide strong evidence, but cannot guarantee detection of every future or heavily obfuscated threat.'
Section 'Analysis complete.'
