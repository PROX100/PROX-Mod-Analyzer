param([string]$ModsPath="")
$ErrorActionPreference='Continue'

function Section([string]$Text){Write-Host "`n==========================================================`n$Text`n=========================================================="}
function Get-Hashes([string]$Path){[pscustomobject]@{SHA256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower();SHA1=(Get-FileHash -LiteralPath $Path -Algorithm SHA1).Hash.ToLower()}}
function Get-Modrinth([string]$Sha1){try{$h=@{'User-Agent'='PROX-Mod-Analyzer/2.0'};$v=Invoke-RestMethod -UseBasicParsing -Uri "https://api.modrinth.com/v2/version_file/$Sha1" -Headers $h -TimeoutSec 8;if(-not $v){return [pscustomobject]@{Found=$false}};$pr=$null;if($v.project_id){$pr=Invoke-RestMethod -UseBasicParsing -Uri "https://api.modrinth.com/v2/project/$($v.project_id)" -Headers $h -TimeoutSec 8};[pscustomobject]@{Found=$true;Name=if($pr){$pr.title}else{'Unknown'};Slug=if($pr){$pr.slug}else{'Unknown'};Version=$v.version_number;ProjectID=$v.project_id}}catch{[pscustomobject]@{Found=$false}}}
function Get-Zone([string]$Path){try{$x=Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop|Where-Object{$_ -like 'HostUrl=*'}|Select-Object -First 1;if($x){$x.Substring(8)}}catch{$null}}
function Read-EntryText($Entry){if($Entry.Length -gt 8MB){return ''};try{$st=$Entry.Open();$ms=New-Object IO.MemoryStream;$st.CopyTo($ms);$st.Dispose();return [Text.Encoding]::UTF8.GetString($ms.ToArray())}catch{return ''}}

# High-confidence cheat/client terms. These are used together with structural evidence.
$CheatTerms=[ordered]@{
 'Combat automation'=@('AimAssist','Aimbot','TriggerBot','AutoClicker','AutoCrystal','AutoHitCrystal','AutoPot','AutoTotem','AutoArmor','AutoInventoryTotem','AutoWTap','CrystalOptimizer','ShieldDisabler','NoMissDelay','AnchorMacro','DoubleAnchor')
 'Movement/network manipulation'=@('Velocity','Fly','Speed','Flight','Freecam','PingSpoof','FakeLag','PacketFly','NoFall','Sprint','Blink','Timer','Packet')
 'Visual/player targeting'=@('PlayerESP','StorageEsp','TargetHud','NameTags','ESP','Tracers','XRay','Targeting','Hitboxes')
 'Client framework'=@('ClickGUI','ModuleManager','ModuleButton','FriendManager','ProfileManager','RotatorManager','RotationUtils','EventManager','PacketSendListener','PacketReceiveListener','MovementPacketListener')
 'Self-destruct/anti-analysis'=@('SelfDestruct','Self-Destruct','DestroyClient','UnloadModules','deleteSelf','deleteClient')
}
$NativeHigh=@('VirtualAlloc','CreateRemoteThread','WriteProcessMemory','OpenProcess','NtWriteVirtualMemory')
$ShellTerms=@('cmd.exe','powershell.exe','pwsh','Invoke-Expression','DownloadString','DownloadFile','powershell -enc','powershell -encodedcommand')

# Strong namespace/fingerprint examples observed in known cheat-client samples.
$KnownNamespaces=@('dev/lvstrng/argon/','me/','cc/','client/modules/','module/modules/')
$ExactKnown=@{
 'fd311430c688859bc867e739cddfe709cc8dea13'='Argon sample SHA-1'
 'fa3928b65ed2aa54e498567abdc31da3bc0d80249764e5c5d27de9d95449a66a'='Argon sample SHA-256'
}

if(-not $ModsPath){$d=Join-Path $env:APPDATA '.minecraft\mods';$ModsPath=Read-Host "Mods folder [$d]";if([string]::IsNullOrWhiteSpace($ModsPath)){$ModsPath=$d}}
$ModsPath=[Environment]::ExpandEnvironmentVariables($ModsPath)
if(-not(Test-Path -LiteralPath $ModsPath -PathType Container)){Write-Host "[!] Folder does not exist: $ModsPath" -ForegroundColor Red;exit 1}
$jars=@(Get-ChildItem -LiteralPath $ModsPath -Filter '*.jar' -File)
Clear-Host
Section 'PROX MOD ANALYZER V4'
Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"
if($jars.Count -eq 0){Write-Host '[!] No JAR files found.' -ForegroundColor Yellow;exit 0}

$verified=New-Object System.Collections.Generic.List[object]
$low=New-Object System.Collections.Generic.List[object]
$review=New-Object System.Collections.Generic.List[object]
$susp=New-Object System.Collections.Generic.List[object]
$high=New-Object System.Collections.Generic.List[object]
$unknown=New-Object System.Collections.Generic.List[object]

foreach($jar in $jars){
 try{
  $hh=Get-Hashes $jar.FullName
  $mr=Get-Modrinth $hh.SHA1
  $score=0;$reasons=New-Object System.Collections.Generic.List[string];$evidence=New-Object System.Collections.Generic.List[string]
  $termHits=@{};$classHits=@();$entryNames=@()
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip=[IO.Compression.ZipFile]::OpenRead($jar.FullName)
  $entryNames=@($zip.Entries|ForEach-Object{$_.FullName})

  # Exact known sample fingerprint. This is intentionally independent of Modrinth reputation.
  if($ExactKnown.ContainsKey($hh.SHA1) -or $ExactKnown.ContainsKey($hh.SHA256)){
   $score=100;$reasons.Add('Exact known cheat-client fingerprint match');$evidence.Add('Known sample fingerprint matched')
  }

  # Namespace / package structure.
  $allNames=($entryNames -join "`n")
  foreach($ns in $KnownNamespaces){$c=([regex]::Matches($allNames,[regex]::Escape($ns),'IgnoreCase')).Count;if($c -ge 5 -and $ns -ne 'me/'){ $score+=10;$reasons.Add("Suspicious client namespace structure");$evidence.Add("Namespace pattern: $ns ($c entries)") }}

  # Class-name evidence. Names are much more useful than scanning every resource byte.
  $classes=@($zip.Entries|Where-Object{$_.FullName -match '\.class$'})
  $classCount=$classes.Count
  foreach($cat in $CheatTerms.Keys){
   $hits=New-Object System.Collections.Generic.List[string]
   foreach($term in $CheatTerms[$cat]){
    $m=$classes|Where-Object{$_.FullName -match ("(?i)(^|/|\$)"+[regex]::Escape($term)+"(\$|\.class$)")}
    if($m){foreach($x in $m){if($hits.Count -lt 12){$hits.Add("$term -> $($x.FullName)")}}}
   }
   if($hits.Count -gt 0){$termHits[$cat]=$hits}
  }

  # Count strong cheat-feature classes.
  $combatCount=0;$movementCount=0;$renderCount=0;$selfCount=0;$frameworkCount=0
  if($termHits.ContainsKey('Combat automation')){$combatCount=$termHits['Combat automation'].Count; $score += [Math]::Min(30,[Math]::Max(10,$combatCount*5)); $reasons.Add('Cheat-specific combat modules')}
  if($termHits.ContainsKey('Movement/network manipulation')){$movementCount=$termHits['Movement/network manipulation'].Count;$score += [Math]::Min(25,[Math]::Max(5,$movementCount*3));$reasons.Add('Movement/network manipulation modules')}
  if($termHits.ContainsKey('Visual/player targeting')){$renderCount=$termHits['Visual/player targeting'].Count;$score += [Math]::Min(15,[Math]::Max(4,$renderCount*2));$reasons.Add('ESP/targeting modules')}
  if($termHits.ContainsKey('Self-destruct/anti-analysis')){$selfCount=$termHits['Self-destruct/anti-analysis'].Count;$score += 20;$reasons.Add('Self-destruct/anti-analysis feature')}
  if($termHits.ContainsKey('Client framework')){$frameworkCount=$termHits['Client framework'].Count;$score += [Math]::Min(15,[Math]::Max(3,$frameworkCount*2));$reasons.Add('Cheat-client framework structure')}

  # Strong correlation bonus: several independent cheat categories together.
  $cats=($termHits.Keys|Where-Object{$_ -in @('Combat automation','Movement/network manipulation','Visual/player targeting','Self-destruct/anti-analysis')}).Count
  if($cats -ge 3){$score+=20;$reasons.Add('Multiple independent cheat-client capability groups')}
  if($cats -ge 4){$score+=15;$reasons.Add('Very strong multi-category cheat-client fingerprint')}

  # Byte/string indicators, capped and given low weight unless shell/native APIs appear.
  $shellFound=$false;$nativeFound=$false;$networkFound=$false;$reflectionFound=$false
  foreach($entry in $zip.Entries){if($entry.FullName.EndsWith('/')){continue};$txt=Read-EntryText $entry;if(-not $txt){continue}
   foreach($t in $ShellTerms){if($txt.IndexOf($t,[StringComparison]::OrdinalIgnoreCase)-ge 0){$shellFound=$true}}
   foreach($t in $NativeHigh){if($txt.IndexOf($t,[StringComparison]::OrdinalIgnoreCase)-ge 0){$nativeFound=$true}}
   if($txt.IndexOf('java/net/Socket',[StringComparison]::OrdinalIgnoreCase)-ge 0 -or $txt.IndexOf('java/net/HttpURLConnection',[StringComparison]::OrdinalIgnoreCase)-ge 0){$networkFound=$true}
   if($txt.IndexOf('java/lang/reflect',[StringComparison]::OrdinalIgnoreCase)-ge 0){$reflectionFound=$true}
  }
  if($shellFound){$score+=15;$reasons.Add('Shell/script execution indicator')}
  if($nativeFound){$score+=30;$reasons.Add('Native process-memory indicator')}
  if($networkFound -and $cats -ge 2){$score+=5;$reasons.Add('Network capability combined with cheat features')}
  if($reflectionFound -and $cats -ge 2){$score+=3;$reasons.Add('Reflection combined with cheat features')}

  # Short class names are only a weak supporting signal.
  $short=0
  foreach($c in $classes){$n=(($c.FullName-replace '\.class$','')-split '/')[-1];if($n.Length -le 2){$short++}}
  if($classCount -gt 0 -and ($short/$classCount) -ge .20){$score+=5;$reasons.Add('High proportion of short class names')}

  $score=[Math]::Min(100,$score)
  if($score -ge 75){$verdict='HIGH RISK'}elseif($score -ge 45){$verdict='SUSPICIOUS'}elseif($score -ge 15){$verdict='REVIEW'}else{$verdict='LOW RISK'}

  $name=if($mr.Found){$mr.Name}else{$jar.BaseName}
  $r=[pscustomobject]@{Name=$name;File=$jar.Name;SHA256=$hh.SHA256;SHA1=$hh.SHA1;Score=$score;Verdict=$verdict;Reasons=$reasons|Select-Object -Unique;Evidence=$evidence;Terms=$termHits;Modrinth=$mr;Origin=Get-Zone $jar.FullName;ClassCount=$classCount}

  # Important: reputation no longer overrides strong behavioral evidence.
  if($mr.Found -and $score -lt 15){$verified.Add($r)}
  elseif($score -lt 15){$low.Add($r)}
  elseif($score -lt 45){$review.Add($r)}
  elseif($score -lt 75){$susp.Add($r)}
  else{$high.Add($r)}
  
  if($zip){$zip.Dispose()}
 }catch{
  $unknown.Add([pscustomobject]@{Name=$jar.BaseName;File=$jar.Name;Error=$_.Exception.Message})
 }
}

Clear-Host
Section 'PROX MOD ANALYZER V4'
Write-Host "Folder: $ModsPath"
Write-Host "Mods found: $($jars.Count)"

function Print-Group($Title,$Items,$Color){Write-Host "`n{ $Title }" -ForegroundColor $Color;if($Items.Count -eq 0){Write-Host '> None';return};foreach($m in $Items){Write-Host ("> "+$m.Name.PadRight(30)+$m.File+"  ["+$m.Score+"/100]")}}

Print-Group 'Verified Mods' $verified Green
Print-Group 'Low Risk' $low DarkGreen
Print-Group 'Review' $review Yellow
Print-Group 'Suspicious' $susp DarkYellow
Print-Group 'High Risk' $high Red
Print-Group 'Unknown' $unknown Magenta

$flagged=@($review+$susp+$high)
if($flagged.Count -gt 0 -or $unknown.Count -gt 0){
 Section 'FLAGGED DETAILS'
 foreach($m in $flagged){Write-Host "`n$m.File" -ForegroundColor Yellow;Write-Host "    Score: $($m.Score)/100";Write-Host "    Verdict: $($m.Verdict)";Write-Host '    Reasons:';foreach($x in $m.Reasons){Write-Host "        - $x"};if($m.Evidence.Count){Write-Host '    Evidence:';foreach($x in $m.Evidence){Write-Host "        - $x"}};foreach($cat in $m.Terms.Keys){Write-Host "    $cat`:";foreach($x in $m.Terms[$cat]){Write-Host "        $x"}};Write-Host "    SHA-256: $($m.SHA256)";Write-Host "    SHA-1:   $($m.SHA1)";if($m.Modrinth.Found){Write-Host "    Modrinth: $($m.Modrinth.Name) $($m.Modrinth.Version)"}else{Write-Host '    Modrinth: no exact hash match'}}
 foreach($m in $unknown){Write-Host "`n$m.File" -ForegroundColor Magenta;Write-Host "    [!] Analysis failed: $($m.Error)"}
}

Section 'SUMMARY'
Write-Host "Total:       $($jars.Count)"
Write-Host "Verified:    $($verified.Count)" -ForegroundColor Green
Write-Host "Low Risk:    $($low.Count)" -ForegroundColor DarkGreen
Write-Host "Review:      $($review.Count)" -ForegroundColor Yellow
Write-Host "Suspicious:  $($susp.Count)" -ForegroundColor DarkYellow
Write-Host "High Risk:   $($high.Count)" -ForegroundColor Red
Write-Host "Unknown:     $($unknown.Count)" -ForegroundColor Magenta
Write-Host "`nIMPORTANT:"
Write-Host '    This tool performs static analysis and reputation checks.'
Write-Host '    Exact reputation matches identify the file; they do not override behavioral evidence.'
Write-Host '    No static scanner can guarantee detection of every future or heavily obfuscated threat.'
Section 'Analysis complete.'
