$MODULE_ID="dead-drop-resolver"
$MODULE_TECHNIQUE="T1102"
$MODULE_DESCRIPTION="Detect Dead Drop Resolver C2 via legitimate web services"
function Add-Finding($t,$s,$e,$r){[pscustomobject]@{technique_id=$MODULE_TECHNIQUE;title=$t;severity=$s;evidence=$e;remediation=$r}}
function run_checks {
  $findings=@();$allow='chrome','msedge','firefox','iexplore','opera','brave','steam','steamwebhelper'
  try{
    $procs=Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $hits=$procs|?{$_.Name -and $allow -notcontains ([IO.Path]::GetFileNameWithoutExtension($_.Name).ToLower()) -and $_.CommandLine -match '(steamcommunity\.com/(id|profiles)/|pastebin\.com/|docs\.google\.com/forms)'}|%{"$($_.Name): $($_.CommandLine)"}
    $hist=Get-ChildItem "$env:LOCALAPPDATA","$env:APPDATA" -Recurse -File -ErrorAction SilentlyContinue|?{$_.FullName -match 'History|Cache|WebCache|Cookies' -and $_.Length -lt 5MB -and $_.LastWriteTime -gt (Get-Date).AddDays(-7)}|Select -First 30
    $hh=foreach($f in $hist){try{Select-String -Path $f.FullName -Pattern 'steamcommunity\.com/(id|profiles)/|pastebin\.com/|docs\.google\.com/forms' -AllMatches -ErrorAction Stop|%{"$($f.Name): $($_.Matches.Value -join ',')"}}catch{}}
    if($hits -or $hh){$findings+=Add-Finding "Suspicious access to dead-drop web pages" "high" (@($hits+$hh)|Select -First 8) "Investigate listed processes, remove unauthorized loaders, and clear browser artifacts after containment."}
  }catch{}
  try{
    $dns=Get-DnsClientCache -ErrorAction Stop|?{$_.Entry -match 'steamcommunity\.com|pastebin\.com|docs\.google\.com'}|%{"$($_.Entry) TTL=$($_.TimeToLive)"}
    if($dns){$findings+=Add-Finding "Recent DNS cache entries for dead-drop services" "medium" $dns "Review recent process execution and DNS activity; block or sinkhole unapproved destinations if malicious."}
  }catch{}
  try{
    $ips=(Get-DnsClientCache -ErrorAction SilentlyContinue|?{$_.Entry -match 'steamcommunity\.com|pastebin\.com|docs\.google\.com' -and $_.Data -match '^\d{1,3}(\.\d{1,3}){3}$'}).Data|Select -Unique
    $net=if($ips){Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue|?{$ips -contains $_.RemoteAddress}|%{$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;if($p -and $allow -notcontains $p.ProcessName.ToLower()){"$($p.ProcessName) -> $($_.RemoteAddress):$($_.RemotePort)"}}}
    if($net){$findings+=Add-Finding "Unexpected process connected to dead-drop infrastructure" "high" $net "Terminate and isolate unexpected processes, collect memory, and review persistence or credential theft activity."}
  }catch{}
  try{
    $roots=@($env:TEMP,$env:LOCALAPPDATA,$env:APPDATA)|?{$_};$urls=@()
    foreach($f in Get-ChildItem $roots -Recurse -File -ErrorAction SilentlyContinue|?{$_.LastWriteTime -gt (Get-Date).AddDays(-3) -and $_.Length -lt 1MB}|Select -First 200){
      try{$txt=[IO.File]::ReadAllText($f.FullName);[regex]::Matches($txt,'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])')|%{try{$d=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.Value));if($d -match '^https?://(steamcommunity\.com|pastebin\.com|docs\.google\.com/forms)'){$urls+="$($f.FullName): $d"}}catch{}}}catch{}
    }
    if($urls){$findings+=Add-Finding "Base64-encoded URLs found in recent Temp/AppData files" "high" ($urls|Select -First 10) "Quarantine decoded payload sources, delete malicious temp files, and scan for infostealer persistence or loaders."}
  }catch{}
  $findings|ConvertTo-Json -Depth 4
}
run_checks
