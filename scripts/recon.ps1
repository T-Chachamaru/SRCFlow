param(
    [Parameter(Mandatory=$true)][string]$Target,
    [string]$Config = "",
    [string]$Url = "",
    [int]$Depth = 2,
    [int]$Threads = 10,
    [switch]$Render,
    [switch]$Katana
)

if ($Katana) {
    if (-not $Url) {
        Write-Error "-Url is required when -Katana is used."
        exit 2
    }
    python ".\ai_src.py" katana-crawl $Target $Url --depth $Depth
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$argsList = @("crawl", $Target, "--depth", "$Depth", "--threads", "$Threads")
if ($Config) {
    $argsList += @("--config", $Config)
}
if ($Render) {
    $argsList += "--render"
}
python ".\ai_src.py" @argsList
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$extractArgs = @("extract", $Target)
if ($Config) {
    $extractArgs += @("--config", $Config)
}
python ".\ai_src.py" @extractArgs
exit $LASTEXITCODE
