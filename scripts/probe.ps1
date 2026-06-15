param(
    [Parameter(Mandatory=$true)][string]$Target,
    [string]$BaseUrl = "",
    [ValidateSet("HEAD", "OPTIONS", "GET")][string]$Method = "HEAD",
    [int]$Limit = 0
)

$argsList = @("probe", $Target, "--method", $Method)
if ($BaseUrl) {
    $argsList += @("--base-url", $BaseUrl)
}
if ($Limit -gt 0) {
    $argsList += @("--limit", "$Limit")
}

python ".\ai_src.py" @argsList
