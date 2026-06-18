param(
    [Parameter(Mandatory=$true)][string]$Report,
    [string]$Target = ""
)

$argsList = @("gate", $Report)
if ($Target) {
    $argsList += @("--target", $Target)
}

python ".\ai_src.py" @argsList
exit $LASTEXITCODE
