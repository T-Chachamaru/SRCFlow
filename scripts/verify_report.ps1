param(
    [Parameter(Mandatory=$true)][string]$Report
)

python ".\ai_src.py" gate $Report
