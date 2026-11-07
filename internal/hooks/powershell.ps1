# Runs inside the captured PowerShell, after the user's profiles.
if ($env:PENTRAIL_TOKEN -and -not $global:__PentrailHooked) {
    $global:__PentrailHooked = $true
    $global:__PentrailUtf8 = New-Object System.Text.UTF8Encoding($false)
    [Console]::InputEncoding = $global:__PentrailUtf8
    [Console]::OutputEncoding = $global:__PentrailUtf8
    $global:OutputEncoding = $global:__PentrailUtf8
    function global:__PentrailMarker([string]$data) {
        [Console]::Write(([string][char]27) + ']697;' + $env:PENTRAIL_TOKEN + ';' + $data + [char]7)
    }
    $global:__PentrailOldPrompt = (Get-Command prompt -CommandType Function -ErrorAction SilentlyContinue).ScriptBlock
    function global:prompt {
        $ok = $?
        if ($global:__PentrailCommandActive) {
            $code = if ($ok) { 0 } else { 1 }
            __PentrailMarker "D;$code"
            $global:__PentrailCommandActive = $false
        }
        __PentrailMarker 'A'
        if ($global:__PentrailOldPrompt) { & $global:__PentrailOldPrompt } else { "PS $($executionContext.SessionState.Path.CurrentLocation)> " }
    }
    if (Get-Module -ListAvailable PSReadLine) {
        Import-Module PSReadLine -ErrorAction SilentlyContinue
        # Automatic history predictions can redraw a command entered during off.
        # Disable predictions only in this captured process; keep history filtering.
        $predictionOption = Get-Command Set-PSReadLineOption -ErrorAction SilentlyContinue
        if ($predictionOption -and $predictionOption.Parameters.ContainsKey('PredictionSource')) {
            Set-PSReadLineOption -PredictionSource None -ErrorAction SilentlyContinue
        }
        # Keep PSReadLine's own sensitive-history filtering and user handlers.
        # Observe the returned line instead of replacing AddToHistoryHandler.
        $global:__PentrailOldReadLine = (Get-Command PSConsoleHostReadLine -CommandType Function -ErrorAction SilentlyContinue).ScriptBlock
        if ($global:__PentrailOldReadLine) {
            function global:PSConsoleHostReadLine {
                $line = & $global:__PentrailOldReadLine @args
                if ($line -is [string] -and $line.Length -gt 0) {
                    __PentrailMarker ('CWD;' + $executionContext.SessionState.Path.CurrentLocation)
                    __PentrailMarker ('CMD;' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($line)))
                    __PentrailMarker 'C'
                    $global:__PentrailCommandActive = $true
                }
                return $line
            }
        }
    }
}
