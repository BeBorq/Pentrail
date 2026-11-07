package hooks

import "strings"

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// psHostIsInteractive decides from the HOST command line (never from script
// arguments) whether this PowerShell process is an interactive window.
//
// Host parameters are parsed left to right like PowerShell does: names are
// case-insensitive, may be abbreviated to any prefix, and some have explicit
// aliases. Anything not starting with '-' (a script path, also "/x.ps1",
// or a command) is treated as batch: when in doubt, the window is NOT
// wrapped — it keeps working, unrecorded, instead of being taken over. Parsing stops at the first
// parameter that runs something (everything after it belongs to the
// command/script). Values of value-taking parameters are skipped, so
// `-WorkingDirectory C:\x` stays interactive. A positional argument is a
// script file (pwsh) or a command (Windows PowerShell): batch.
// Codex iteration 03: -CommandWithArgs/-cwa and -ec/-en were not recognised.
const psHostIsInteractive = `$__ptInteractive = $true
$__ptSkip = $false
foreach ($__ptArg in [Environment]::GetCommandLineArgs() | Select-Object -Skip 1) {
    if ($__ptSkip) { $__ptSkip = $false; continue }
    if (-not $__ptArg.StartsWith('-')) { $__ptInteractive = $false; break }
    $__ptFlag = $__ptArg.TrimStart('-').Split(':')[0].ToLowerInvariant()
    if ($__ptFlag -eq '' -or @('c', 'cwa', 'e', 'ec', 'en', 'f', 'noni') -contains $__ptFlag) { $__ptInteractive = $false; break }
    $__ptRuns = $false
    foreach ($__ptName in @('command', 'commandwithargs', 'encodedcommand', 'file', 'noninteractive')) {
        if ($__ptName.StartsWith($__ptFlag)) { $__ptRuns = $true }
    }
    if ($__ptRuns) { $__ptInteractive = $false; break }
    $__ptValue = @('config', 'ex', 'ep', 'inp', 'if', 'o', 'of', 'settings', 'wd', 'w', 'ea', 'v') -contains $__ptFlag
    foreach ($__ptName in @('configurationname', 'configurationfile', 'custompipename', 'executionpolicy', 'inputformat', 'outputformat', 'settingsfile', 'workingdirectory', 'windowstyle', 'psconsolefile', 'encodedarguments', 'version')) {
        if ($__ptName.StartsWith($__ptFlag)) { $__ptValue = $true }
    }
    if ($__ptValue -and -not $__ptArg.Contains(':')) { $__ptSkip = $true }
}
`

// PowerShellAutoStart is the body of the profile block that moves an
// interactive PowerShell window into a recorded session. bin is the pentrail
// executable, shell the PowerShell executable, custom an optional profile to
// load inside the session.
func PowerShellAutoStart(bin, shell, custom string) string {
	extra := ""
	if custom != "" {
		extra = " --startup-profile " + psQuote(custom)
	}
	return `$__ptBinDir = ` + psQuote(dirOf(bin)) + `
if (($env:PATH -split ";") -notcontains $__ptBinDir) { $env:PATH = $__ptBinDir + ";" + $env:PATH }
` + psHostIsInteractive + `if ($__ptInteractive -and -not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
    $__ptOldExit = $global:LASTEXITCODE
    & ` + psQuote(bin) + ` __auto-check
    if ($LASTEXITCODE -eq 0) {
        & ` + psQuote(bin) + ` start --auto --shell ` + psQuote(shell) + extra + `
        if ($LASTEXITCODE -eq 0) { [Environment]::Exit(0) }
        Write-Warning 'Pentrail capture failed; this terminal is not recording.'
    }
    $global:LASTEXITCODE = $__ptOldExit
}
Remove-Variable __ptOldExit,__ptBinDir,__ptInteractive,__ptSkip,__ptArg,__ptFlag,__ptRuns,__ptName,__ptValue -ErrorAction SilentlyContinue
`
}

// dirOf is filepath.Dir for Windows paths on any build OS.
func dirOf(p string) string {
	i := strings.LastIndexAny(p, `\/`)
	switch {
	case i < 0:
		return "."
	case i == 2 && p[1] == ':' || i == 0:
		return p[:i+1]
	}
	return p[:i]
}
