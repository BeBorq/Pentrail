// Package hooks embeds the shell-integration snippets so pentrail ships as one
// self-contained binary with no external files to install.
package hooks

import _ "embed"

//go:embed bash.sh
var Bash string

//go:embed zsh.sh
var Zsh string

//go:embed powershell.ps1
var PowerShell string

// For a given shell basename, return the matching hook (and whether we have one).
func For(shell string) (string, bool) {
	switch shell {
	case "bash":
		return Bash, true
	case "powershell", "pwsh", "powershell.exe", "pwsh.exe":
		return PowerShell, true
	case "zsh":
		return Zsh, true
	default:
		return "", false
	}
}
