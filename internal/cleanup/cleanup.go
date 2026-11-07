// Package cleanup is the accountability layer: it scans the commands the
// OPERATOR ran and flags the ones that changed state on the target, so that at
// the end of an engagement they have a checklist of things to undo and can
// answer the client's SOC ("yes, that was us at 14:32"). It is purely
// defensive bookkeeping over commands already captured — no offensive logic.
package cleanup

import "regexp"

// Category groups a change by what kind of teardown it needs.
type Category string

const (
	CatFile    Category = "file"    // wrote/created/copied a file on the target
	CatConfig  Category = "config"  // edited configuration or permissions
	CatAccount Category = "account" // created or changed an account
	CatService Category = "service" // started/enabled a service or scheduled task
)

// Hit is one change detected in a command, with a human description for the
// cleanup checklist.
type Hit struct {
	Category Category
	Desc     string
}

type rule struct {
	cat  Category
	desc string
	re   *regexp.Regexp
}

// Rules are intentionally simple and reviewable. This is a review aid, not an
// authority: a pentester confirms each item. False positives are acceptable;
// missing a state change is worse, so rules lean inclusive.
var rules = []rule{
	// --- files written / copied onto the target ---
	{CatFile, "write to a file (redirection >)", regexp.MustCompile(`>>?\s*(?:/|~|\./)?[\w./~-]+`)},
	{CatFile, "write to a file (tee)", regexp.MustCompile(`\btee\b`)},
	{CatFile, "file copy (cp/mv/rsync)", regexp.MustCompile(`\b(?:cp|mv|rsync)\b`)},
	{CatFile, "file transfer (scp/sftp)", regexp.MustCompile(`\b(?:scp|sftp)\b`)},
	{CatFile, "download to a file (wget / curl -o)", regexp.MustCompile(`\bwget\b|\bcurl\b[^\n]*\s-[oO]\b`)},
	{CatFile, "file/directory created (touch/mkdir)", regexp.MustCompile(`\b(?:touch|mkdir)\b`)},

	// --- configuration / permissions changed ---
	{CatConfig, "in-place edit (sed -i)", regexp.MustCompile(`\bsed\b[^\n]*\s-i\b`)},
	{CatConfig, "write to /etc", regexp.MustCompile(`>>?\s*/etc/`)},
	{CatConfig, "permission/owner change (chmod/chown)", regexp.MustCompile(`\b(?:chmod|chown)\b`)},

	// --- accounts --- (anchored so "/etc/passwd" as a path is not a hit)
	{CatAccount, "account operation (useradd/adduser/usermod/passwd)", regexp.MustCompile(`(?:^|[\s;&|(])(?:useradd|adduser|usermod|groupadd|passwd)\b`)},
	{CatAccount, "account operation (net user)", regexp.MustCompile(`(?:^|[\s;&|(])net\s+user\b`)},

	// --- services / scheduled tasks ---
	{CatService, "service (systemctl/service)", regexp.MustCompile(`\b(?:systemctl|service)\b`)},
	{CatService, "scheduled task (crontab/at)", regexp.MustCompile(`\bcrontab\b|\bat\s+\d`)},
}

// ignore drops redirections to places that are not a real change.
var ignore = regexp.MustCompile(`>>?\s*/dev/(?:null|stdout|stderr)`)

// Detect returns the de-duplicated (by category) changes a command represents.
func Detect(command string) []Hit {
	if command == "" {
		return nil
	}
	clean := ignore.ReplaceAllString(command, "")
	seen := map[Category]bool{}
	var hits []Hit
	for _, r := range rules {
		if seen[r.cat] {
			continue
		}
		if r.re.MatchString(clean) {
			seen[r.cat] = true
			hits = append(hits, Hit{Category: r.cat, Desc: r.desc})
		}
	}
	return hits
}
