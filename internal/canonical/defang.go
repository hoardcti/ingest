package canonical

import (
	"regexp"
	"strings"
)

// Defang reverses the conventional ways analysts and feeds neuter an indicator
// so that it cannot be clicked or auto-linked.
//
// Only unambiguous forms are reversed. Bracketed substitutions like [.] and
// [at] cannot occur in a legitimate observable, so undoing them is safe. Bare
// forms such as " dot " and " at " are deliberately left alone: they occur in
// real URL paths and query strings, and reversing them would corrupt good data
// in order to rescue bad.
func Defang(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "<>\"'`")
	if s == "" {
		return s
	}

	// Scheme obfuscation first, so "hxxps[://]" resolves whichever way the
	// feed spelled it.
	s = replaceSchemePrefix(s)

	if strings.ContainsAny(s, "[({\\") {
		for _, r := range defangRules {
			s = r.re.ReplaceAllString(s, r.with)
		}
	}
	return strings.TrimSpace(s)
}

// Ordered: "://" must be tried before ":" so the longer form is not eaten by
// the shorter one.
var defangRules = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`[\[({]\s*:\s*/\s*/\s*[\])}]`), "://"},
	{regexp.MustCompile(`(?i)[\[({]\s*(?:\.|dot|punto|point)\s*[\])}]`), "."},
	{regexp.MustCompile(`(?i)[\[({]\s*(?:@|at)\s*[\])}]`), "@"},
	{regexp.MustCompile(`[\[({]\s*:\s*[\])}]`), ":"},
	{regexp.MustCompile(`[\[({]\s*/{1,2}\s*[\])}]`), "/"},
	{regexp.MustCompile(`\\\.`), "."},
}

// schemeAliases maps defanged scheme spellings to the real thing. Matched
// case-insensitively against the start of the value only, so a path segment
// named "hxxp" is left alone.
var schemeAliases = []struct{ from, to string }{
	{"hxxps", "https"},
	{"hxtps", "https"},
	{"htxps", "https"},
	{"h**ps", "https"},
	{"hxxp", "http"},
	{"hxtp", "http"},
	{"htxp", "http"},
	{"h**p", "http"},
	{"fxp", "ftp"},
}

func replaceSchemePrefix(s string) string {
	for _, a := range schemeAliases {
		if len(s) < len(a.from) || !strings.EqualFold(s[:len(a.from)], a.from) {
			continue
		}
		// Only rewrite when what follows really is a scheme separator,
		// defanged or not.
		rest := s[len(a.from):]
		if strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "[:") ||
			strings.HasPrefix(rest, "(:") || strings.HasPrefix(rest, "{:") {
			return a.to + rest
		}
	}
	return s
}
