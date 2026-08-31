// Package canonical turns what a feed said into the one normalised form the
// database stores.
//
// This package is the reason the ingest service exists as a single process.
// UNIQUE (kind, canonical_key) is the deduplication guarantee for the whole
// system, and it only holds if canonicalisation is deterministic and happens in
// exactly one place. If a Go collector, a Python collector and a Node collector
// each implemented their own defanging and hash normalisation, they would
// produce three subtly different answers, the unique constraint would quietly
// stop deduplicating, and nobody would notice for months.
//
// So: never at query time, never in a scraper, never twice. Here.
package canonical

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"

	"github.com/hoardcti/ingest/internal/envelope"
)

// ErrUnknownType is returned when type inference cannot classify a value.
var ErrUnknownType = errors.New("cannot infer observable type")

// Limits from the DNS specification, enforced so a malformed feed cannot plant
// a 4 KB "domain" in the index.
const (
	maxDomainLen = 253
	maxLabelLen  = 63
)

// Observable is a canonicalised indicator: the resolved type, and the value in
// the single form the database stores.
type Observable struct {
	Type  envelope.ObservableType
	Value string
}

// idnaProfile deliberately relaxes StrictDomainName. Threat feeds carry
// hostnames with underscores (DNS service records, malware C2 conventions) that
// a strict profile rejects outright, and dropping them would lose real
// indicators. Case folding, NFC normalisation and punycode conversion — the
// parts that actually affect deduplication — are kept.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(false),
	idna.Transitional(false),
)

var (
	schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	cveRe    = regexp.MustCompile(`^CVE-([0-9]{4})-([0-9]{4,})$`)
	slugRe   = regexp.MustCompile(`[^a-z0-9]+`)
)

// hashLengths maps hex digest length to the algorithm that produces it.
var hashLengths = map[int]envelope.ObservableType{
	32:  envelope.TypeMD5,
	40:  envelope.TypeSHA1,
	64:  envelope.TypeSHA256,
	128: envelope.TypeSHA512,
}

// defaultPorts are stripped from canonical URLs so that http://evil.com:80/ and
// http://evil.com/ deduplicate.
var defaultPorts = map[string]string{
	"http":  "80",
	"https": "443",
	"ftp":   "21",
	"ssh":   "22",
}

// Indicator canonicalises one observable.
//
// Pass [envelope.TypeAuto] to have the type inferred, for feeds that ship mixed
// IOC lists with no type column. Passing an explicit type is stricter: a value
// declared ipv4 that does not parse as an IPv4 address is an error rather than
// something quietly reclassified as a domain, because a feed mislabelling its
// own columns is worth knowing about.
func Indicator(t envelope.ObservableType, raw string) (Observable, error) {
	v := Defang(raw)
	if v == "" {
		return Observable{}, errors.New("empty value after defanging")
	}

	if t == "" || t == envelope.TypeAuto {
		inferred, err := InferType(v)
		if err != nil {
			return Observable{}, err
		}
		t = inferred
	}

	switch t {
	case envelope.TypeIPv4:
		return canonIP(v, 4)
	case envelope.TypeIPv6:
		return canonIP(v, 6)
	case envelope.TypeCIDR:
		return canonCIDR(v)
	case envelope.TypeDomain:
		return canonDomain(v)
	case envelope.TypeURL:
		return canonURL(v)
	case envelope.TypeEmail:
		return canonEmail(v)
	case envelope.TypeMD5, envelope.TypeSHA1, envelope.TypeSHA256, envelope.TypeSHA512:
		return canonHash(t, v)
	default:
		return Observable{}, fmt.Errorf("unsupported observable type %q", t)
	}
}

// InferType classifies an already-defanged value.
//
// Order matters. Hashes are checked first because they are unambiguous;
// addresses before domains because 1.2.3.4 satisfies both readings; and a bare
// host with a path is treated as a URL rather than a domain with junk on the
// end.
func InferType(v string) (envelope.ObservableType, error) {
	if t, ok := hashLengths[len(v)]; ok && hexRe.MatchString(v) {
		return t, nil
	}
	if schemeRe.MatchString(v) {
		return envelope.TypeURL, nil
	}
	if addr, err := netip.ParseAddr(stripZone(v)); err == nil {
		if addr.Unmap().Is4() {
			return envelope.TypeIPv4, nil
		}
		return envelope.TypeIPv6, nil
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return envelope.TypeCIDR, nil
	}
	if strings.Contains(v, "@") {
		return envelope.TypeEmail, nil
	}
	if strings.Contains(v, "/") {
		return envelope.TypeURL, nil
	}
	if looksLikeDomain(v) {
		return envelope.TypeDomain, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownType, truncate(v, 80))
}

func canonIP(v string, want int) (Observable, error) {
	addr, err := netip.ParseAddr(stripZone(v))
	if err != nil {
		return Observable{}, fmt.Errorf("parse IP %q: %w", truncate(v, 80), err)
	}
	// An IPv4-mapped IPv6 address (::ffff:1.2.3.4) is the same host as 1.2.3.4
	// and must not produce a second entity.
	addr = addr.Unmap()

	got := 6
	if addr.Is4() {
		got = 4
	}
	if got != want {
		return Observable{}, fmt.Errorf("value %q is IPv%d but was declared IPv%d",
			truncate(v, 80), got, want)
	}
	// netip's String is the canonical form: lowercase, RFC 5952 compression.
	t := envelope.TypeIPv4
	if got == 6 {
		t = envelope.TypeIPv6
	}
	return Observable{Type: t, Value: addr.String()}, nil
}

func canonCIDR(v string) (Observable, error) {
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return Observable{}, fmt.Errorf("parse CIDR %q: %w", truncate(v, 80), err)
	}
	// Masked() zeroes the host bits, so 10.0.0.7/8 and 10.0.0.0/8 are one
	// entity rather than two names for the same range.
	return Observable{Type: envelope.TypeCIDR, Value: p.Masked().String()}, nil
}

func canonDomain(v string) (Observable, error) {
	// Feeds are sloppy about the difference between a domain and a URL. Take
	// the host out of whatever we were given rather than rejecting it.
	if schemeRe.MatchString(v) {
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			v = u.Host
		}
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if i := strings.LastIndex(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	v = strings.TrimSuffix(v, ".")
	if h, _, err := splitHostPort(v); err == nil {
		v = h
	}
	if v == "" {
		return Observable{}, errors.New("empty domain")
	}

	host, err := normaliseHost(v)
	if err != nil {
		return Observable{}, err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return Observable{}, fmt.Errorf("value %q is an IP address, not a domain", host)
	}
	if err := validateDomain(host); err != nil {
		return Observable{}, err
	}
	return Observable{Type: envelope.TypeDomain, Value: host}, nil
}

func canonURL(v string) (Observable, error) {
	if !schemeRe.MatchString(v) {
		// A bare host-and-path. Feeds emit these constantly; assume http,
		// which is also what every browser and every other CTI tool assumes.
		v = "http://" + v
	}

	u, err := url.Parse(v)
	if err != nil {
		return Observable{}, fmt.Errorf("parse URL %q: %w", truncate(v, 120), err)
	}
	if u.Host == "" {
		return Observable{}, fmt.Errorf("URL %q has no host", truncate(v, 120))
	}

	scheme := strings.ToLower(u.Scheme)

	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return Observable{}, err
	}
	host, err = normaliseHost(host)
	if err != nil {
		return Observable{}, err
	}
	if strings.Contains(host, ":") { // IPv6 literal needs its brackets back
		host = "[" + host + "]"
	}
	// A port that is the default for the scheme carries no information and
	// only splits the entity in two.
	if port != "" && defaultPorts[scheme] == port {
		port = ""
	}

	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	if u.User != nil {
		b.WriteString(u.User.String())
		b.WriteByte('@')
	}
	b.WriteString(host)
	if port != "" {
		b.WriteByte(':')
		b.WriteString(port)
	}
	b.WriteString(cleanURLPath(u.EscapedPath()))
	if u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}
	// The fragment is client-side only and never reaches the server, so it
	// cannot distinguish two indicators. Dropped.
	return Observable{Type: envelope.TypeURL, Value: b.String()}, nil
}

func canonEmail(v string) (Observable, error) {
	i := strings.LastIndex(v, "@")
	if i <= 0 || i == len(v)-1 {
		return Observable{}, fmt.Errorf("value %q is not an email address", truncate(v, 120))
	}
	local, domain := v[:i], v[i+1:]

	host, err := normaliseHost(strings.TrimSuffix(domain, "."))
	if err != nil {
		return Observable{}, err
	}
	if err := validateDomain(host); err != nil {
		return Observable{}, fmt.Errorf("email domain: %w", err)
	}
	// The local part is case-sensitive per RFC 5321, but no mail provider in
	// practice treats it that way, and two feeds reporting the same address
	// with different casing must not become two entities. Lowercased, with the
	// original preserved in indicator.raw_value.
	return Observable{
		Type:  envelope.TypeEmail,
		Value: strings.ToLower(local) + "@" + host,
	}, nil
}

func canonHash(t envelope.ObservableType, v string) (Observable, error) {
	v = strings.TrimSpace(v)
	// Some feeds prefix the algorithm: "sha256:abc…".
	if i := strings.Index(v, ":"); i >= 0 && strings.EqualFold(v[:i], string(t)) {
		v = v[i+1:]
	}
	if !hexRe.MatchString(v) {
		return Observable{}, fmt.Errorf("%s value %q is not hexadecimal", t, truncate(v, 80))
	}
	want := 0
	for n, ht := range hashLengths {
		if ht == t {
			want = n
		}
	}
	if len(v) != want {
		return Observable{}, fmt.Errorf("%s must be %d hex characters, got %d", t, want, len(v))
	}
	return Observable{Type: t, Value: strings.ToLower(v)}, nil
}

// CVEID canonicalises a CVE identifier to the uppercase form as issued.
func CVEID(raw string) (string, error) {
	v := strings.ToUpper(strings.TrimSpace(raw))
	m := cveRe.FindStringSubmatch(v)
	if m == nil {
		return "", fmt.Errorf("%q is not a CVE identifier", truncate(raw, 80))
	}
	// The sequence number is not zero-padded to a fixed width by MITRE, but
	// feeds sometimes pad it anyway. Strip leading zeroes so CVE-2024-0003094
	// and CVE-2024-3094 are one entity. Four digits is the minimum width.
	seq := strings.TrimLeft(m[2], "0")
	if seq == "" {
		seq = "0"
	}
	for len(seq) < 4 {
		seq = "0" + seq
	}
	return "CVE-" + m[1] + "-" + seq, nil
}

// BreachSlug derives the canonical key for a breach.
//
// An explicit slug from the feed wins; otherwise it is built from the name plus
// the year of the breach, which is how these are referred to in practice
// ("linkedin-2021"). Two breaches at the same company in different years stay
// distinct; two feeds reporting the same breach converge.
func BreachSlug(b *envelope.Breach) (string, error) {
	if s := Slugify(b.Slug); s != "" {
		return s, nil
	}
	base := Slugify(b.Name)
	if base == "" {
		return "", errors.New("breach has neither slug nor a name that slugifies")
	}
	switch {
	case b.BreachDate != nil && !b.BreachDate.IsZero():
		return base + "-" + strconv.Itoa(b.BreachDate.Year()), nil
	case b.DisclosedAt != nil && !b.DisclosedAt.IsZero():
		return base + "-" + strconv.Itoa(b.DisclosedAt.Year()), nil
	default:
		return base, nil
	}
}

// Slugify reduces a string to lowercase alphanumerics joined by hyphens.
func Slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Map(func(r rune) rune {
		if r > unicode.MaxASCII {
			// Fold what we can; drop the rest rather than emitting mojibake
			// into a primary key.
			if f, ok := asciiFold[r]; ok {
				return f
			}
			return -1
		}
		return r
	}, s)
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 200 {
		s = strings.Trim(s[:200], "-")
	}
	return s
}

// asciiFold covers the accented Latin letters that turn up in breached company
// names. Anything outside it is dropped.
var asciiFold = map[rune]rune{
	'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a',
	'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
	'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
	'ó': 'o', 'ò': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o', 'ø': 'o',
	'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
	'ñ': 'n', 'ç': 'c', 'ý': 'y', 'ÿ': 'y', 'ß': 's',
}

// Key canonicalises a relationship endpoint into the (kind, canonical_key) pair
// the entity table is keyed by, plus the resolved observable type when the
// endpoint is an indicator.
//
// The type is returned because an endpoint gets a module row of its own: an
// indicator a feed says exploits Log4Shell has to be findable by its value, and
// indicator.type is NOT NULL.
func Key(e envelope.Endpoint) (envelope.Kind, string, envelope.ObservableType, error) {
	switch e.Kind {
	case envelope.KindIndicator:
		obs, err := Indicator(e.Type, e.Value)
		if err != nil {
			return "", "", "", err
		}
		return envelope.KindIndicator, obs.Value, obs.Type, nil
	case envelope.KindCVE:
		id, err := CVEID(e.Value)
		if err != nil {
			return "", "", "", err
		}
		return envelope.KindCVE, id, "", nil
	case envelope.KindBreach:
		s := Slugify(e.Value)
		if s == "" {
			return "", "", "", fmt.Errorf("breach reference %q does not slugify", truncate(e.Value, 80))
		}
		return envelope.KindBreach, s, "", nil
	default:
		return "", "", "", fmt.Errorf("unknown kind %q", e.Kind)
	}
}

// --- helpers ---

// normaliseHost lowercases and punycodes a hostname, leaving IP literals alone.
func normaliseHost(h string) (string, error) {
	h = strings.Trim(h, "[]")
	if addr, err := netip.ParseAddr(stripZone(h)); err == nil {
		return addr.Unmap().String(), nil
	}
	ascii, err := idnaProfile.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("normalise host %q: %w", truncate(h, 80), err)
	}
	return strings.ToLower(ascii), nil
}

func validateDomain(h string) error {
	if h == "" {
		return errors.New("empty domain")
	}
	if len(h) > maxDomainLen {
		return fmt.Errorf("domain is %d bytes, over the %d byte limit", len(h), maxDomainLen)
	}
	if !strings.Contains(h, ".") {
		// A single label is a host on someone's LAN, not an internet
		// indicator, and is far more often a parsing accident.
		return fmt.Errorf("domain %q has no dot", truncate(h, 80))
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" {
			return fmt.Errorf("domain %q has an empty label", truncate(h, 80))
		}
		if len(label) > maxLabelLen {
			return fmt.Errorf("domain label %q is over %d bytes", truncate(label, 20), maxLabelLen)
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
				continue
			}
			return fmt.Errorf("domain %q contains %q", truncate(h, 80), r)
		}
	}
	return nil
}

func looksLikeDomain(v string) bool {
	if !strings.Contains(v, ".") || strings.ContainsAny(v, " \t/?#@:") {
		return false
	}
	_, err := canonDomain(v)
	return err == nil
}

// splitHostPort splits an authority into host and port. Unlike net.SplitHostPort
// it accepts an authority with no port at all, which is the common case.
func splitHostPort(authority string) (host, port string, err error) {
	if strings.HasPrefix(authority, "[") {
		end := strings.LastIndex(authority, "]")
		if end < 0 {
			return "", "", fmt.Errorf("unterminated IPv6 literal in %q", truncate(authority, 80))
		}
		host = authority[1:end]
		rest := authority[end+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return host, port, nil
	}
	i := strings.LastIndex(authority, ":")
	if i < 0 {
		return authority, "", nil
	}
	// A bare IPv6 address has many colons and no port.
	if strings.Count(authority, ":") > 1 {
		return authority, "", nil
	}
	maybePort := authority[i+1:]
	if maybePort != "" {
		if _, convErr := strconv.Atoi(maybePort); convErr != nil {
			return authority, "", nil
		}
	}
	return authority[:i], maybePort, nil
}

// stripZone removes an IPv6 zone identifier (fe80::1%eth0). A zone is local to
// one machine and cannot be part of a shared indicator's identity.
func stripZone(s string) string {
	if i := strings.Index(s, "%"); i >= 0 {
		return s[:i]
	}
	return s
}

// cleanURLPath resolves . and .. segments and guarantees a leading slash, while
// preserving a meaningful trailing slash. An empty path becomes "/" so that
// http://evil.com and http://evil.com/ are one indicator.
func cleanURLPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	trailing := strings.HasSuffix(p, "/")
	c := path.Clean(p)
	if !strings.HasPrefix(c, "/") {
		c = "/" + c
	}
	if trailing && c != "/" {
		c += "/"
	}
	return c
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
