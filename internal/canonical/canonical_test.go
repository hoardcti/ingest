package canonical

import (
	"errors"
	"testing"
	"time"

	"github.com/hoardcti/ingest/internal/envelope"
)

// The whole system's deduplication rests on these functions being
// deterministic, so the table is deliberately exhaustive about the ways feeds
// misbehave rather than the ways they behave.
func TestIndicator(t *testing.T) {
	tests := []struct {
		name     string
		typ      envelope.ObservableType
		in       string
		wantType envelope.ObservableType
		want     string
	}{
		// Defanging
		{"defanged domain", envelope.TypeAuto, "evil[.]com", envelope.TypeDomain, "evil.com"},
		{"defanged domain parens", envelope.TypeAuto, "evil(.)com", envelope.TypeDomain, "evil.com"},
		{"defanged domain word", envelope.TypeAuto, "evil[dot]com", envelope.TypeDomain, "evil.com"},
		{"defanged domain mixed case word", envelope.TypeAuto, "evil[DoT]com", envelope.TypeDomain, "evil.com"},
		{"escaped dot", envelope.TypeAuto, `evil\.com`, envelope.TypeDomain, "evil.com"},
		{"hxxp url", envelope.TypeAuto, "hxxp://evil[.]com/a", envelope.TypeURL, "http://evil.com/a"},
		{"hxxps url", envelope.TypeAuto, "hxxps://evil[.]com/a", envelope.TypeURL, "https://evil.com/a"},
		{"fully defanged url", envelope.TypeAuto, "hxxps[://]evil[.]com[/]a", envelope.TypeURL, "https://evil.com/a"},
		{"defanged ip", envelope.TypeAuto, "185[.]234[.]1[.]7", envelope.TypeIPv4, "185.234.1.7"},
		{"defanged email", envelope.TypeAuto, "bad[at]evil[.]com", envelope.TypeEmail, "bad@evil.com"},
		{"angle brackets stripped", envelope.TypeAuto, "<evil.com>", envelope.TypeDomain, "evil.com"},
		{"surrounding whitespace", envelope.TypeAuto, "  evil.com \n", envelope.TypeDomain, "evil.com"},

		// A path segment that happens to spell a defanged scheme must survive.
		{"hxxp in path is not a scheme", envelope.TypeURL, "http://evil.com/hxxp/x",
			envelope.TypeURL, "http://evil.com/hxxp/x"},

		// Addresses
		{"ipv4", envelope.TypeIPv4, "185.234.1.7", envelope.TypeIPv4, "185.234.1.7"},
		{"ipv6 uppercase compresses", envelope.TypeIPv6, "2001:0DB8:0000:0000:0000:0000:0000:0001",
			envelope.TypeIPv6, "2001:db8::1"},
		{"ipv4-mapped ipv6 unmaps", envelope.TypeAuto, "::ffff:185.234.1.7",
			envelope.TypeIPv4, "185.234.1.7"},
		{"ipv6 zone stripped", envelope.TypeAuto, "fe80::1%eth0", envelope.TypeIPv6, "fe80::1"},
		{"cidr host bits masked", envelope.TypeAuto, "10.1.2.3/8", envelope.TypeCIDR, "10.0.0.0/8"},
		{"cidr already masked", envelope.TypeCIDR, "192.168.0.0/16", envelope.TypeCIDR, "192.168.0.0/16"},

		// Domains
		{"uppercase lowered", envelope.TypeDomain, "EVIL.COM", envelope.TypeDomain, "evil.com"},
		{"trailing dot removed", envelope.TypeDomain, "evil.com.", envelope.TypeDomain, "evil.com"},
		{"punycode resolved", envelope.TypeDomain, "bücher.example", envelope.TypeDomain, "xn--bcher-kva.example"},
		{"already punycode", envelope.TypeDomain, "XN--BCHER-KVA.EXAMPLE", envelope.TypeDomain, "xn--bcher-kva.example"},
		{"port stripped from domain", envelope.TypeDomain, "evil.com:8080", envelope.TypeDomain, "evil.com"},
		{"path stripped from domain", envelope.TypeDomain, "evil.com/malware", envelope.TypeDomain, "evil.com"},
		{"scheme stripped from domain", envelope.TypeDomain, "https://evil.com/x", envelope.TypeDomain, "evil.com"},
		{"underscore label kept", envelope.TypeDomain, "_dmarc.evil.com", envelope.TypeDomain, "_dmarc.evil.com"},

		// URLs — the trailing-slash and default-port cases are the ones that
		// silently double an indicator if you get them wrong.
		{"bare host gets root path", envelope.TypeURL, "http://evil.com", envelope.TypeURL, "http://evil.com/"},
		{"root path preserved", envelope.TypeURL, "http://evil.com/", envelope.TypeURL, "http://evil.com/"},
		{"default http port dropped", envelope.TypeURL, "http://evil.com:80/a", envelope.TypeURL, "http://evil.com/a"},
		{"default https port dropped", envelope.TypeURL, "https://evil.com:443/a", envelope.TypeURL, "https://evil.com/a"},
		{"non-default port kept", envelope.TypeURL, "http://evil.com:8080/a", envelope.TypeURL, "http://evil.com:8080/a"},
		{"scheme lowered", envelope.TypeURL, "HTTP://EVIL.COM/A", envelope.TypeURL, "http://evil.com/A"},
		{"fragment dropped", envelope.TypeURL, "http://evil.com/a#frag", envelope.TypeURL, "http://evil.com/a"},
		{"query preserved", envelope.TypeURL, "http://evil.com/a?b=1&c=2", envelope.TypeURL, "http://evil.com/a?b=1&c=2"},
		{"dot segments resolved", envelope.TypeURL, "http://evil.com/a/./b/../c", envelope.TypeURL, "http://evil.com/a/c"},
		{"deep trailing slash kept", envelope.TypeURL, "http://evil.com/a/", envelope.TypeURL, "http://evil.com/a/"},
		{"schemeless url assumes http", envelope.TypeURL, "evil.com/a", envelope.TypeURL, "http://evil.com/a"},
		{"idn host in url", envelope.TypeURL, "http://bücher.example/a", envelope.TypeURL, "http://xn--bcher-kva.example/a"},
		{"ipv6 literal keeps brackets", envelope.TypeURL, "http://[2001:0db8::1]/a", envelope.TypeURL, "http://[2001:db8::1]/a"},

		// Email
		{"email lowercased", envelope.TypeEmail, "Bad.Actor@EVIL.COM", envelope.TypeEmail, "bad.actor@evil.com"},
		{"email idn domain", envelope.TypeEmail, "a@bücher.example", envelope.TypeEmail, "a@xn--bcher-kva.example"},
		{"email plus address preserved", envelope.TypeEmail, "a+b@evil.com", envelope.TypeEmail, "a+b@evil.com"},

		// Hashes
		{"md5 lowered", envelope.TypeMD5, "D41D8CD98F00B204E9800998ECF8427E",
			envelope.TypeMD5, "d41d8cd98f00b204e9800998ecf8427e"},
		{"md5 inferred", envelope.TypeAuto, "d41d8cd98f00b204e9800998ecf8427e",
			envelope.TypeMD5, "d41d8cd98f00b204e9800998ecf8427e"},
		{"sha1 inferred", envelope.TypeAuto, "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			envelope.TypeSHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"sha256 inferred", envelope.TypeAuto,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			envelope.TypeSHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"algorithm prefix stripped", envelope.TypeSHA256,
			"sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			envelope.TypeSHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Indicator(tt.typ, tt.in)
			if err != nil {
				t.Fatalf("Indicator(%q, %q) = error %v", tt.typ, tt.in, err)
			}
			if got.Value != tt.want {
				t.Errorf("value = %q, want %q", got.Value, tt.want)
			}
			if got.Type != tt.wantType {
				t.Errorf("type = %q, want %q", got.Type, tt.wantType)
			}
		})
	}
}

// Canonicalisation is only useful if genuinely different spellings converge.
func TestIndicatorConverges(t *testing.T) {
	// Each group is one indicator spelled several ways. A URL and a bare
	// domain are deliberately *not* in the same group: they are different
	// observables, and TestIndicatorDoesNotOverMerge asserts they stay apart.
	groups := [][]string{
		{"evil[.]com", "EVIL.COM", "evil.com.", "<evil.com>", `evil\.com`},
		{"185.234.1.7", "185[.]234[.]1[.]7", "::ffff:185.234.1.7"},
		{"http://evil.com", "http://evil.com/", "http://EVIL.com:80/", "hxxp://evil[.]com/"},
		{"https://evil.com/", "https://EVIL.com:443/", "hxxps://evil[.]com"},
		{"D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"},
	}

	for i, group := range groups {
		var want string
		for j, in := range group {
			obs, err := Indicator(envelope.TypeAuto, in)
			if err != nil {
				t.Fatalf("group %d: Indicator(%q) = error %v", i, in, err)
			}
			if j == 0 {
				want = obs.Value
				continue
			}
			if obs.Value != want {
				t.Errorf("group %d: %q canonicalised to %q, but %q gave %q — "+
					"these would become two entities",
					i, in, obs.Value, group[0], want)
			}
		}
	}
}

// Different indicators must not collide. A canonicaliser that is too eager is
// worse than one that is too shy: a collision silently merges two entities.
func TestIndicatorDoesNotOverMerge(t *testing.T) {
	pairs := [][2]string{
		{"http://evil.com/a", "http://evil.com/a/"},
		{"http://evil.com/a", "https://evil.com/a"},
		{"http://evil.com:8080/a", "http://evil.com/a"},
		{"http://evil.com/a?b=1", "http://evil.com/a?b=2"},
		{"evil.com", "www.evil.com"},
		{"10.0.0.0/8", "10.0.0.0/16"},
	}

	for _, p := range pairs {
		a, err := Indicator(envelope.TypeAuto, p[0])
		if err != nil {
			t.Fatalf("Indicator(%q) = error %v", p[0], err)
		}
		b, err := Indicator(envelope.TypeAuto, p[1])
		if err != nil {
			t.Fatalf("Indicator(%q) = error %v", p[1], err)
		}
		if a.Value == b.Value {
			t.Errorf("%q and %q both canonicalised to %q — distinct indicators merged",
				p[0], p[1], a.Value)
		}
	}
}

func TestIndicatorErrors(t *testing.T) {
	tests := []struct {
		name string
		typ  envelope.ObservableType
		in   string
	}{
		{"empty", envelope.TypeAuto, ""},
		{"whitespace only", envelope.TypeAuto, "   "},
		{"single label domain", envelope.TypeDomain, "localhost"},
		{"ip declared as domain", envelope.TypeDomain, "185.234.1.7"},
		{"ipv6 declared as ipv4", envelope.TypeIPv4, "2001:db8::1"},
		{"ipv4 declared as ipv6", envelope.TypeIPv6, "185.234.1.7"},
		{"not an ip", envelope.TypeIPv4, "999.999.999.999"},
		{"md5 wrong length", envelope.TypeMD5, "d41d8cd98f00b204e9800998ecf8427"},
		{"md5 not hex", envelope.TypeMD5, "z41d8cd98f00b204e9800998ecf8427e"},
		{"email with no domain", envelope.TypeEmail, "nobody@"},
		{"email with no local part", envelope.TypeEmail, "@evil.com"},
		{"uninferable", envelope.TypeAuto, "just some words"},
		{"label too long", envelope.TypeDomain,
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Indicator(tt.typ, tt.in)
			if err == nil {
				t.Fatalf("Indicator(%q, %q) = %q, want an error", tt.typ, tt.in, got.Value)
			}
		})
	}
}

func TestInferTypeUnknown(t *testing.T) {
	_, err := InferType("this is not an indicator")
	if !errors.Is(err, ErrUnknownType) {
		t.Fatalf("InferType error = %v, want ErrUnknownType", err)
	}
}

func TestCVEID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"CVE-2024-3094", "CVE-2024-3094"},
		{"cve-2024-3094", "CVE-2024-3094"},
		{"  CVE-2024-3094  ", "CVE-2024-3094"},
		{"CVE-2024-0003094", "CVE-2024-3094"}, // zero padding stripped
		{"CVE-2021-44228", "CVE-2021-44228"},  // five digits, unpadded
		{"CVE-2024-0001", "CVE-2024-0001"},    // minimum width preserved
	}
	for _, tt := range tests {
		got, err := CVEID(tt.in)
		if err != nil {
			t.Fatalf("CVEID(%q) = error %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("CVEID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	for _, bad := range []string{"", "CVE", "CVE-24-3094", "CVE-2024-309", "not a cve", "2024-3094"} {
		if _, err := CVEID(bad); err == nil {
			t.Errorf("CVEID(%q) succeeded, want an error", bad)
		}
	}
}

func TestBreachSlug(t *testing.T) {
	d := func(s string) *envelope.Date {
		t2, err := time.Parse("2006-01-02", s)
		if err != nil {
			panic(err)
		}
		return &envelope.Date{Time: t2}
	}

	tests := []struct {
		name string
		in   envelope.Breach
		want string
	}{
		{"explicit slug wins", envelope.Breach{Slug: "LinkedIn-2021", Name: "LinkedIn"}, "linkedin-2021"},
		{"name and breach year", envelope.Breach{Name: "LinkedIn", BreachDate: d("2021-06-01")}, "linkedin-2021"},
		{"punctuation collapsed", envelope.Breach{Name: "Adobe, Inc.", BreachDate: d("2013-10-04")}, "adobe-inc-2013"},
		{"accents folded", envelope.Breach{Name: "Café Móvil", BreachDate: d("2019-01-01")}, "cafe-movil-2019"},
		{"no date", envelope.Breach{Name: "Some Company"}, "some-company"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BreachSlug(&tt.in)
			if err != nil {
				t.Fatalf("BreachSlug = error %v", err)
			}
			if got != tt.want {
				t.Errorf("BreachSlug = %q, want %q", got, tt.want)
			}
		})
	}

	if _, err := BreachSlug(&envelope.Breach{Name: "!!!"}); err == nil {
		t.Error("BreachSlug of an unslugifiable name succeeded, want an error")
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		in       envelope.Endpoint
		wantKind envelope.Kind
		wantKey  string
	}{
		{envelope.Endpoint{Kind: envelope.KindIndicator, Value: "EVIL[.]com"},
			envelope.KindIndicator, "evil.com"},
		{envelope.Endpoint{Kind: envelope.KindIndicator, Type: envelope.TypeDomain, Value: "evil.com."},
			envelope.KindIndicator, "evil.com"},
		{envelope.Endpoint{Kind: envelope.KindCVE, Value: "cve-2024-3094"},
			envelope.KindCVE, "CVE-2024-3094"},
		{envelope.Endpoint{Kind: envelope.KindBreach, Value: "LinkedIn 2021"},
			envelope.KindBreach, "linkedin-2021"},
	}

	for _, tt := range tests {
		kind, key, _, err := Key(tt.in)
		if err != nil {
			t.Fatalf("Key(%+v) = error %v", tt.in, err)
		}
		if kind != tt.wantKind || key != tt.wantKey {
			t.Errorf("Key(%+v) = (%q, %q), want (%q, %q)",
				tt.in, kind, key, tt.wantKind, tt.wantKey)
		}
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct{ in, want string }{
		{"LinkedIn", "linkedin"},
		{"  Hello   World  ", "hello-world"},
		{"a---b", "a-b"},
		{"---", ""},
		{"Acme Corp. (UK) Ltd", "acme-corp-uk-ltd"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := Slugify(tt.in); got != tt.want {
			t.Errorf("Slugify(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Canonicalisation must be idempotent: feeding a canonical value back through
// has to be a no-op, or a reprocessing run would rewrite every entity.
func TestIndicatorIsIdempotent(t *testing.T) {
	inputs := []string{
		"evil[.]com", "hxxps://EVIL.com:443/a/./b", "::ffff:185.234.1.7",
		"Bad@EVIL.com", "D41D8CD98F00B204E9800998ECF8427E", "10.1.2.3/8",
		"bücher.example",
	}
	for _, in := range inputs {
		first, err := Indicator(envelope.TypeAuto, in)
		if err != nil {
			t.Fatalf("Indicator(%q) = error %v", in, err)
		}
		second, err := Indicator(first.Type, first.Value)
		if err != nil {
			t.Fatalf("re-canonicalising %q = error %v", first.Value, err)
		}
		if second.Value != first.Value {
			t.Errorf("not idempotent: %q → %q → %q", in, first.Value, second.Value)
		}
	}
}
