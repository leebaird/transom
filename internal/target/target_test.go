package target

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		port     int
		scheme   string
		root     string
		discover bool
	}{
		{"example.com", "example.com", 0, "", "/", true},
		{"example.com:8443", "example.com", 8443, "", "/", false},
		{"https://example.com/app", "example.com", 443, "https", "/app", false},
		{"https://example.com:8443/app/", "example.com", 8443, "https", "/app", false},
		{"http://example.com", "example.com", 80, "http", "/", false},
		{"[2001:db8::1]", "2001:db8::1", 0, "", "/", true},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443, "", "/", false},
		{"https://[2001:db8::1]:8443/app", "2001:db8::1", 8443, "https", "/app", false},
	}
	for _, tc := range cases {
		got, err := Parse(tc.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.in, err)
		}
		if got.Host != tc.host || got.Port != tc.port || got.Scheme != tc.scheme || got.Root != tc.root || got.Discover != tc.discover {
			t.Fatalf("Parse(%q) = %+v", tc.in, got)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "ftp://example.com", "example.com:foo", "host:1:2", "example.com:0", "http://example.com/my%20app", "http://example.com/a%0d%0aB"} {
		if _, err := Parse(in); err == nil {
			t.Fatalf("Parse(%q) succeeded", in)
		}
	}
}

func TestJoin(t *testing.T) {
	app, err := Parse("https://example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	if got := app.Join("/health"); got != "/app/health" {
		t.Fatalf("join health: %s", got)
	}
	if got := app.Join("/app/health"); got != "/app/health" {
		t.Fatalf("join already rooted: %s", got)
	}
	root, err := Parse("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := root.Join("/health"); got != "/health" {
		t.Fatalf("join at /: %s", got)
	}
	if got := app.Join("/?=abc"); got != "/app/?=abc" {
		t.Fatalf("join query: %s", got)
	}
}

func TestRequestURIEncodes(t *testing.T) {
	app, err := Parse("https://example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	got, err := app.RequestURI("/my file")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/my%20file" {
		t.Fatalf("%s", got)
	}
	if _, err := app.RequestURI("/?\r\nX: y"); err == nil {
		t.Fatal("query line break was accepted")
	}
}

func TestRequestHost(t *testing.T) {
	def, err := Parse("https://example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	if got := def.RequestHost(); got != "example.com" {
		t.Fatalf("default https host: %s", got)
	}
	alt, err := Parse("https://example.com:8443/app")
	if err != nil {
		t.Fatal(err)
	}
	if got := alt.RequestHost(); got != "example.com:8443" {
		t.Fatalf("alt host: %s", got)
	}
	v6, err := Parse("http://[2001:db8::1]:8080/")
	if err != nil {
		t.Fatal(err)
	}
	if got := v6.RequestHost(); got != "[2001:db8::1]:8080" {
		t.Fatalf("v6 host: %s", got)
	}
}
