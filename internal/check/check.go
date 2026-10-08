package check

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Check is one path match loaded from JSON.
type Check struct {
	ID            string            `json:"id"`
	Path          string            `json:"path"`
	Method        string            `json:"method"`
	Statuses      []int             `json:"statuses"`
	Body          string            `json:"body"`
	Headers       map[string]string `json:"headers"`
	Message       string            `json:"message"`
	IgnoreSoft404 bool              `json:"ignoreSoft404,omitempty"`
	// Raw asks for Accept-Encoding: identity so magic-byte patterns see the file.
	Raw bool `json:"raw,omitempty"`

	bodyRe     *regexp.Regexp
	bodyPrefix []byte
	headerRe   map[string]*regexp.Regexp
}

// Finding is one reported result.
type Finding struct {
	ID      string `json:"id"`
	Target  string `json:"target"`
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// LoadDir reads every *.json file in dir. Each file is a JSON array of checks.
func LoadDir(dir string) ([]Check, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read checks: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var out []Check
	seen := map[string]string{}
	for _, name := range names {
		path := filepath.Join(dir, name)
		batch, err := loadFile(path)
		if err != nil {
			return nil, err
		}
		for _, c := range batch {
			if prev, ok := seen[c.ID]; ok {
				return nil, fmt.Errorf("duplicate check id %q in %s and %s", c.ID, prev, name)
			}
			seen[c.ID] = name
			out = append(out, c)
		}
	}
	return out, nil
}

func loadFile(path string) ([]Check, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw []json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s: trailing data", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := make([]Check, 0, len(raw))
	for _, msg := range raw {
		dec := json.NewDecoder(bytes.NewReader(msg))
		dec.DisallowUnknownFields()
		var c Check
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := c.compile(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func (c *Check) compile() error {
	if c.ID == "" {
		return fmt.Errorf("check missing id")
	}
	if c.Path == "" {
		return fmt.Errorf("check %s missing path", c.ID)
	}
	if c.Method == "" {
		c.Method = http.MethodGet
	}
	if c.Message == "" {
		return fmt.Errorf("check %s missing message", c.ID)
	}
	if c.Body != "" {
		// Go's regexp treats \x8b as U+008B, whose UTF-8 form is not the
		// gzip byte 0x8b. A pattern that is only ^\xHH escapes is matched
		// against the raw body bytes instead.
		if prefix, ok := rawHexPrefix(c.Body); ok {
			c.bodyPrefix = prefix
		} else {
			re, err := regexp.Compile(c.Body)
			if err != nil {
				return fmt.Errorf("check %s body: %w", c.ID, err)
			}
			c.bodyRe = re
		}
	}
	if len(c.Headers) > 0 {
		c.headerRe = make(map[string]*regexp.Regexp, len(c.Headers))
		for name, expr := range c.Headers {
			re, err := regexp.Compile(expr)
			if err != nil {
				return fmt.Errorf("check %s header %s: %w", c.ID, name, err)
			}
			c.headerRe[name] = re
		}
	}
	return nil
}

var passwordInput = regexp.MustCompile(`(?i)<input\b[^>]*\btype\s*=\s*["']?password\b`)

// loginPage is an HTML form that asks for a password.
func loginPage(body string) bool {
	return passwordInput.MatchString(body)
}

// sameBaseURL reports whether page is the site base, ignoring a trailing slash.
func sameBaseURL(page, base string) bool {
	return strings.TrimRight(page, "/") == strings.TrimRight(base, "/")
}

func fingerprint(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func (c Check) match(status int, body string, header http.Header, failed bool, soft string, softOK bool) bool {
	if failed {
		return false
	}
	if len(c.Statuses) > 0 && !statusListed(c.Statuses, status) {
		return false
	}
	if !c.IgnoreSoft404 && softOK && status == http.StatusOK && fingerprint(body) == soft {
		return false
	}
	if c.bodyPrefix != nil && !bytes.HasPrefix([]byte(body), c.bodyPrefix) {
		return false
	}
	if c.bodyRe != nil && !c.bodyRe.MatchString(body) {
		return false
	}
	for name, re := range c.headerRe {
		if !re.MatchString(joinedHeader(header, name)) {
			return false
		}
	}
	return true
}

// rawHexPrefix reports the raw bytes of a pattern shaped like ^\x1f\x8b.
func rawHexPrefix(expr string) ([]byte, bool) {
	if !strings.HasPrefix(expr, "^") {
		return nil, false
	}
	rest := expr[1:]
	if rest == "" {
		return nil, false
	}
	var out []byte
	for rest != "" {
		if !strings.HasPrefix(rest, `\x`) || len(rest) < 4 {
			return nil, false
		}
		b, err := hex.DecodeString(rest[2:4])
		if err != nil {
			return nil, false
		}
		out = append(out, b[0])
		rest = rest[4:]
	}
	return out, true
}

func statusListed(list []int, status int) bool {
	for _, s := range list {
		if s == status {
			return true
		}
	}
	return false
}

func joinedHeader(h http.Header, name string) string {
	if h == nil {
		return ""
	}
	return strings.Join(h.Values(name), ", ")
}
