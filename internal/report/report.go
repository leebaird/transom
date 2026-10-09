// Package report writes text findings and atomic JSON or HTML documents.
package report

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leebaird/transom/internal/check"
)

// Target is one scanned origin in the JSON report.
type Target struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
	Root   string `json:"root"`
}

// Document is the JSON report.
type Document struct {
	Command     string          `json:"command,omitempty"`
	Started     time.Time       `json:"started"`
	Finished    time.Time       `json:"finished"`
	Interrupted bool            `json:"interrupted,omitempty"`
	Targets     []Target        `json:"targets"`
	Findings    []check.Finding `json:"findings"`
}

// WriteText prints one finding per line.
func WriteText(w io.Writer, findings []check.Finding) error {
	for _, f := range findings {
		msg := strings.ReplaceAll(f.Message, "\n", " ")
		if _, err := fmt.Fprintf(w, "%s  %s  %s\n", f.URL, f.ID, msg); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON writes doc to path by creating a sibling temp file and renaming it.
func WriteJSON(path string, doc Document) error {
	doc = normalize(doc)
	return writeAtomic(path, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(doc)
	})
}

func normalize(doc Document) Document {
	if doc.Targets == nil {
		doc.Targets = []Target{}
	}
	if doc.Findings == nil {
		doc.Findings = []check.Finding{}
	}
	return doc
}

// staleAfter is the age at which a temp file counts as abandoned. Writing a
// report takes well under a second, so an older one belongs to a run that
// was killed partway.
const staleAfter = time.Minute

// writeAtomic writes a sibling temp file and renames it over path. The temp
// name is random and created with O_EXCL, so two runs writing the same report
// do not share it and a link left at that name is not followed.
// os.CreateTemp would do the same but leave the report at mode 0600.
func writeAtomic(path string, write func(io.Writer) error) error {
	removeStale(path)
	tmp := path + "." + rand.Text() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) //nolint:gosec // G302: a report is an ordinary output file, left to the umask
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// removeStale deletes the temp files killed runs left beside path. Failing
// to is not an error: the report can still be written.
func removeStale(path string) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !isTempName(e.Name(), base) {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > staleAfter {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// isTempName reports whether name is one writeAtomic made for the report
// called base: base, a dot, the letters and digits of rand.Text, and .tmp.
func isTempName(name, base string) bool {
	middle, ok := strings.CutPrefix(name, base+".")
	if !ok {
		return false
	}
	middle, ok = strings.CutSuffix(middle, ".tmp")
	if !ok || len(middle) != len(rand.Text()) {
		return false
	}
	return !strings.ContainsFunc(middle, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '2' || r > '7')
	})
}
