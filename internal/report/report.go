// Package report writes text findings and atomic JSON or HTML documents.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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

func writeAtomic(path string, write func(io.Writer) error) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
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
