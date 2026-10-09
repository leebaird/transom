// Package transom embeds the default port list and check corpus, so an
// installed binary scans without ports.txt and checks/ beside it.
package transom

import "embed"

// Ports is ports.txt as shipped with this build.
//
//go:embed ports.txt
var Ports []byte

// Checks holds the starter corpus under ChecksDir.
//
//go:embed checks/*.json
var Checks embed.FS

// ChecksDir is the directory inside Checks that holds the corpus.
const ChecksDir = "checks"
