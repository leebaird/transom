package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Same fallback Discover uses when resource/user-agent.txt is missing.
const discoverUAFallback = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"

// discoverUserAgent matches Nikto: $USER_AGENT, then Discover's
// resource/user-agent.txt, then the built-in Edge string.
// USER_AGENT is used only when it starts with Mozilla/ and contains no controls,
// the same rule as a line in the Discover file.
func discoverUserAgent() string {
	if ua := strings.TrimSpace(os.Getenv("USER_AGENT")); acceptableUA(ua) {
		return ua
	}
	for _, path := range discoverUAFiles() {
		if ua := readDiscoverUA(path); ua != "" {
			return ua
		}
	}
	return discoverUAFallback
}

func acceptableUA(line string) bool {
	if !strings.HasPrefix(line, "Mozilla/") {
		return false
	}
	for _, r := range line {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func discoverUAFiles() []string {
	var paths []string
	if root := os.Getenv("DISCOVER"); root != "" {
		paths = append(paths, filepath.Join(root, "resource", "user-agent.txt"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, "discover", "resource", "user-agent.txt"))
	}
	return paths
}

func readDiscoverUA(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !acceptableUA(line) {
			return ""
		}
		return line
	}
	return ""
}
