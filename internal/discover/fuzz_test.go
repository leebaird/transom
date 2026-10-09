package discover

import "testing"

// FuzzParsePortList checks that an accepted ports.txt yields at least one
// port, each in range and listed once.
func FuzzParsePortList(f *testing.F) {
	for _, seed := range []string{
		"80\n443\n",
		"# web ports\n80\n443  # https\n\n8080, 8081\n80\n",
		"80,,443",
		"0",
		"65536",
		"-1",
		"http",
		"",
		"#\n",
		"80\r\n443\r\n",
		"99999999999999999999",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ports, err := ParsePortList("fuzz", data)
		if err != nil {
			return
		}
		if len(ports) == 0 {
			t.Fatal("no ports and no error")
		}
		seen := map[int]bool{}
		for _, p := range ports {
			if p < 1 || p > 65535 {
				t.Fatalf("port %d out of range", p)
			}
			if seen[p] {
				t.Fatalf("port %d listed twice", p)
			}
			seen[p] = true
		}
	})
}
