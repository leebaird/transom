# Transom

A Go web server scanner. Give it a hostname and it probes a short list of common web ports, keeps each port that speaks HTTP or HTTPS, and checks that origin on its own. A full URL scans only that origin. It fetches paths and reads headers, certificates, cookies, and `robots.txt`. It does not send exploit payloads, try passwords, or upload files. Inspired by Nikto, by Chris Sullo (https://cirt.net/Nikto2).

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts

----------------------------------------------------------------------------------------------

## Install

Each [release](https://github.com/leebaird/transom/releases) has `.deb`, `.rpm`, and Arch Linux packages for amd64 and arm64, a `.pkg` installer for macOS on Apple silicon, and a `.tar.gz` for each of those targets. `checksums.txt` lists the SHA-256 of every file.

```bash
sudo dpkg -i transom_*_linux_amd64.deb              # Debian, Ubuntu, Kali
sudo rpm -i transom_*_linux_amd64.rpm               # Fedora, RHEL
sudo pacman -U transom_*_linux_amd64.pkg.tar.zst    # Arch
sudo installer -pkg transom_*_darwin_arm64.pkg -target /
```

The Linux packages install `/usr/bin/transom`. The macOS installer is unsigned and installs `/usr/local/bin/transom`.

With Go 1.27 or newer:

```bash
go install github.com/leebaird/transom/cmd/transom@latest
```

The binary is self-contained. The default port list and check corpus are compiled into it.

## Use

```bash
transom example.com
transom example.com:8443
transom '[2001:db8::1]:8443'
transom https://example.com:8443/app
transom --ports 80,8080 --timeout 5s -o report.json example.com
transom -o report.htm example.com other.example
transom version
```

| Target | What is scanned |
| --- | --- |
| `example.com` | Every port in the port list that answers as HTTP or HTTPS |
| `example.com:8443` | That socket only, as whichever of HTTPS or HTTP it speaks |
| `https://example.com:8443/app` | That origin only, with no probing. A path other than `/` is prefixed to every check path |

A port is kept only when a TLS handshake completes or a plaintext response starts with an HTTP status line. Transom does not run Nmap. An IPv6 address needs brackets.

`transom version` prints the release tag the binary was built from, or a pseudo-version naming the commit for a build between releases.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--ports 80,8080` | the port list | Ports to probe for a bare hostname |
| `--timeout 10s` | `10s` | Deadline for one request or one port probe |
| `--concurrency 8` | `8` | In-flight requests |
| `--header 'Name: value'` | none | Extra request header. Repeatable |
| `--user-agent ua` | see below | `User-Agent` header |
| `--follow mode` | `same-host` | `same-host` follows up to five redirects that stay on the same scheme, host, and port. `off` follows none |
| `--max-body bytes` | `1048576` | Stop reading a response body after this many bytes |
| `--checks dir` | the check corpus | Directory of JSON check files |
| `--format kind` | from the `-o` extension | `json` or `htm` |
| `-o path` | none | Write a JSON or HTML report |

Flags go before the targets. Anything after the first target is read as another target.

### Port list

The default list is [`ports.txt`](ports.txt): one port per line, or several separated by commas, with `#` comments. Transom reads a `ports.txt` next to the program, then one in the current directory, and otherwise uses the copy built into the binary. It says so on stderr when it takes one from the current directory. `--ports` replaces all three for that run.

### User-Agent

If `--user-agent` is omitted, Transom uses `USER_AGENT` when that value starts with `Mozilla/` and contains no control characters. Otherwise it reads the first line that is not blank or a `#` comment from `$DISCOVER/resource/user-agent.txt`, then `~/discover/resource/user-agent.txt`, under the same rule. The fallback is the Edge string Discover uses.

### Proxies

Discovery, path fetches, and the raw probes honor `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`.

### Output

Each discovered origin is printed to stdout as `host:port scheme`, followed by one finding per line: URL, check id, message. Target errors go to stderr.

`-o` also writes a report, replaced atomically when the run finishes. A path ending in `.htm` or `.html` is HTML; anything else is JSON. `--format` overrides the extension. The HTML report has one section per origin, one table per finding with repeated findings sharing a table, and a scan summary. An interrupt or a `SIGTERM` stops the scan and still writes the report, and the JSON then includes `"interrupted": true`. A second one ends the program at once.

| Exit status | Meaning |
| --- | --- |
| `0` | Every target was scanned. Findings do not change the status |
| `1` | A bad command line, a target that could not be scanned, or a report that could not be written |
| `2` | The run was interrupted |

## Checks

### Built in

These run against every origin and need no configuration:

* Missing `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`, and `Strict-Transport-Security`
* Disclosure in `Server`, `X-Powered-By`, `X-AspNet-Version`, `Via`, `Link`, and uncommon response headers, and a `Server` banner that changes between requests
* Apache, nginx, PHP, and IIS versions older than the release numbers compiled into the program
* Wildcard `Access-Control-Allow-Origin`, and `X-Frame-Options` still in use
* `OPTIONS` methods, `TRACE`, `DEBUG`, and servers that accept a made-up method
* Cookies missing `Secure` or `HttpOnly`
* TLS below 1.2, and certificates that are expired, expiring within 30 days, not yet valid, wildcard, or for another hostname. An untrusted issuer alone is not a finding
* Inode-leaking `ETag`, Apache MultiViews, the PHP credits page, Cloudflare's trace page, the default IIS page, and an internal address in a redirect
* `robots.txt` `Disallow` paths that are readable, up to 20 of them

### Path checks

Path checks are JSON. Each file is an array of checks:

```json
[
  {
    "id": "env-file",
    "path": "/.env",
    "method": "GET",
    "statuses": [200],
    "body": "(?m)^[A-Za-z_][A-Za-z0-9_]*=",
    "message": "/.env contains assignment-style lines"
  }
]
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Name printed with the finding. Unique across every file |
| `path` | yes | Path to request |
| `message` | yes | Text printed with the finding |
| `method` | no | HTTP method. Default `GET` |
| `statuses` | no | Status codes that match. Empty matches any status |
| `body` | no | Go regular expression the body must match. A pattern made only of `^\xHH` escapes is compared with the leading raw bytes instead |
| `headers` | no | Header name to regular expression. Every one must match |
| `ignoreSoft404` | no | Keep a match even when the page is the site's soft 404 |
| `raw` | no | Send `Accept-Encoding: identity`, for a `body` that matches file magic |

A file with an unknown field, a bad regular expression, or a repeated `id` is rejected. Before the path checks, Transom requests a random path. When that returns `200`, a check whose `200` response has the same body is dropped as a soft 404 unless `ignoreSoft404` is set.

The starter corpus is [`checks/paths.json`](checks/paths.json). Transom reads every `*.json` file in `--checks`, or in a `checks` directory next to the program, or in one in the current directory, and otherwise uses the starter corpus built into the binary. A `checks` directory it finds by name is passed over when it holds no checks, and it says so on stderr when it takes one from the current directory. The Linux packages install a copy of `ports.txt` and the corpus under `/usr/share/doc/transom/examples` to start from.

## Build

```bash
go build -o transom ./cmd/transom
```

Go 1.27 or newer. The module has no third-party dependencies.

`make build` cross-compiles Linux amd64, Linux arm64, and macOS arm64 binaries into `build/`.

## Develop

```bash
make fix            # go fix modernizers
make fmt-check      # gofmt and goimports, through golangci-lint
make lint           # golangci-lint, configured in .golangci.yml
make vet
make test           # with and without the race detector
make fuzz           # each fuzz target for FUZZTIME, 10s by default
make vulncheck      # govulncheck, at the version pinned in the Makefile
make tidy-check
make release-check  # validate .goreleaser.yaml
make snapshot       # GoReleaser: every archive and Linux package, into dist/
```

`make lint` and `make fmt-check` need [golangci-lint](https://golangci-lint.run) v2. `make snapshot` and `make release-check` need [GoReleaser](https://goreleaser.com) v2. `make vulncheck` downloads govulncheck. `make pkg-darwin-arm64 VERSION=1.2.3` builds the macOS installer and runs only on macOS, because it calls `pkgbuild`.

GitHub Actions runs lint, build, tests, and a snapshot packaging build on every push to `master` and every pull request, and govulncheck on those and weekly. Dependabot groups GitHub Actions and Go module updates into one pull request.

Pushing a `v*` tag runs the release workflow. It builds the macOS installer on a macOS runner, then GoReleaser publishes it with the archives, the Linux packages, and `checksums.txt`.

This tool should only be used against targets that you are authorized to scan.
