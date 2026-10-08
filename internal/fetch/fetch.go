package fetch

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"github.com/leebaird/transom/internal/target"
)

// Response is what a check sees. Err is set only when the exchange produced
// no status line. A short body leaves Err nil and sets Truncated.
type Response struct {
	Status    int
	Header    http.Header
	Body      string
	URL       string
	TLS       *tls.ConnectionState
	Duration  time.Duration
	Truncated bool
	Err       error
}

// Do fetches path, which must already include the target root.
func (c *Client) Do(ctx context.Context, method, path string) Response {
	return c.do(ctx, method, path, false)
}

// DoIdentity fetches path and sends Accept-Encoding: identity so a magic-byte
// check sees the file itself when a server would otherwise gzip the body.
func (c *Client) DoIdentity(ctx context.Context, method, path string) Response {
	return c.do(ctx, method, path, true)
}

func (c *Client) do(ctx context.Context, method, path string, identity bool) (out Response) {
	defer func() {
		if c.Observe != nil {
			c.Observe(out)
		}
	}()
	start := time.Now()
	if method == "" {
		method = http.MethodGet
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.target.URL(path), nil)
	if err != nil {
		return Response{Err: err, Duration: time.Since(start)}
	}
	if c.ua != "" {
		req.Header.Set("User-Agent", c.ua)
	}
	for k, vs := range c.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if identity {
		req.Header.Set("Accept-Encoding", "identity")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Response{Err: err, Duration: time.Since(start)}
	}
	defer resp.Body.Close()
	buf, readErr := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	truncated := int64(len(buf)) > c.maxBody
	if truncated {
		buf = buf[:c.maxBody]
	}
	if readErr != nil {
		truncated = true
	}
	out = Response{
		Status:    resp.StatusCode,
		Header:    resp.Header.Clone(),
		Body:      string(buf),
		URL:       resp.Request.URL.String(),
		Duration:  time.Since(start),
		Truncated: truncated,
	}
	if resp.TLS != nil {
		state := *resp.TLS
		out.TLS = &state
	}
	return out
}

// Target returns the origin this client was built for.
func (c *Client) Target() target.Target { return c.target }
