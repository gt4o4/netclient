package ncutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gravitl/netmaker/models"
	"github.com/hashicorp/go-retryablehttp"
)

// httpDialTimeout is the per-Dial timeout for outbound HTTP/S requests
// from SendRequest. Mirrors retryablehttp's default behavior — long
// enough to accommodate the worst-case Cloudflare-fronted edge handshake
// (TLS over MPTCP), short enough that a dead edge falls back to retry.
const httpDialTimeout = 30 * time.Second

type ErrStatusNotOk struct {
	Status  int
	Message string
}

func (e ErrStatusNotOk) Error() string {
	if e.Message != "" {
		return e.Message
	}

	return fmt.Sprintf("http request failed with status %d (%s)", e.Status, http.StatusText(e.Status))
}

func SendRequest(method, endpoint string, headers http.Header, data any) (*bytes.Buffer, error) {
	var request *retryablehttp.Request
	var err error

	if data != nil {
		payload, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		request, err = retryablehttp.NewRequestWithContext(context.TODO(), method, endpoint, bytes.NewBuffer(payload))
		if err != nil {
			return nil, err
		}

		request.Header.Set("Content-Type", "application/json")
	} else {
		request, err = retryablehttp.NewRequestWithContext(context.TODO(), method, endpoint, nil)
		if err != nil {
			return nil, err
		}
	}

	for key, value := range headers {
		request.Header.Set(key, value[0])
	}

	client := retryablehttp.NewClient()
	// Override the default transport so outbound TCP becomes MPTCP-capable
	// (auto-fallback to plain TCP) and so api.nm.wenri.org:443 is rewritten
	// to its Cloudflare anycast edge per /etc/netclient/peers_extra_ips.json.
	// TLS still uses the URL host for SNI/cert verification.
	client.HTTPClient.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           MPTCPDialContext(httpDialTimeout),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client.RetryMax = 3
	client.Logger = nil
	client.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if err != nil {
			// retry network errors
			return true, nil
		}

		return false, nil
	}
	client.RetryWaitMin = 5 * time.Second
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		var errResp models.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		if err != nil {
			return nil, ErrStatusNotOk{
				Status: resp.StatusCode,
			}
		}

		return nil, ErrStatusNotOk{
			Status:  resp.StatusCode,
			Message: errResp.Message,
		}
	}

	var body bytes.Buffer
	_, err = io.Copy(&body, resp.Body)
	if err != nil {
		return nil, err
	}

	return &body, nil
}
