package functions

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// ip112Response is the XML response from ip112.com API
type ip112Response struct {
	IP string `xml:"items>ip"`
}

// ip112Source implements externalip.Source using ip112.com POST API
type ip112Source struct{}

func (s *ip112Source) IP(timeout time.Duration, logger *log.Logger, protocol uint) (net.IP, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Post("https://ip112.com/api/ip", "application/x-www-form-urlencoded", strings.NewReader("ip="))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result ip112Response
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(result.IP))
	if ip == nil {
		return nil, fmt.Errorf("ip112.com returned invalid IP: %q", result.IP)
	}
	return ip, nil
}

// ip138Source implements externalip.Source using 2026.ip138.com
type ip138Source struct{}

func (s *ip138Source) IP(timeout time.Duration, logger *log.Logger, protocol uint) (net.IP, error) {
	req, err := http.NewRequest("GET", "https://2026.ip138.com/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	title, err := extractHTMLTitle(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ip138.com: %w", err)
	}
	// title format: "您的IP地址是：45.13.119.235"
	parts := strings.SplitN(title, "：", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("ip138.com: unexpected title format: %q", title)
	}
	ip := net.ParseIP(strings.TrimSpace(parts[1]))
	if ip == nil {
		return nil, fmt.Errorf("ip138.com returned invalid IP: %q", parts[1])
	}
	return ip, nil
}

// ip111Source implements externalip.Source using ip111.cn
type ip111Source struct{}

func (s *ip111Source) IP(timeout time.Duration, logger *log.Logger, protocol uint) (net.IP, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get("https://ip111.cn/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ip, err := extractFirstIPFromCardBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ip111.cn: %w", err)
	}
	return ip, nil
}

// extractFirstIPFromCardBody parses HTML and extracts the IP from the first
// <div class="card-body"> element's <p> text content
func extractFirstIPFromCardBody(r io.Reader) (net.IP, error) {
	tokenizer := html.NewTokenizer(r)
	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return nil, fmt.Errorf("no IP found in card-body")
		case html.StartTagToken:
			tn, hasAttr := tokenizer.TagName()
			if string(tn) == "div" && hasAttr {
				for {
					key, val, more := tokenizer.TagAttr()
					if string(key) == "class" && strings.Contains(string(val), "card-body") {
						return extractIPFromChildren(tokenizer)
					}
					if !more {
						break
					}
				}
			}
		}
	}
}

// extractIPFromChildren scans child text nodes for a valid IP address
func extractIPFromChildren(tokenizer *html.Tokenizer) (net.IP, error) {
	depth := 1
	for depth > 0 {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return nil, fmt.Errorf("unexpected end of HTML")
		case html.StartTagToken:
			depth++
		case html.EndTagToken:
			depth--
		case html.TextToken:
			text := strings.TrimSpace(string(tokenizer.Text()))
			if text == "" {
				continue
			}
			// text format: "45.13.119.235 法国 巴黎"
			fields := strings.Fields(text)
			if len(fields) > 0 {
				if ip := net.ParseIP(fields[0]); ip != nil {
					return ip, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no valid IP found")
}

// extractHTMLTitle parses HTML and returns the content of the <title> element
func extractHTMLTitle(r io.Reader) (string, error) {
	tokenizer := html.NewTokenizer(r)
	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return "", fmt.Errorf("no <title> found")
		case html.StartTagToken:
			tn, _ := tokenizer.TagName()
			if string(tn) == "title" {
				if tokenizer.Next() == html.TextToken {
					return strings.TrimSpace(string(tokenizer.Text())), nil
				}
			}
		}
	}
}
