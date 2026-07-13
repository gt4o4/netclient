package functions

import (
	"log"
	"os"
	"testing"
	"time"
)

func TestIp112Source(t *testing.T) {
	s := &ip112Source{}
	ip, err := s.IP(10*time.Second, log.New(os.Stderr, "", 0), 4)
	if err != nil {
		t.Fatalf("ip112Source failed: %v", err)
	}
	t.Logf("ip112Source: %s", ip)
}

func TestIp138Source(t *testing.T) {
	s := &ip138Source{}
	ip, err := s.IP(10*time.Second, log.New(os.Stderr, "", 0), 4)
	if err != nil {
		t.Fatalf("ip138Source failed: %v", err)
	}
	t.Logf("ip138Source: %s", ip)
}

func TestIp111Source(t *testing.T) {
	s := &ip111Source{}
	ip, err := s.IP(10*time.Second, log.New(os.Stderr, "", 0), 4)
	if err != nil {
		t.Fatalf("ip111Source failed: %v", err)
	}
	t.Logf("ip111Source: %s", ip)
}
