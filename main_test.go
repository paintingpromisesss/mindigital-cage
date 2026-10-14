package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestParseDomains(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "ru, su",
			expected: []string{"ru", ".ru", "su", ".su"},
		},
		{
			input:    ".ru, xn--p1ai",
			expected: []string{"ru", ".ru", "xn--p1ai", ".xn--p1ai"},
		},
	}

	for _, tc := range tests {
		got := ParseDomains(tc.input)
		if !reflect.DeepEqual(got, tc.expected) {
			t.Errorf("ParseDomains(%q) = %v, expected %v", tc.input, got, tc.expected)
		}
	}
}

func TestZeroKey(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if k.D == nil || k.D.Sign() == 0 {
		t.Fatalf("Expected non-zero private exponent D")
	}

	zeroKey(k)

	if k.D != nil {
		t.Errorf("Expected k.D to be nil after zeroKey, got %v", k.D)
	}
	if k.Primes != nil {
		t.Errorf("Expected k.Primes to be nil after zeroKey")
	}
}

func TestNameConstraintsValidation(t *testing.T) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	permittedDomains := []string{
		"ru", ".ru",
		"su", ".su",
		"xn--p1ai", ".xn--p1ai",
	}
	_, ipv4All, _ := net.ParseCIDR("0.0.0.0/0")
	_, ipv6All, _ := net.ParseCIDR("::/0")
	excludedIPs := []*net.IPNet{ipv4All, ipv6All}

	now := time.Now().Add(-1 * time.Hour)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cage Root CA",
		},
		NotBefore:                   now,
		NotAfter:                    now.Add(24 * time.Hour),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permittedDomains,
		ExcludedIPRanges:            excludedIPs,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate root: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate root: %v", err)
	}

	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey sub: %v", err)
	}
	subTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Sub CA",
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	subDER, err := x509.CreateCertificate(rand.Reader, subTmpl, rootCert, &subKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate sub: %v", err)
	}
	subCert, err := x509.ParseCertificate(subDER)
	if err != nil {
		t.Fatalf("ParseCertificate sub: %v", err)
	}

	issueLeaf := func(dnsNames []string, ips []net.IP) *x509.Certificate {
		leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject: pkix.Name{
				CommonName: dnsNames[0],
			},
			DNSNames:              dnsNames,
			IPAddresses:           ips,
			NotBefore:             now,
			NotAfter:              now.Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, leafTmpl, subCert, &leafKey.PublicKey, subKey)
		if err != nil {
			t.Fatalf("CreateCertificate leaf (%v): %v", dnsNames, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate leaf: %v", err)
		}
		return cert
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(subCert)

	validDomains := []string{"gosuslugi.ru", "sub.sberbank.ru", "test.su", "site.xn--p1ai"}
	for _, domain := range validDomains {
		leaf := issueLeaf([]string{domain}, nil)
		opts := x509.VerifyOptions{
			DNSName:       domain,
			Roots:         roots,
			Intermediates: intermediates,
		}
		if _, err := leaf.Verify(opts); err != nil {
			t.Errorf("Expected domain %s to be valid, but got: %v", domain, err)
		}
	}

	invalidDomains := []string{"google.com", "github.com", "bank.kz", "example.org"}
	for _, domain := range invalidDomains {
		leaf := issueLeaf([]string{domain}, nil)
		opts := x509.VerifyOptions{
			DNSName:       domain,
			Roots:         roots,
			Intermediates: intermediates,
		}
		if _, err := leaf.Verify(opts); err == nil {
			t.Errorf("Expected domain %s to FAIL verification due to Name Constraints, but it passed!", domain)
		}
	}

	leafIP := issueLeaf([]string{"1.1.1.1"}, []net.IP{net.ParseIP("1.1.1.1")})
	optsIP := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}
	if _, err := leafIP.Verify(optsIP); err == nil {
		t.Errorf("Expected IP address 1.1.1.1 to FAIL verification due to ExcludedIPRanges, but it passed!")
	}
}
