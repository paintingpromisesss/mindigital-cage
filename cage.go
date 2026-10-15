package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// DefaultRootCAURL - официальный прямой URL Root CA Минцифры с CDN Госуслуг
	DefaultRootCAURL = "https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt"
	// DefaultSubCAURL - официальный прямой URL Sub CA Минцифры с CDN Госуслуг
	DefaultSubCAURL = "https://gu-st.ru/content/lending/russian_trusted_sub_ca_pem.crt"

	// LocalRootCN - имя локального ограниченного корневого центра сертификации
	LocalRootCN = "Local Restricted Root CA (RU-SU-RF Only)"
)

type GenerateOptions struct {
	OutDir           string
	PermittedDomains []string
	RootCAURL        string
	SubCAURL         string
}

type CageResult struct {
	LocalRootCert  *x509.Certificate
	CrossCert      *x509.Certificate
	SubCert        *x509.Certificate
	OrigRootCert   *x509.Certificate
	LocalRootPath  string
	CrossCertPath  string
	SubCertPath    string
	OrigRootBackup string
}

func DefaultPermittedDomains() []string {
	return []string{
		"ru", ".ru",
		"su", ".su",
		"xn--p1ai", ".xn--p1ai", // .рф в punycode
	}
}

func ParseDomains(raw string) []string {
	parts := strings.Split(raw, ",")
	var result []string
	for _, p := range parts {
		d := strings.TrimSpace(p)
		if d == "" {
			continue
		}
		d = strings.ToLower(d)
		if strings.HasPrefix(d, ".") {
			withoutDot := strings.TrimPrefix(d, ".")
			result = append(result, withoutDot, d)
		} else {
			result = append(result, d, "."+d)
		}
	}
	return deduplicateStrings(result)
}

func deduplicateStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func GenerateCage(opts GenerateOptions) (*CageResult, error) {
	if opts.RootCAURL == "" {
		opts.RootCAURL = DefaultRootCAURL
	}
	if opts.SubCAURL == "" {
		opts.SubCAURL = DefaultSubCAURL
	}
	if len(opts.PermittedDomains) == 0 {
		opts.PermittedDomains = DefaultPermittedDomains()
	}

	origRoot, rawRootPEM, err := fetchCert(opts.RootCAURL)
	if err != nil {
		return nil, fmt.Errorf("не удалось скачать Root CA: %w", err)
	}
	origSub, rawSubPEM, err := fetchCert(opts.SubCAURL)
	if err != nil {
		return nil, fmt.Errorf("не удалось скачать Sub CA: %w", err)
	}

	localRootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации RSA ключа: %w", err)
	}

	_, ipv4All, _ := net.ParseCIDR("0.0.0.0/0")
	_, ipv6All, _ := net.ParseCIDR("::/0")
	excludedIPs := []*net.IPNet{ipv4All, ipv6All}

	now := time.Now().Add(-1 * time.Hour)
	tenYears := now.AddDate(10, 0, 0)

	localRootSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("генерация серийного номера: %w", err)
	}

	localRootTmpl := &x509.Certificate{
		SerialNumber: localRootSerial,
		Subject: pkix.Name{
			CommonName:   LocalRootCN,
			Organization: []string{"Local Security Cage"},
			Country:      []string{"RU"},
		},
		NotBefore:                   now,
		NotAfter:                    tenYears,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  2,
		MaxPathLenZero:              false,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         opts.PermittedDomains,
		ExcludedIPRanges:            excludedIPs,
	}

	localRootDER, err := x509.CreateCertificate(rand.Reader, localRootTmpl, localRootTmpl, &localRootKey.PublicKey, localRootKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания Local Root CA: %w", err)
	}
	localRootCert, err := x509.ParseCertificate(localRootDER)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга Local Root CA: %w", err)
	}

	crossSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("генерация серийного номера: %w", err)
	}

	crossTmpl := &x509.Certificate{
		SerialNumber:                crossSerial,
		RawSubject:                  origRoot.RawSubject,
		NotBefore:                   origRoot.NotBefore,
		NotAfter:                    origRoot.NotAfter,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  1,
		MaxPathLenZero:              false,
		SubjectKeyId:                origRoot.SubjectKeyId,
		AuthorityKeyId:              localRootCert.SubjectKeyId,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         opts.PermittedDomains,
		ExcludedIPRanges:            excludedIPs,
	}

	crossDER, err := x509.CreateCertificate(rand.Reader, crossTmpl, localRootCert, origRoot.PublicKey, localRootKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания кросс-сертификата: %w", err)
	}
	crossCert, err := x509.ParseCertificate(crossDER)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга кросс-сертификата: %w", err)
	}

	zeroKey(localRootKey)

	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("ошибка создания папки %s: %w", opts.OutDir, err)
	}

	localRootPath := filepath.Join(opts.OutDir, "1_local_restricted_root.crt")
	crossCertPath := filepath.Join(opts.OutDir, "2_mindigital_cross_ca.crt")
	subCertPath := filepath.Join(opts.OutDir, "3_mindigital_sub_ca.crt")
	origRootBackup := filepath.Join(opts.OutDir, "orig_mindigital_root_DO_NOT_INSTALL.pem")

	if err := writePEM(localRootPath, "CERTIFICATE", localRootDER); err != nil {
		return nil, err
	}
	if err := writePEM(crossCertPath, "CERTIFICATE", crossDER); err != nil {
		return nil, err
	}
	if err := os.WriteFile(subCertPath, rawSubPEM, 0o644); err != nil {
		return nil, fmt.Errorf("ошибка записи Sub CA: %w", err)
	}
	if err := os.WriteFile(origRootBackup, rawRootPEM, 0o644); err != nil {
		return nil, fmt.Errorf("ошибка записи бэкапа оригинального Root CA: %w", err)
	}

	return &CageResult{
		LocalRootCert:  localRootCert,
		CrossCert:      crossCert,
		SubCert:        origSub,
		OrigRootCert:   origRoot,
		LocalRootPath:  localRootPath,
		CrossCertPath:  crossCertPath,
		SubCertPath:    subCertPath,
		OrigRootBackup: origRootBackup,
	}, nil
}

func fetchCert(url string) (*x509.Certificate, []byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d (%s)", resp.StatusCode, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(data)
	var derBytes []byte
	if block != nil {
		derBytes = block.Bytes
	} else {
		derBytes = data
		var buf bytes.Buffer
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		data = buf.Bytes()
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, data, nil
}

func writePEM(path, pemType string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("не удалось создать файл %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: pemType, Bytes: der}); err != nil {
		return fmt.Errorf("ошибка кодирования PEM в %s: %w", path, err)
	}
	return nil
}

func zeroBigInt(n *big.Int) {
	if n == nil {
		return
	}
	words := n.Bits()
	for i := range words {
		words[i] = 0
	}
	n.SetInt64(0)
}

func zeroKey(k *rsa.PrivateKey) {
	if k == nil {
		return
	}
	zeroBigInt(k.D)
	for _, p := range k.Primes {
		zeroBigInt(p)
	}
	zeroBigInt(k.Precomputed.Dp)
	zeroBigInt(k.Precomputed.Dq)
	zeroBigInt(k.Precomputed.Qinv)
	for _, c := range k.Precomputed.CRTValues {
		zeroBigInt(c.Exp)
		zeroBigInt(c.Coeff)
		zeroBigInt(c.R)
	}
	k.D = nil
	k.Primes = nil
	k.Precomputed = rsa.PrecomputedValues{}
	runtime.GC()
}
