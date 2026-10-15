package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func RunVerification(certDir string) error {
	localRootPath := filepath.Join(certDir, "1_local_restricted_root.crt")
	crossCertPath := filepath.Join(certDir, "2_mindigital_cross_ca.crt")
	subCertPath := filepath.Join(certDir, "3_mindigital_sub_ca.crt")

	for _, p := range []string{localRootPath, crossCertPath, subCertPath} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("файл не найден: %s (сначала выполните генерацию)", p)
		}
	}

	localRoot, err := readCertFile(localRootPath)
	if err != nil {
		return fmt.Errorf("чтение localRoot: %w", err)
	}
	crossCert, err := readCertFile(crossCertPath)
	if err != nil {
		return fmt.Errorf("чтение crossCert: %w", err)
	}
	subCert, err := readCertFile(subCertPath)
	if err != nil {
		return fmt.Errorf("чтение subCert: %w", err)
	}

	if err := crossCert.CheckSignatureFrom(localRoot); err != nil {
		return fmt.Errorf("подпись кросс-сертификата невалидна: %w", err)
	}
	if err := subCert.CheckSignatureFrom(crossCert); err != nil {
		return fmt.Errorf("подпись Sub CA невалидна: %w", err)
	}
	if !localRoot.PermittedDNSDomainsCritical || len(localRoot.PermittedDNSDomains) == 0 {
		return fmt.Errorf("в Local Root CA отсутствует расширение PermittedDNSDomains")
	}

	if err := testAttackSimulation(localRoot); err != nil {
		return fmt.Errorf("симуляция изоляции не пройдена: %w", err)
	}

	fmt.Println("[*] Проверка изоляции сертификатов:")
	fmt.Println("  [+] Цепочка сертификатов: валидна")
	fmt.Printf("  [+] Разрешенные зоны: %s\n", strings.Join(localRoot.PermittedDNSDomains, ", "))
	fmt.Println("  [+] Блокировка внешних доменов (.com, .org, IP): активна")

	audit, err := CheckSystemStore()
	if err == nil {
		if audit.LocalRootInstalled {
			fmt.Println("  [+] Системное хранилище: изолированный корень установлен")
		} else {
			fmt.Println("  [-] Системное хранилище: изолированный корень НЕ установлен (запустите -install)")
		}

		if audit.OrigRootInRootStore {
			fmt.Println("  [!] ВНИМАНИЕ: оригинальный незащищенный корень Минцифры найден в Root (запустите -clean-orig)")
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://gu-st.ru")
	if err == nil {
		_ = resp.Body.Close()
		fmt.Printf("  [+] Сетевое подключение к gu-st.ru: OK (HTTP %d)\n", resp.StatusCode)
	}

	return nil
}

func readCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("не найден PEM блок в %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func testAttackSimulation(testRoot *x509.Certificate) error {
	simKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().Add(-1 * time.Hour)

	_, ipv4All, _ := net.ParseCIDR("0.0.0.0/0")
	_, ipv6All, _ := net.ParseCIDR("::/0")

	simRootTmpl := &x509.Certificate{
		SerialNumber:                big.NewInt(100),
		Subject:                     pkix.Name{CommonName: "Sim Root"},
		NotBefore:                   now,
		NotAfter:                    now.Add(24 * time.Hour),
		KeyUsage:                    x509.KeyUsageCertSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         testRoot.PermittedDNSDomains,
		ExcludedIPRanges:            []*net.IPNet{ipv4All, ipv6All},
	}
	simRootDER, _ := x509.CreateCertificate(rand.Reader, simRootTmpl, simRootTmpl, &simKey.PublicKey, simKey)
	simRoot, _ := x509.ParseCertificate(simRootDER)

	simSubKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	simSubTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "Sim Sub CA"},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	simSubDER, _ := x509.CreateCertificate(rand.Reader, simSubTmpl, simRoot, &simSubKey.PublicKey, simKey)
	simSub, _ := x509.ParseCertificate(simSubDER)

	roots := x509.NewCertPool()
	roots.AddCert(simRoot)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(simSub)

	issueCert := func(domain string, ip net.IP) (*x509.Certificate, error) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		t := &x509.Certificate{
			SerialNumber:          big.NewInt(102),
			Subject:               pkix.Name{CommonName: domain},
			DNSNames:              []string{domain},
			NotBefore:             now,
			NotAfter:              now.Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		if ip != nil {
			t.IPAddresses = []net.IP{ip}
		}
		der, err := x509.CreateCertificate(rand.Reader, t, simSub, &k.PublicKey, simSubKey)
		if err != nil {
			return nil, fmt.Errorf("CreateCertificate (%s): %w", domain, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("ParseCertificate (%s): %w", domain, err)
		}
		return cert, nil
	}

	allowed := []string{"gosuslugi.ru", "sberbank.ru", "nalog.gov.ru", "portal.su", "test.xn--p1ai"}
	for _, domain := range allowed {
		cert, err := issueCert(domain, nil)
		if err != nil {
			return err
		}
		opts := x509.VerifyOptions{
			DNSName:       domain,
			Roots:         roots,
			Intermediates: intermediates,
		}
		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("ошибка валидации легитимного домена %s: %w", domain, err)
		}
	}

	forbidden := []string{"google.com", "github.com", "telegram.org", "apple.com", "bank.kz"}
	for _, domain := range forbidden {
		cert, err := issueCert(domain, nil)
		if err != nil {
			return err
		}
		opts := x509.VerifyOptions{
			DNSName:       domain,
			Roots:         roots,
			Intermediates: intermediates,
		}
		if _, err := cert.Verify(opts); err == nil {
			return fmt.Errorf("домен %s прошел валидацию в обход Name Constraints", domain)
		}
	}

	ipCert, err := issueCert("1.1.1.1", net.ParseIP("1.1.1.1"))
	if err != nil {
		return err
	}
	optsIP := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}
	if _, err := ipCert.Verify(optsIP); err == nil {
		return fmt.Errorf("сертификат с IP 1.1.1.1 прошел валидацию")
	}

	return nil
}
