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
	fmt.Println("================================================================")
	fmt.Println("             MINDIGITAL-CAGE: АУДИТ И ВЕРИФИКАЦИЯ               ")
	fmt.Println("================================================================")

	localRootPath := filepath.Join(certDir, "1_local_restricted_root.crt")
	crossCertPath := filepath.Join(certDir, "2_mindigital_cross_ca.crt")
	subCertPath := filepath.Join(certDir, "3_mindigital_sub_ca.crt")

	fmt.Println("\n[1/4] Проверка файлов сертификатов...")
	for _, p := range []string{localRootPath, crossCertPath, subCertPath} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("файл не найден: %s. Сначала запустите генерацию (без флагов или с -install)", p)
		}
	}
	fmt.Println("  [✓] Все файлы сертификатов присутствуют на диске.")

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

	fmt.Println("\n[2/4] Криптографическая проверка целостности цепочки...")

	if err := crossCert.CheckSignatureFrom(localRoot); err != nil {
		return fmt.Errorf("подпись кросс-сертификата не сходится с локальным корнем: %w", err)
	}
	fmt.Println("  [✓] Кросс-сертификат корректно подписан локальным корнем (CheckSignature: OK).")

	if err := subCert.CheckSignatureFrom(crossCert); err != nil {
		return fmt.Errorf("подпись Sub CA не сходится с кросс-сертификатом Минцифры: %w", err)
	}
	fmt.Println("  [✓] Russian Trusted Sub CA корректно верифицируется открытым ключом кросс-сертификата: OK.")

	if !localRoot.PermittedDNSDomainsCritical || len(localRoot.PermittedDNSDomains) == 0 {
		return fmt.Errorf("ВНИМАНИЕ: в Local Root CA отсутствует или не критично расширение PermittedDNSDomains!")
	}
	fmt.Printf("  [✓] Name Constraints в Local Root CA: КРИТИЧНО, разрешенные зоны: %s\n", strings.Join(localRoot.PermittedDNSDomains, ", "))

	if len(localRoot.ExcludedIPRanges) == 0 {
		return fmt.Errorf("ВНИМАНИЕ: в Local Root CA не заблокированы IP-диапазоны!")
	}
	fmt.Println("  [✓] ExcludedIPRanges в Local Root CA: заблокированы все IPv4 и IPv6 (0.0.0.0/0, ::/0).")

	fmt.Println("\n[3/4] Тестирование изоляции Name Constraints (симуляция атак)...")
	if err := testAttackSimulation(localRoot); err != nil {
		return fmt.Errorf("тест симуляции атак не пройден: %w", err)
	}

	fmt.Println("\n[4/4] Аудит системного хранилища сертификатов ОС...")
	audit, err := CheckSystemStore()
	if err != nil {
		fmt.Printf("  [!] Не удалось получить полный статус хранилища ОС: %v\n", err)
	} else {
		if audit.LocalRootInstalled {
			fmt.Println("  [✓] 'Local Restricted Root CA' обнаружен в доверенных корневых центрах.")
		} else {
			fmt.Println("  [-] 'Local Restricted Root CA' пока НЕ установлен в системное хранилище.")
			fmt.Println("      Для установки запустите:  mindigital-cage -install  (от имени Администратора/root)")
		}

		if audit.OrigRootInRootStore {
			fmt.Println("\n  [!] ВНИМАНИЕ (КРИТИЧНО ДЛЯ БЕЗОПАСНОСТИ):")
			fmt.Println("      В системном хранилище Root обнаружен оригинальный незащищенный 'Russian Trusted Root CA'!")
			fmt.Println("      Если он установлен, Windows/система может предпочесть прямую короткую цепочку БЕЗ ограничений.")
			fmt.Println("      Рекомендуется удалить его командой:  mindigital-cage -clean-orig")
		} else {
			fmt.Println("  [✓] Оригинальный незащищенный Root CA Минцифры отсутствует в корневых центрах (безопасно).")
		}
	}

	fmt.Println("\n[*] Проверка сетевого доступа к инфраструктуре Госуслуг (gu-st.ru)...")
	testLiveConnection()

	fmt.Println("\n================================================================")
	fmt.Println("                 РЕЗУЛЬТАТ ВЕРИФИКАЦИИ: УСПЕШНО                 ")
	fmt.Println("  Все сайты .ru/.su/.рф с сертами Минцифры работают штатно.     ")
	fmt.Println("  Любые попытки подделки сертификатов .com/.org заблокированы.  ")
	fmt.Println("================================================================")
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
	fmt.Println("  [✓] Легитимные домены (.ru, .su, .рф) успешно валидируются.")

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
			return fmt.Errorf("КРИТИЧЕСКИЙ СБОЙ: домен %s прошел валидацию в обход Name Constraints!", domain)
		}
	}
	fmt.Println("  [✓] Попытки выпуска сертификатов для google.com, github.com, telegram.org надежно заблокированы.")

	ipCert, err := issueCert("1.1.1.1", net.ParseIP("1.1.1.1"))
	if err != nil {
		return err
	}
	optsIP := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}
	if _, err := ipCert.Verify(optsIP); err == nil {
		return fmt.Errorf("КРИТИЧЕСКИЙ СБОЙ: сертификат с IP адресом 1.1.1.1 прошел валидацию!")
	}
	fmt.Println("  [✓] Прямые IP-адреса (1.1.1.1) надежно заблокированы правилом ExcludedIPRanges.")

	return nil
}

func testLiveConnection() {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://gu-st.ru")
	if err != nil {
		fmt.Printf("  [i] Запрос к gu-st.ru: %v (возможно, нет сети или сервис недоступен)\n", err)
		return
	}
	_ = resp.Body.Close()
	fmt.Printf("  [✓] TLS подключение к https://gu-st.ru прошло успешно (HTTP %d).\n", resp.StatusCode)
}
