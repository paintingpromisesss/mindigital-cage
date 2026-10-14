//go:build darwin

package main

import (
	"fmt"
	"os/exec"
)

type StoreAuditResult struct {
	LocalRootInstalled  bool
	OrigRootInRootStore bool
	CrossCertInstalled  bool
	SubCertInstalled    bool
	Notes               []string
}

const keychainPath = "/Library/Keychains/System.keychain"

func InstallCertificates(localRootPath, crossPath, subPath string) error {
	fmt.Println("[*] Установка Local Restricted Root CA в системный Keychain macOS (требуется sudo)...")
	if out, err := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", keychainPath, localRootPath).CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка добавления Local Root: %w (%s)", err, string(out))
	}

	fmt.Println("[*] Установка промежуточных сертификатов в Keychain...")
	if out, err := exec.Command("sudo", "security", "add-certificate", "-k", keychainPath, crossPath).CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка добавления cross CA: %w (%s)", err, string(out))
	}
	if out, err := exec.Command("sudo", "security", "add-certificate", "-k", keychainPath, subPath).CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка добавления sub CA: %w (%s)", err, string(out))
	}

	fmt.Println("[+] Сертификаты успешно установлены в macOS System Keychain!")
	return nil
}

func UninstallCertificates() error {
	fmt.Println("[*] Удаление Local Restricted Root CA из Keychain...")
	_ = exec.Command("sudo", "security", "delete-certificate", "-c", LocalRootCN, keychainPath).Run()
	_ = exec.Command("sudo", "security", "delete-certificate", "-c", "Russian Trusted Root CA", keychainPath).Run()
	_ = exec.Command("sudo", "security", "delete-certificate", "-c", "Russian Trusted Sub CA", keychainPath).Run()
	fmt.Println("[+] Сертификаты удалены из macOS Keychain.")
	return nil
}

func CheckSystemStore() (StoreAuditResult, error) {
	var res StoreAuditResult
	if err := exec.Command("security", "find-certificate", "-c", LocalRootCN, keychainPath).Run(); err == nil {
		res.LocalRootInstalled = true
	}
	if err := exec.Command("security", "find-certificate", "-c", "Russian Trusted Root CA", keychainPath).Run(); err == nil {
		res.OrigRootInRootStore = true
	}
	return res, nil
}

func CleanOriginalRoot() error {
	_ = exec.Command("sudo", "security", "delete-certificate", "-c", "Russian Trusted Root CA", keychainPath).Run()
	return nil
}
