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
	if out, err := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", keychainPath, localRootPath).CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка добавления Local Root: %w (%s)", err, string(out))
	}

	if out, err := exec.Command("sudo", "security", "add-certificate", "-k", keychainPath, crossPath).CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка добавления cross CA: %w (%s)", err, string(out))
	}
	if out, err := exec.Command("sudo", "security", "add-certificate", "-k", keychainPath, subPath).CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка добавления sub CA: %w (%s)", err, string(out))
	}

	return nil
}

func UninstallCertificates() error {
	_ = exec.Command("sudo", "security", "delete-certificate", "-c", LocalRootCN, keychainPath).Run()
	_ = exec.Command("sudo", "security", "delete-certificate", "-c", "Russian Trusted Root CA", keychainPath).Run()
	_ = exec.Command("sudo", "security", "delete-certificate", "-c", "Russian Trusted Sub CA", keychainPath).Run()
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
