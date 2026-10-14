//go:build !windows && !linux && !darwin

package main

import (
	"fmt"
	"runtime"
)

type StoreAuditResult struct {
	LocalRootInstalled  bool
	OrigRootInRootStore bool
	CrossCertInstalled  bool
	SubCertInstalled    bool
	Notes               []string
}

func InstallCertificates(localRootPath, crossPath, subPath string) error {
	return fmt.Errorf("автоматическая установка не поддерживается для ОС %s. Установите файлы сертификатов вручную", runtime.GOOS)
}

func UninstallCertificates() error {
	return fmt.Errorf("автоматическое удаление не поддерживается для ОС %s", runtime.GOOS)
}

func CheckSystemStore() (StoreAuditResult, error) {
	return StoreAuditResult{}, fmt.Errorf("проверка хранилища не поддерживается для ОС %s", runtime.GOOS)
}

func CleanOriginalRoot() error {
	return fmt.Errorf("очистка не поддерживается для ОС %s", runtime.GOOS)
}
