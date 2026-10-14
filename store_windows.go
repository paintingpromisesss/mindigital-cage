//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type StoreAuditResult struct {
	LocalRootInstalled  bool
	OrigRootInRootStore bool
	CrossCertInstalled  bool
	SubCertInstalled    bool
	Notes               []string
}

func InstallCertificates(localRootPath, crossPath, subPath string) error {
	fmt.Println("[*] Очистка оригинального Root CA Минцифры из хранилища 'Root'...")
	_ = exec.Command("certutil", "-f", "-delstore", "Root", "Russian Trusted Root CA").Run()
	_ = exec.Command("certutil", "-user", "-f", "-delstore", "Root", "Russian Trusted Root CA").Run()

	fmt.Println("[*] Установка Local Restricted Root CA в системное хранилище 'Root'...")
	if out, err := exec.Command("certutil", "-f", "-addstore", "Root", localRootPath).CombinedOutput(); err != nil {
		return fmt.Errorf("не удалось добавить в Root (требуются права Администратора): %w\nВывод: %s", err, string(out))
	}

	fmt.Println("[*] Установка кросс-сертификата в системное хранилище промежуточных ЦС ('CA')...")
	if out, err := exec.Command("certutil", "-f", "-addstore", "CA", crossPath).CombinedOutput(); err != nil {
		return fmt.Errorf("не удалось добавить кросс-сертификат в CA: %w\nВывод: %s", err, string(out))
	}

	fmt.Println("[*] Установка Russian Trusted Sub CA в хранилище промежуточных ЦС ('CA')...")
	if out, err := exec.Command("certutil", "-f", "-addstore", "CA", subPath).CombinedOutput(); err != nil {
		return fmt.Errorf("не удалось добавить Sub CA в CA: %w\nВывод: %s", err, string(out))
	}

	fmt.Println("[+] Успешно установлено в системное хранилище Windows!")
	fmt.Println("    - 'Local Restricted Root CA' -> Доверенные корневые центры сертификации (Root)")
	fmt.Println("    - 'mindigital_cross_ca'     -> Промежуточные центры сертификации (CA)")
	fmt.Println("    - 'mindigital_sub_ca'       -> Промежуточные центры сертификации (CA)")

	checkFirefox()
	return nil
}

func UninstallCertificates() error {
	fmt.Println("[*] Удаление Local Restricted Root CA из хранилищ Root (Machine и User)...")
	_ = exec.Command("certutil", "-f", "-delstore", "Root", LocalRootCN).Run()
	_ = exec.Command("certutil", "-user", "-f", "-delstore", "Root", LocalRootCN).Run()

	fmt.Println("[*] Удаление промежуточных сертификатов Минцифры из хранилищ CA...")
	_ = exec.Command("certutil", "-f", "-delstore", "CA", "Russian Trusted Root CA").Run()
	_ = exec.Command("certutil", "-user", "-f", "-delstore", "CA", "Russian Trusted Root CA").Run()

	_ = exec.Command("certutil", "-f", "-delstore", "CA", "Russian Trusted Sub CA").Run()
	_ = exec.Command("certutil", "-user", "-f", "-delstore", "CA", "Russian Trusted Sub CA").Run()

	fmt.Println("[+] Сертификаты успешно удалены из хранилища Windows.")
	return nil
}

func CheckSystemStore() (StoreAuditResult, error) {
	var res StoreAuditResult

	if err := exec.Command("certutil", "-verifystore", "Root", LocalRootCN).Run(); err == nil {
		res.LocalRootInstalled = true
	} else if err := exec.Command("certutil", "-user", "-verifystore", "Root", LocalRootCN).Run(); err == nil {
		res.LocalRootInstalled = true
	}

	if err := exec.Command("certutil", "-verifystore", "Root", "Russian Trusted Root CA").Run(); err == nil {
		res.OrigRootInRootStore = true
	} else if err := exec.Command("certutil", "-user", "-verifystore", "Root", "Russian Trusted Root CA").Run(); err == nil {
		res.OrigRootInRootStore = true
	}

	if err := exec.Command("certutil", "-verifystore", "CA", "Russian Trusted Root CA").Run(); err == nil {
		res.CrossCertInstalled = true
	}
	if err := exec.Command("certutil", "-verifystore", "CA", "Russian Trusted Sub CA").Run(); err == nil {
		res.SubCertInstalled = true
	}

	return res, nil
}

func checkFirefox() {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return
	}
	ffDir := filepath.Join(appData, "Mozilla", "Firefox")
	if _, err := os.Stat(ffDir); err == nil {
		fmt.Println("\n[i] Внимание для пользователей Mozilla Firefox:")
		fmt.Println("    Firefox по умолчанию использует собственную базу сертификатов (NSS).")
		fmt.Println("    Чтобы Firefox подхватывал системные сертификаты Windows:")
		fmt.Println("    1. Откройте в Firefox страницу: about:config")
		fmt.Println("    2. Найдите параметр: security.enterprise_roots.enabled")
		fmt.Println("    3. Переключите его в: true")
	}
}

func CleanOriginalRoot() error {
	out1, err1 := exec.Command("certutil", "-f", "-delstore", "Root", "Russian Trusted Root CA").CombinedOutput()
	out2, _ := exec.Command("certutil", "-user", "-f", "-delstore", "Root", "Russian Trusted Root CA").CombinedOutput()
	if err1 != nil && !strings.Contains(string(out1), "0x80090011") && !strings.Contains(string(out2), "0x80090011") {
		return fmt.Errorf("ошибка удаления: %s", string(out1))
	}
	return nil
}
