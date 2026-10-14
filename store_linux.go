//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type StoreAuditResult struct {
	LocalRootInstalled  bool
	OrigRootInRootStore bool
	CrossCertInstalled  bool
	SubCertInstalled    bool
	Notes               []string
}

const (
	p11AnchorsDir    = "/etc/ca-certificates/trust-source/anchors"
	debianCertsDir   = "/usr/local/share/ca-certificates"
	fedoraAnchorsDir = "/etc/pki/ca-trust/source/anchors"
)

func InstallCertificates(localRootPath, crossPath, subPath string) error {
	targetDir := ""
	if _, err := os.Stat(p11AnchorsDir); err == nil {
		targetDir = p11AnchorsDir
	} else if _, err := os.Stat(fedoraAnchorsDir); err == nil {
		targetDir = fedoraAnchorsDir
	}

	if targetDir != "" {
		fmt.Printf("[*] Обнаружена система с p11-kit / ca-trust (%s)...\n", targetDir)
		if err := copyFile(localRootPath, filepath.Join(targetDir, "local_restricted_root.crt")); err != nil {
			return err
		}
		if err := copyFile(crossPath, filepath.Join(targetDir, "mindigital_cross_ca.crt")); err != nil {
			return err
		}

		if _, err := exec.LookPath("trust"); err == nil {
			if out, err := exec.Command("trust", "extract-compat").CombinedOutput(); err != nil {
				return fmt.Errorf("ошибка trust extract-compat: %w (%s)", err, string(out))
			}
		} else if _, err := exec.LookPath("update-ca-trust"); err == nil {
			if out, err := exec.Command("update-ca-trust").CombinedOutput(); err != nil {
				return fmt.Errorf("ошибка update-ca-trust: %w (%s)", err, string(out))
			}
		}
		fmt.Println("[+] Системное хранилище сертификатов Linux успешно обновлено!")
		return nil
	}

	if _, err := os.Stat(debianCertsDir); err == nil {
		fmt.Printf("[*] Обнаружена система Debian/Ubuntu (%s)...\n", debianCertsDir)
		if err := copyFile(localRootPath, filepath.Join(debianCertsDir, "local_restricted_root.crt")); err != nil {
			return err
		}
		if err := copyFile(crossPath, filepath.Join(debianCertsDir, "mindigital_cross_ca.crt")); err != nil {
			return err
		}

		if out, err := exec.Command("update-ca-certificates").CombinedOutput(); err != nil {
			return fmt.Errorf("ошибка update-ca-certificates: %w (%s)", err, string(out))
		}
		fmt.Println("[+] Системное хранилище сертификатов Linux успешно обновлено!")
		return nil
	}

	return fmt.Errorf("не удалось автоматически определить систему сертификатов Linux. Скопируйте 1_local_restricted_root.crt и 2_mindigital_cross_ca.crt вручную")
}

func UninstallCertificates() error {
	removed := false

	for _, dir := range []string{p11AnchorsDir, fedoraAnchorsDir} {
		if _, err := os.Stat(dir); err == nil {
			_ = os.Remove(filepath.Join(dir, "local_restricted_root.crt"))
			_ = os.Remove(filepath.Join(dir, "mindigital_cross_ca.crt"))
			_ = os.Remove(filepath.Join(dir, "mindigital_sub_ca.crt")) // на случай старых установок
			if _, err := exec.LookPath("trust"); err == nil {
				_ = exec.Command("trust", "extract-compat").Run()
			} else if _, err := exec.LookPath("update-ca-trust"); err == nil {
				_ = exec.Command("update-ca-trust").Run()
			}
			removed = true
		}
	}

	if _, err := os.Stat(debianCertsDir); err == nil {
		_ = os.Remove(filepath.Join(debianCertsDir, "local_restricted_root.crt"))
		_ = os.Remove(filepath.Join(debianCertsDir, "mindigital_cross_ca.crt"))
		_ = os.Remove(filepath.Join(debianCertsDir, "mindigital_sub_ca.crt"))
		_ = exec.Command("update-ca-certificates", "--fresh").Run()
		removed = true
	}

	if !removed {
		return fmt.Errorf("не найдены стандартные каталоги ca-certificates для удаления")
	}

	fmt.Println("[+] Сертификаты клетки удалены из системы Linux.")
	return nil
}

func CheckSystemStore() (StoreAuditResult, error) {
	var res StoreAuditResult

	checkPaths := []string{
		filepath.Join(p11AnchorsDir, "local_restricted_root.crt"),
		filepath.Join(debianCertsDir, "local_restricted_root.crt"),
		filepath.Join(fedoraAnchorsDir, "local_restricted_root.crt"),
	}
	for _, p := range checkPaths {
		if _, err := os.Stat(p); err == nil {
			res.LocalRootInstalled = true
			break
		}
	}

	badPaths := []string{
		filepath.Join(p11AnchorsDir, "russian_trusted_root_ca.crt"),
		filepath.Join(debianCertsDir, "russian_trusted_root_ca.crt"),
		filepath.Join(debianCertsDir, "mindigital_sub_ca.crt"),
		filepath.Join(p11AnchorsDir, "mindigital_sub_ca.crt"),
	}
	for _, p := range badPaths {
		if _, err := os.Stat(p); err == nil {
			res.OrigRootInRootStore = true
			break
		}
	}

	return res, nil
}

func CleanOriginalRoot() error {
	badPaths := []string{
		filepath.Join(p11AnchorsDir, "russian_trusted_root_ca.crt"),
		filepath.Join(debianCertsDir, "russian_trusted_root_ca.crt"),
		filepath.Join(debianCertsDir, "mindigital_sub_ca.crt"),
		filepath.Join(p11AnchorsDir, "mindigital_sub_ca.crt"),
	}
	for _, p := range badPaths {
		_ = os.Remove(p)
	}
	_ = exec.Command("update-ca-certificates", "--fresh").Run()
	_ = exec.Command("trust", "extract-compat").Run()
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("ошибка чтения %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return fmt.Errorf("ошибка записи в %s (требуется sudo): %w", dst, err)
	}
	return nil
}
