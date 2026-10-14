package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

const appVersion = "1.1.0"

func main() {
	outDir := flag.String("out", "./certs_out", "Директория для сохранения сгенерированных сертификатов")
	install := flag.Bool("install", false, "Автоматически установить сертификаты в системное хранилище (требуются права Администратора/root)")
	uninstall := flag.Bool("uninstall", false, "Удалить установленные сертификаты из системы")
	verify := flag.Bool("verify", false, "Запустить полный аудит и криптографическую проверку изоляции (Name Constraints)")
	cleanOrig := flag.Bool("clean-orig", false, "Удалить оригинальный незащищенный корень Минцифры из хранилища 'Root'")
	domainsFlag := flag.String("domains", "", "Разрешенные доменные зоны через запятую (по умолчанию: ru, su, xn--p1ai (.рф))")
	rootURL := flag.String("root-url", DefaultRootCAURL, "URL для загрузки Root CA Минцифры")
	subURL := flag.String("sub-url", DefaultSubCAURL, "URL для загрузки Sub CA Минцифры")
	version := flag.Bool("version", false, "Показать версию утилиты")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "mindigital-cage v%s — Безопасная изоляция сертификатов Минцифры\n\n", appVersion)
		fmt.Fprintf(os.Stderr, "Использование:\n")
		fmt.Fprintf(os.Stderr, "  mindigital-cage [параметры]\n\n")
		fmt.Fprintf(os.Stderr, "Основные сценарии:\n")
		fmt.Fprintf(os.Stderr, "  1. Генерация и автоустановка в систему:\n")
		fmt.Fprintf(os.Stderr, "     mindigital-cage -install\n\n")
		fmt.Fprintf(os.Stderr, "  2. Проверка работы клетки и аудит безопасности:\n")
		fmt.Fprintf(os.Stderr, "     mindigital-cage -verify\n\n")
		fmt.Fprintf(os.Stderr, "  3. Полное удаление сертификатов из системы:\n")
		fmt.Fprintf(os.Stderr, "     mindigital-cage -uninstall\n\n")
		fmt.Fprintf(os.Stderr, "  4. Удаление только оригинального незащищенного корня Минцифры:\n")
		fmt.Fprintf(os.Stderr, "     mindigital-cage -clean-orig\n\n")
		fmt.Fprintf(os.Stderr, "Доступные флаги:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *version {
		fmt.Printf("mindigital-cage v%s (%s/%s)\n", appVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	if *uninstall {
		if err := UninstallCertificates(); err != nil {
			fatalf("Ошибка удаления сертификатов: %v", err)
		}
		return
	}

	if *cleanOrig {
		fmt.Println("[*] Очистка оригинального корня Минцифры из системного хранилища...")
		if err := CleanOriginalRoot(); err != nil {
			fatalf("Ошибка очистки оригинального корня: %v", err)
		}
		fmt.Println("[+] Оригинальный корень Минцифры успешно удален из хранилища 'Root'.")
		return
	}

	if *verify {
		if err := RunVerification(*outDir); err != nil {
			fatalf("Верификация завершилась с ошибкой: %v", err)
		}
		return
	}

	var permittedDomains []string
	if *domainsFlag != "" {
		permittedDomains = ParseDomains(*domainsFlag)
	} else {
		permittedDomains = DefaultPermittedDomains()
	}

	fmt.Printf("=== mindigital-cage v%s ===\n", appVersion)
	fmt.Printf("Разрешенные зоны (Name Constraints): %s\n\n", strings.Join(permittedDomains, ", "))

	res, err := GenerateCage(GenerateOptions{
		OutDir:           *outDir,
		PermittedDomains: permittedDomains,
		RootCAURL:        *rootURL,
		SubCAURL:         *subURL,
	})
	if err != nil {
		fatalf("Ошибка генерации клетки: %v", err)
	}

	fmt.Printf("\n[+] Сертификаты успешно сгенерированы и сохранены в %s:\n", *outDir)
	fmt.Printf("    1. %s\n       -> Ставить в Доверенные корневые центры сертификации (Root)\n", res.LocalRootPath)
	fmt.Printf("    2. %s\n       -> Ставить в Промежуточные центры сертификации (CA)\n", res.CrossCertPath)
	fmt.Printf("    3. %s\n       -> Ставить в Промежуточные центры сертификации (CA)\n", res.SubCertPath)
	fmt.Printf("    4. %s\n       -> Оригинал Минцифры (бэкап, НЕ устанавливать!)\n", res.OrigRootBackup)

	if *install {
		fmt.Printf("\n[*] Запуск автоматической установки в систему (%s)...\n", runtime.GOOS)
		if err := InstallCertificates(res.LocalRootPath, res.CrossCertPath, res.SubCertPath); err != nil {
			fatalf("Ошибка установки: %v", err)
		}
		fmt.Println("\n[*] Запуск проверки установленной цепочки...")
		_ = RunVerification(*outDir)
	} else {
		fmt.Println("\n[i] Сертификаты готовы! Чтобы установить их в систему автоматически, выполните:")
		fmt.Println("    mindigital-cage -install    (от имени Администратора/root)")
		fmt.Println("\n[i] Или запустите проверку:")
		fmt.Println("    mindigital-cage -verify")
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\n[!] "+format+"\n", args...)
	os.Exit(1)
}
