package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
)

const appVersion = "1.0.0"

func main() {
	outDir := flag.String("out", "./certs_out", "Директория для сохранения сгенерированных сертификатов")
	install := flag.Bool("install", false, "Установить сертификаты в системное хранилище (требуется sudo / Администратор)")
	uninstall := flag.Bool("uninstall", false, "Удалить установленные сертификаты из системы")
	verify := flag.Bool("verify", false, "Проверить изоляцию сертификатов и хранилище ОС")
	cleanOrig := flag.Bool("clean-orig", false, "Удалить оригинальный незащищенный корень Минцифры из хранилища 'Root'")
	domainsFlag := flag.String("domains", "", "Разрешенные доменные зоны через запятую (по умолчанию: ru, su, xn--p1ai)")
	rootURL := flag.String("root-url", DefaultRootCAURL, "URL для загрузки Root CA Минцифры")
	subURL := flag.String("sub-url", DefaultSubCAURL, "URL для загрузки Sub CA Минцифры")
	version := flag.Bool("version", false, "Показать версию утилиты")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "mindigital-cage v%s — Изоляция сертификатов Минцифры (Name Constraints)\n\n", appVersion)
		fmt.Fprintf(os.Stderr, "Использование:\n")
		fmt.Fprintf(os.Stderr, "  mindigital-cage -install     Установить изолированные сертификаты в систему\n")
		fmt.Fprintf(os.Stderr, "  mindigital-cage -verify      Проверить работу изоляции и хранилище\n")
		fmt.Fprintf(os.Stderr, "  mindigital-cage -uninstall   Удалить сертификаты из системы\n")
		fmt.Fprintf(os.Stderr, "  mindigital-cage -clean-orig  Удалить незащищенный оригинал Минцифры\n\n")
		fmt.Fprintf(os.Stderr, "Флаги:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *version {
		fmt.Printf("mindigital-cage v%s (%s/%s)\n", appVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	if *uninstall {
		if err := UninstallCertificates(); err != nil {
			fatalf("Ошибка удаления: %v", err)
		}
		fmt.Println("[+] Сертификаты успешно удалены из системы.")
		return
	}

	if *cleanOrig {
		if err := CleanOriginalRoot(); err != nil {
			fatalf("Ошибка очистки: %v", err)
		}
		fmt.Println("[+] Оригинальный корень Минцифры удален из хранилища 'Root'.")
		return
	}

	if *verify {
		if err := RunVerification(*outDir); err != nil {
			fatalf("Ошибка верификации: %v", err)
		}
		return
	}

	var permittedDomains []string
	if *domainsFlag != "" {
		permittedDomains = ParseDomains(*domainsFlag)
	} else {
		permittedDomains = DefaultPermittedDomains()
	}

	fmt.Println("[*] Загрузка и выпуск изолированных сертификатов...")
	res, err := GenerateCage(GenerateOptions{
		OutDir:           *outDir,
		PermittedDomains: permittedDomains,
		RootCAURL:        *rootURL,
		SubCAURL:         *subURL,
	})
	if err != nil {
		fatalf("Ошибка генерации: %v", err)
	}

	if *install {
		fmt.Println("[*] Установка в системное хранилище...")
		if err := InstallCertificates(res.LocalRootPath, res.CrossCertPath, res.SubCertPath); err != nil {
			fatalf("Ошибка установки: %v", err)
		}
		fmt.Println("[+] Сертификаты Минцифры успешно изолированы и установлены в систему.")
	} else {
		fmt.Printf("[+] Сертификаты сохранены в %s\n", *outDir)
		fmt.Println("[i] Для установки в систему запустите:  mindigital-cage -install")
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
	os.Exit(1)
}
