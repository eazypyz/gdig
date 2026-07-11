package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Struktur untuk mendefinisikan aturan deteksi secret yang lebih spesifik
type SecretRule struct {
	Name  string
	Regex *regexp.Regexp
}

// Ruleset regex yang diinspirasi dari pola kredensial spesifik layanan.
// Mengakomodasi token format tunggal tanpa identifier (single-value token).
var secretRules = []SecretRule{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9]{10,48}`)},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36}`)},
	{"Stripe Live Key", regexp.MustCompile(`(?:r|s)k_live_[0-9a-zA-Z]{24}`)},
	{"HackerOne API Token", regexp.MustCompile(`(?i)(?:hackerone|h1).*(?:token|api)\s*[:=]\s*["']([a-zA-Z0-9_-]{32,})["']`)},
	{"Twilio API Key", regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
	// Fallback generik jika tidak cocok dengan pola spesifik di atas
	{"Generic Secret", regexp.MustCompile(`(?i)(?:api_key|token|bearer|secret)\s*[:=]\s*["']([^"']+)["']`)},
}

// Pola Regex untuk JS dan Endpoints
var (
	jsRegex       = regexp.MustCompile(`(?i)<script[^>]+src=["'](.*?\.js[^"']*)["']`)
	endpointRegex = regexp.MustCompile(`(?i)(?:https?://|/api/|/v1/)[a-zA-Z0-9./_-]+`)
)

func main() {
	targetURL := flag.String("u", "", "Target URL (contoh: https://example.com)")
	threads := flag.Int("t", 5, "Jumlah konkurensi / threads")
	silent := flag.Bool("s", false, "Silent mode (hanya menampilkan temuan, cocok untuk piping)")
	flag.Parse()

	if *targetURL == "" {
		fmt.Println("Gunakan flag -u untuk menentukan URL target.")
		return
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	if !*silent {
		fmt.Printf("[*] Memulai gdig untuk target: %s\n", *targetURL)
	}

	body, err := fetchURL(client, *targetURL)
	if err != nil {
		if !*silent {
			fmt.Printf("[-] Gagal mengambil target utama: %v\n", err)
		}
		return
	}

	jsLinks := extractJSLinks(body, *targetURL)
	if !*silent {
		fmt.Printf("[+] Ditemukan %d file JavaScript eksternal.\n", len(jsLinks))
	}

	analyzeContent(body, *targetURL)

	var wg sync.WaitGroup
	sem := make(chan struct{}, *threads) 

	for _, jsLink := range jsLinks {
		wg.Add(1)
		sem <- struct{}{} 

		go func(link string) {
			defer wg.Done()
			defer func() { <-sem }() 

			jsBody, err := fetchURL(client, link)
			if err != nil {
				return
			}
			analyzeContent(jsBody, link)
		}(jsLink)
	}

	wg.Wait()
}

func fetchURL(client *http.Client, target string) (string, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "gdig-recon-bot/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

func extractJSLinks(html string, baseURL string) []string {
	var links []string
	matches := jsRegex.FindAllStringSubmatch(html, -1)
	
	base, err := url.Parse(baseURL)
	if err != nil {
		return links
	}

	for _, match := range matches {
		if len(match) > 1 {
			jsPath := match[1]
			parsedURL, err := url.Parse(jsPath)
			if err == nil {
				absoluteURL := base.ResolveReference(parsedURL).String()
				links = append(links, absoluteURL)
			}
		}
	}
	return links
}

func analyzeContent(content string, source string) {
	// 1. Mencari Endpoints
	endpoints := endpointRegex.FindAllString(content, -1)
	endpoints = uniqueStrings(endpoints)
	for _, ep := range endpoints {
		if !strings.Contains(ep, "w3.org") {
			fmt.Printf("[ENDPOINT] %s -> %s\n", source, ep)
		}
	}

	// 2. Mencari Secrets berdasarkan Ruleset Keyhacks
	for _, rule := range secretRules {
		matches := rule.Regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			secretVal := match[0]
			if len(match) > 1 {
				// Jika ada capture group, ekstrak nilai murninya saja
				secretVal = match[1] 
			}
			// Hasil output terstruktur berdasarkan nama layanan
			fmt.Printf("[SECRET] [%s] %s -> %s\n", rule.Name, source, secretVal)
		}
	}
}

func uniqueStrings(input []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range input {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
