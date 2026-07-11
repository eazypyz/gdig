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

// Pola Regex untuk mendeteksi file JS dan endpoints/secrets dasar
var (
	jsRegex       = regexp.MustCompile(`(?i)<script[^>]+src=["'](.*?\.js[^"']*)["']`)
	endpointRegex = regexp.MustCompile(`(?i)(?:https?://|/api/|/v1/)[a-zA-Z0-9./_-]+`)
	secretRegex   = regexp.MustCompile(`(?i)(?:api_key|token|bearer|secret)\s*[:=]\s*["']([^"']+)["']`)
)

func main() {
	// 1. Setup Flags
	targetURL := flag.String("u", "", "Target URL (contoh: https://example.com)")
	threads := flag.Int("t", 5, "Jumlah konkurensi / threads")
	silent := flag.Bool("s", false, "Silent mode (hanya menampilkan temuan, cocok untuk piping)")
	flag.Parse()

	if *targetURL == "" {
		fmt.Println("Gunakan flag -u untuk menentukan URL target. Contoh: gdig -u https://example.com")
		return
	}

	// 2. Konfigurasi HTTP Client
	// Mengabaikan error SSL/TLS (InsecureSkipVerify) agar tetap berjalan di target yang miskonfigurasi
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

	// 3. Ambil halaman utama
	body, err := fetchURL(client, *targetURL)
	if err != nil {
		if !*silent {
			fmt.Printf("[-] Gagal mengambil target utama: %v\n", err)
		}
		return
	}

	// 4. Ekstrak link JavaScript
	jsLinks := extractJSLinks(body, *targetURL)
	if !*silent {
		fmt.Printf("[+] Ditemukan %d file JavaScript eksternal.\n", len(jsLinks))
	}

	// Analisis halaman utama
	analyzeContent(body, *targetURL)

	// 5. Crawl dan Analisis JS secara Konkuren
	var wg sync.WaitGroup
	sem := make(chan struct{}, *threads) // Mengontrol jumlah goroutines (Rate limiting)

	for _, jsLink := range jsLinks {
		wg.Add(1)
		sem <- struct{}{} // Block jika channel penuh

		go func(link string) {
			defer wg.Done()
			defer func() { <-sem }() // Lepaskan slot setelah selesai

			jsBody, err := fetchURL(client, link)
			if err != nil {
				return // Abaikan error secara diam-diam agar tidak spamming terminal
			}
			analyzeContent(jsBody, link)
		}(jsLink)
	}

	wg.Wait()
}

// fetchURL melakukan HTTP GET request dengan custom User-Agent
func fetchURL(client *http.Client, target string) (string, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "gdig-recon-bot/1.0")

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

// extractJSLinks mencari tag <script src="..."> dan mengubahnya menjadi absolute URL
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
			// Resolusi relative path ke absolute URL
			parsedURL, err := url.Parse(jsPath)
			if err == nil {
				absoluteURL := base.ResolveReference(parsedURL).String()
				links = append(links, absoluteURL)
			}
		}
	}
	return links
}

// analyzeContent menjalankan engine regex untuk menemukan endpoint dan secrets
func analyzeContent(content string, source string) {
	// Mencari Endpoints
	endpoints := endpointRegex.FindAllString(content, -1)
	endpoints = uniqueStrings(endpoints)
	for _, ep := range endpoints {
		// Filter sederhana untuk membuang false positive (seperti URL W3C)
		if !strings.Contains(ep, "w3.org") {
			fmt.Printf("[ENDPOINT] %s -> %s\n", source, ep)
		}
	}

	// Mencari Secrets (Hardcoded tokens)
	secrets := secretRegex.FindAllStringSubmatch(content, -1)
	for _, secret := range secrets {
		if len(secret) > 1 {
			fmt.Printf("[SECRET] %s -> %s\n", source, secret[1])
		}
	}
}

// uniqueStrings menghapus duplikat dari array string
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
