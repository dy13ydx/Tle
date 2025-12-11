package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Define colors for better readability (works in most Linux terminals)
const (
	ColorReset  = "\033[0m"
	ColorGreen  = "\033[32m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
)

func main() {
	// 1. Define Command Line Flags
	targetIP := flag.String("t", "127.0.0.1", "The internal IP you want to scan via the proxy")
	proxyAddr := flag.String("x", "http://127.0.0.1:8080", "The Proxy URL (e.g., http://127.0.0.1:8080)")
	workers := flag.Int("w", 50, "Number of concurrent workers")
	portMax := flag.Int("max", 65535, "Maximum port number to scan (starts at 1)")
	
	// Custom usage message for -h
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Println("This tool scans an internal IP through a proxy (SSRF/Proxy scan).")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExample:")
		fmt.Printf("  go run %s -t 192.168.1.5 -x http://10.10.10.10:3128 -w 100\n", os.Args[0])
	}
	flag.Parse()

	// 2. Configure the Proxy Client
	pURL, err := url.Parse(*proxyAddr)
	if err != nil {
		fmt.Printf("%s[!] Error parsing proxy URL: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(pURL),
		// Optimization: Disable KeepAlives for scanning to free connections faster
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second, // Fast timeout
		}).DialContext,
	}

	// Create a client with a strict timeout
	client := &http.Client{
		Transport: transport,
		Timeout:   4 * time.Second,
	}

	fmt.Printf("%s[*] Starting scan against %s via %s%s\n", ColorYellow, *targetIP, *proxyAddr, ColorReset)
	fmt.Printf("[*] Workers: %d | Ports: 1-%d\n", *workers, *portMax)

	// 3. Concurrency Setup
	ports := make(chan int, *workers)
	var wg sync.WaitGroup
	openPorts := []int{}
	var mutex sync.Mutex // To safely append to openPorts

	// Start Workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ports {
				if scanPort(client, *targetIP, p) {
					mutex.Lock()
					openPorts = append(openPorts, p)
					// Print immediately when found
					fmt.Printf("\r%s[+] Port %d found!          %s\n", ColorGreen, p, ColorReset)
					mutex.Unlock()
				}
			}
		}()
	}

	// 4. Feed the workers
	// We use a separate goroutine to send numbers so the main thread can wait
	go func() {
		for i := 1; i <= *portMax; i++ {
			ports <- i
			// Simple progress indicator
			if i%500 == 0 {
				fmt.Printf("\r[*] Scanned %d/%d ports...", i, *portMax)
			}
		}
		close(ports)
	}()

	wg.Wait()
	fmt.Printf("\n%s[*] Scan Complete.%s\n", ColorYellow, ColorReset)
	
	if len(openPorts) == 0 {
		fmt.Println("No open ports found.")
	} else {
		fmt.Println("Open Ports List:", openPorts)
	}
}

// scanPort performs the HTTP request and checks logic
func scanPort(client *http.Client, target string, port int) bool {
	// Construct the URL to access THROUGH the proxy
	targetURL := fmt.Sprintf("http://%s:%d", target, port)

	// Create a request with Context (good practice)
	req, err := http.NewRequestWithContext(context.Background(), "GET", targetURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Read body to check for specific error messages
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	bodyStr := string(body)

	// LOGIC: If the proxy says "could not be retrieved", the port is likely CLOSED.
	// If that message is ABSENT, the port is likely OPEN (or returning something else).
	if strings.Contains(bodyStr, "The requested URL could not be retrieved") {
		return false
	}
	
	// Optional: Check for "Connection refused" if the proxy returns that text
	if strings.Contains(bodyStr, "Connection refused") {
		return false
	}

	return true
}
