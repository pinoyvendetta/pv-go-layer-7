--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Pinoy Vendetta - Go Layer 7 💣

**pv_http_pro** is a powerful and evasive Layer 7 stress testing tool written in Go. It simulates sophisticated, high-volume traffic to assess the performance, stability, and resilience of web servers and applications. Its key differentiator is the ability to automatically detect or specify and utilize multiple HTTP protocols (HTTP/1.1, HTTP/2, and HTTP/3) simultaneously, launching a comprehensive, multi-pronged attack.

## Key Features

  - **Multi-Protocol Attack Engine**: Automatically detects if a target supports HTTP/1.1, HTTP/2, and HTTP/3, then distributes workers to attack using all supported protocols concurrently. This maximizes stress on different parts of a server's network stack.
  - **HTTP/2 MadeYouReset Attack**: If HTTP/2 is detected, the tool automatically initiates a specialized MadeYouReset attack, rapidly opening and closing streams to exhaust server resources.
  - **Advanced Evasion Techniques**: Simulates realistic user traffic by randomizing:
      - User-Agents
      - **JA3/TLS Fingerprints** to bypass client fingerprinting
      - Source IPs (via X-Forwarded-For / X-Real-IP headers)
      - Request Paths and Query Parameters
      - HTTP Headers (Names and Values)
      - Browser Cookies
  - **Adaptive Learning Delay**: When enabled via a flag, it intelligently increases request delays when encountering specific blocking status codes (like 429, 403, etc.) and gradually reduces the delay as conditions improve, helping to bypass simple rate-limiting.
  - **Traffic Burst & Think Simulation**: Mimics realistic user behavior by sending high-volume bursts of requests followed by a variable "think time," creating unpredictable traffic patterns.
  - **Comprehensive Real-time Dashboard**: A clean, live-updating terminal dashboard displays key metrics, including:
      - Requests per second (RPS)
      - Average latency
      - Total requests and responses
      - Active HTTP versions
      - Detailed response status code counts
      - Live event log and error tracking
  - **Highly Configurable**: Control concurrency, duration, methods, and all evasive features through command-line flags.
![image](https://raw.githubusercontent.com/pinoyvendetta/pv-go-layer-7/refs/heads/main/img/pv-go-l7.png)
-----

## Prerequisites

1.  **Go**: You must have Go installed and configured on your system (version 1.18 or newer recommended). Download it from [golang.org](https://golang.org/).
2.  Install dependencies:
    ```bash
    go get github.com/fatih/color
    go get golang.org/x/net/http2
    go get github.com/quic-go/quic-go/http3
    go get github.com/refraction-networking/utls
    go get github.com/quic-go/quic-go@v0.37.6   (IMPORTANT, if you encounter quic-go or http3 error when compiling)
    ```

-----

## Compilation

To compile the tool, navigate to the directory containing `pv_http_pro.go` and run:

```bash
go build pv_http_pro.go
```

This will create an executable file named `pv_http_pro` (or `pv_http_pro.exe` on Windows).

-----

## Usage

Run the tool from your terminal, providing the target URL and any desired flags.

### Basic Syntax

```bash
./pv_http_pro --url <target_url> [OPTIONS]
```

### Command-line Flags

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--url` | **Required.** Target URL (e.g., [https://example.com](https://example.com)). | `""` |
| `--concurrency` | Total number of concurrent workers to run. | `100` |
| `--duration` | Test duration in minutes. | `5` |
| `--http-method` | Comma-separated HTTP methods to use. | `GET,POST` |
| `--port` | Target port (optional, overrides the port in the URL). | `""` |
| `--random-path` | Randomize request paths and add cache-busting queries. | `false` |
| `--burst` | Enable "Burst & Think" mode for more realistic traffic patterns. | `true` |
| `--burst-size` | Max number of requests per worker during a burst. | `15` |
| `--think-time` | Max "think time" (in ms) between bursts for a worker. | `7000` |
| `--jitter` | Maximum random delay (in ms) to add to each request's think time. | `50` |
| `--adaptive-delay`| Enable adaptive delay based on server responses (4xx/5xx status codes). | `false` |
| `--http-protocol` | Force attack using specified protocols (e.g., "2,3"), bypassing detection. | `""` (auto-detects) |

-----

## Examples

### Example 1: Standard 10-Minute Test

Run a 10-minute test against `https://api.example.com` with 250 concurrent workers. The tool will automatically detect and use all available HTTP protocols.

```bash
./pv_http_pro --url https://api.example.com --concurrency 250 --duration 10
```

### Example 2: Aggressive Test with Path Randomization

Run a very aggressive 30-minute test with 1000 workers, enabling path randomization to bypass caching layers.

```bash
./pv_http_pro --url https://www.example.com --concurrency 1000 --duration 30 --random-path=true
```

### Example 3: Focused POST Request Test

Run a 5-minute test using only POST methods, which can be more resource-intensive for a server to handle.

```bash
./pv_http_pro --url https://service.example.com/login --http-method POST --concurrency 150 --duration 5
```

### Example 4: Test with Adaptive Delay

Run a test against a target with rate-limiting, enabling adaptive delay to automatically adjust the request rate based on server feedback.

```bash
./pv_http_pro --url https://api.ratelimited.com --concurrency 200 --duration 15 --adaptive-delay=true
```

-----
## Cloudflare 403 Response Bypass ✅

![image](https://raw.githubusercontent.com/pinoyvendetta/pv-go-layer-7/refs/heads/main/img/cf-bypass.png)

## Disclaimer

This tool is intended for educational purposes and for authorized security testing and network stress analysis only. Using this tool against networks and servers without explicit permission is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
