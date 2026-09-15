package turn

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const captchaListenPort = "8765"

// VKCaptchaChallenge contains parsed VK captcha details.
type VKCaptchaChallenge struct {
	ErrorCode    int    `json:"error_code"`
	ErrorMsg     string `json:"error_msg"`
	RedirectURI  string `json:"redirect_uri"`
	SessionToken string `json:"session_token"`
	CaptchaSid   string `json:"captcha_sid"`
	CaptchaTs    string `json:"captcha_ts"`
}

// ParseCaptchaError checks if an API response object is a captcha challenge.
func ParseCaptchaError(errMap map[string]interface{}) *VKCaptchaChallenge {
	code, _ := errMap["error_code"].(float64)
	if code != 14 {
		return nil
	}

	msg, _ := errMap["error_msg"].(string)
	redirectURI, _ := errMap["redirect_uri"].(string)
	sid, _ := errMap["captcha_sid"].(string)
	ts, _ := errMap["captcha_ts"].(string)

	token := ""
	if redirectURI != "" {
		if u, err := neturl.Parse(redirectURI); err == nil {
			token = u.Query().Get("session_token")
		}
	}

	return &VKCaptchaChallenge{
		ErrorCode:    int(code),
		ErrorMsg:     msg,
		RedirectURI:  redirectURI,
		SessionToken: token,
		CaptchaSid:   sid,
		CaptchaTs:    ts,
	}
}

// SolveCaptchaViaBrowser spins up a local proxy server, opens the browser for the user to solve captcha, and captures the success token.
func SolveCaptchaViaBrowser(ctx context.Context, redirectURI string) (string, error) {
	parsedTarget, err := neturl.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect_uri: %w", err)
	}

	upstreamHost := parsedTarget.Host
	if upstreamHost == "" {
		upstreamHost = "id.vk.ru"
	}

	tokenChan := make(chan string, 1)
	errChan := make(chan error, 1)

	mux := http.NewServeMux()

	var srv *http.Server
	var once sync.Once

	finish := func(token string, err error) {
		once.Do(func() {
			if err != nil {
				errChan <- err
			} else {
				tokenChan <- token
			}
			go func() {
				time.Sleep(500 * time.Millisecond)
				if srv != nil {
					_ = srv.Shutdown(context.Background())
				}
			}()
		})
	}

	// Result endpoint that the injected JS calls when VK captcha passes
	mux.HandleFunc("/local-captcha-result", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		token := r.FormValue("token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token != "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html><body style="font-family:sans-serif;background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:90vh"><div style="text-align:center;background:rgba(255,255,255,0.05);padding:30px;border-radius:12px;border:1px solid rgba(255,255,255,0.1)"><h2>Капча пройдена!</h2><p style="color:#94a3b8">Можете закрыть это окно. Приложение подключается...</p></div></body></html>`))
			finish(token, nil)
			return
		}
		http.Error(w, "missing token", http.StatusBadRequest)
	})

	// Reverse proxy to VK Not Robot endpoint with JS injector
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		upstreamURL := fmt.Sprintf("https://%s%s", upstreamHost, r.URL.RequestURI())
		if r.URL.Path == "/" || r.URL.Path == "" {
			upstreamURL = redirectURI
		}

		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		for k, v := range r.Header {
			if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Accept-Encoding") {
				continue
			}
			req.Header[k] = v
		}
		req.Host = upstreamHost
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
		req.Header.Set("Origin", fmt.Sprintf("https://%s", upstreamHost))
		req.Header.Set("Referer", fmt.Sprintf("https://%s/", upstreamHost))
		req.Header.Set("sec-ch-ua", `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`)
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("sec-ch-ua-platform", `"Windows"`)

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if token := req.URL.Query().Get("success_token"); token != "" {
					finish(token, nil)
				}
				return nil
			},
			Timeout: 25 * time.Second,
		}

		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		for k, v := range resp.Header {
			if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Content-Security-Policy") {
				continue
			}
			for _, val := range v {
				w.Header().Add(k, val)
			}
		}

		// Inject token sniffer JS into HTML
		bodyStr := string(bodyBytes)
		if strings.Contains(bodyStr, "</head>") || strings.Contains(bodyStr, "</body>") {
			injectedScript := `
			<script>
			(function() {
				function notifySuccess(token) {
					fetch('/local-captcha-result?token=' + encodeURIComponent(token))
						.then(() => { window.close(); })
						.catch(() => {});
				}

				const origFetch = window.fetch;
				if (origFetch) {
					window.fetch = function(...args) {
						return origFetch.apply(this, args).then(res => {
							try {
								const clone = res.clone();
								clone.json().then(data => {
									if (data && data.response && data.response.success_token) {
										notifySuccess(data.response.success_token);
									}
								}).catch(()=>{});
							} catch(e){}
							return res;
						});
					};
				}

				setInterval(() => {
					const urlParams = new URLSearchParams(window.location.search);
					const token = urlParams.get('success_token') || urlParams.get('token');
					if (token) notifySuccess(token);
				}, 400);
			})();
			</script>
			`
			bodyStr = strings.Replace(bodyStr, "</head>", injectedScript+"</head>", 1)
		}

		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write([]byte(bodyStr))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:"+captchaListenPort)
	if err != nil {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", fmt.Errorf("failed to start captcha listener: %w", err)
		}
	}

	srv = &http.Server{
		Handler: mux,
	}

	go func() {
		_ = srv.Serve(listener)
	}()

	localPort := listener.Addr().(*net.TCPAddr).Port
	localURL := fmt.Sprintf("http://localhost:%d%s", localPort, parsedTarget.RequestURI())
	if parsedTarget.RequestURI() == "" || parsedTarget.RequestURI() == "/" {
		localURL = fmt.Sprintf("http://localhost:%d/?domain=vk.com", localPort)
	}

	log.Printf("[VK Captcha] Opening browser to solve captcha: %s", localURL)
	openBrowser(localURL)

	select {
	case token := <-tokenChan:
		log.Printf("[VK Captcha] Successfully solved! Token received.")
		return token, nil
	case err := <-errChan:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("решение капчи отменено (таймаут)")
	case <-time.After(90 * time.Second):
		return "", fmt.Errorf("превышено время ожидания решения капчи (90 сек)")
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
