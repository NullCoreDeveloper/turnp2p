package turn

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const captchaListenPort = "8765"

type browserCommand struct {
	name string
	args []string
}

// VKCaptchaChallenge contains parsed VK captcha details.
type VKCaptchaChallenge struct {
	ErrorCode      int    `json:"error_code"`
	ErrorMsg       string `json:"error_msg"`
	RedirectURI    string `json:"redirect_uri"`
	SessionToken   string `json:"session_token"`
	CaptchaSid     string `json:"captcha_sid"`
	CaptchaTs      string `json:"captcha_ts"`
	CaptchaAttempt string `json:"captcha_attempt"`
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
	attempt, _ := errMap["captcha_attempt"].(string)
	if attempt == "" || attempt == "0" {
		attempt = "1"
	}

	token := ""
	if redirectURI != "" {
		if u, err := neturl.Parse(redirectURI); err == nil {
			token = u.Query().Get("session_token")
		}
	}

	return &VKCaptchaChallenge{
		ErrorCode:      int(code),
		ErrorMsg:       msg,
		RedirectURI:    redirectURI,
		SessionToken:   token,
		CaptchaSid:     sid,
		CaptchaTs:      ts,
		CaptchaAttempt: attempt,
	}
}

func localCaptchaOrigin() string {
	return "http://localhost:" + captchaListenPort
}

func localCaptchaListenAddrs() []string {
	return []string{
		"127.0.0.1:" + captchaListenPort,
		"[::1]:" + captchaListenPort,
	}
}

func localCaptchaHosts() []string {
	return []string{
		"localhost:" + captchaListenPort,
		"127.0.0.1:" + captchaListenPort,
		"[::1]:" + captchaListenPort,
	}
}

func isLocalCaptchaHost(host string) bool {
	for _, localHost := range localCaptchaHosts() {
		if strings.EqualFold(host, localHost) {
			return true
		}
	}
	return false
}

func localCaptchaURLForTarget(targetURL *neturl.URL) string {
	localURL := &neturl.URL{
		Scheme:   "http",
		Host:     "localhost:" + captchaListenPort,
		Path:     targetURL.Path,
		RawPath:  targetURL.RawPath,
		RawQuery: targetURL.RawQuery,
	}
	if localURL.Path == "" {
		localURL.Path = "/"
	}
	return localURL.String()
}

func targetOrigin(targetURL *neturl.URL) string {
	return targetURL.Scheme + "://" + targetURL.Host
}

func isSafeLocalRedirectPath(raw string) bool {
	if raw == "" || raw[0] != '/' {
		return false
	}
	if len(raw) > 1 && (raw[1] == '/' || raw[1] == '\\') {
		return false
	}
	return true
}

func rewriteProxyRedirectLocation(raw string, targetURL *neturl.URL) (string, bool) {
	if isSafeLocalRedirectPath(raw) {
		return raw, true
	}

	parsed, err := neturl.Parse(raw)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, targetURL.Scheme) || !strings.EqualFold(parsed.Host, targetURL.Host) {
		return "", false
	}

	return localCaptchaURLForTarget(parsed), true
}

func rewriteProxyHeaderURL(raw string, targetURL *neturl.URL) string {
	if raw == "" {
		return raw
	}
	parsed, err := neturl.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.Scheme != "http" || !isLocalCaptchaHost(parsed.Host) {
		return raw
	}
	parsed.Scheme = targetURL.Scheme
	parsed.Host = targetURL.Host
	return parsed.String()
}

func rewriteProxyRequest(req *http.Request, targetURL *neturl.URL) {
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	if req.URL.Path == "" {
		req.URL.Path = targetURL.Path
	}
	req.Host = targetURL.Host

	// If request is calling VK API method (/method/...), route to api.vk.ru (or api.vk.com)
	if strings.HasPrefix(req.URL.Path, "/method/") {
		apiHost := "api.vk.ru"
		if strings.HasSuffix(targetURL.Host, ".com") {
			apiHost = "api.vk.com"
		}
		req.URL.Host = apiHost
		req.Host = apiHost
	}

	req.Header.Del("Accept-Encoding")
	req.Header.Del("TE")
	for _, headerName := range []string{"Origin", "Referer"} {
		if rewritten := rewriteProxyHeaderURL(req.Header.Get(headerName), targetURL); rewritten != "" {
			req.Header.Set(headerName, rewritten)
		} else {
			req.Header.Del(headerName)
		}
	}
}

func extractSuccessToken(body []byte) string {
	var payload struct {
		Response struct {
			SuccessToken string `json:"success_token"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.Response.SuccessToken
}

func rewriteProxyCookies(header http.Header) {
	cookies := (&http.Response{Header: header}).Cookies()
	if len(cookies) == 0 {
		return
	}
	header.Del("Set-Cookie")
	for _, cookie := range cookies {
		cookie.Domain = ""
		cookie.Secure = false
		cookie.Partitioned = false
		if cookie.SameSite == http.SameSiteNoneMode || cookie.SameSite == http.SameSiteStrictMode {
			cookie.SameSite = http.SameSiteLaxMode
		}
		header.Add("Set-Cookie", cookie.String())
	}
}

func rewriteCaptchaHTML(html string, targetURL *neturl.URL) string {
	localOrigin := localCaptchaOrigin()
	upstreamOrigin := targetOrigin(targetURL)
	html = strings.ReplaceAll(html, upstreamOrigin, localOrigin)

	script := fmt.Sprintf(`
<script>
(function() {
    var localOrigin = %q;
    var upstreamOrigin = %q;

    // Mask webdriver flag
    try {
        Object.defineProperty(navigator, 'webdriver', {
            get: function() { return false; }
        });
    } catch (e) {}

    function rewriteUrl(urlStr) {
        if (!urlStr || typeof urlStr !== 'string') return urlStr;
        if (urlStr.indexOf(localOrigin) === 0) return urlStr;
        if (urlStr.indexOf(upstreamOrigin) === 0) return localOrigin + urlStr.slice(upstreamOrigin.length);
        if (urlStr.indexOf('https://api.vk.ru') === 0) return localOrigin + urlStr.slice(17);
        if (urlStr.indexOf('https://api.vk.com') === 0) return localOrigin + urlStr.slice(18);
        return urlStr;
    }

    var autoClickInterval = null;

    function handleSuccessToken(token) {
        if (!token) return;
        if (autoClickInterval) clearInterval(autoClickInterval);
        fetch('/local-captcha-result', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'token=' + encodeURIComponent(token)
        }).then(function() {
            document.body.innerHTML = '<h2 style="text-align:center;margin-top:20vh;color:#22c55e">Капча успешно пройдена!</h2>';
            setTimeout(function() { window.close(); }, 300);
        }).catch(function() {});
    }

    var origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function() {
        if (arguments[1] && typeof arguments[1] === 'string') {
            this._origUrl = arguments[1];
            arguments[1] = rewriteUrl(arguments[1]);
        }
        return origOpen.apply(this, arguments);
    };

    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {
        var xhr = this;
        if (this._origUrl && this._origUrl.indexOf('captchaNotRobot.check') !== -1) {
            xhr.addEventListener('load', function() {
                try {
                    var data = JSON.parse(xhr.responseText);
                    if (data.response && data.response.success_token) {
                        handleSuccessToken(data.response.success_token);
                    }
                } catch (e) {}
            });
        }
        return origSend.apply(this, arguments);
    };

    var origFetch = window.fetch;
    if (origFetch) {
        window.fetch = function() {
            var url = arguments[0];
            var isObj = (typeof url === 'object' && url && url.url);
            var urlStr = isObj ? url.url : url;
            var origUrlStr = urlStr;

            if (typeof urlStr === 'string') {
                urlStr = rewriteUrl(urlStr);
                arguments[0] = urlStr;
            }

            var p = origFetch.apply(this, arguments);
            if (typeof origUrlStr === 'string' && origUrlStr.indexOf('captchaNotRobot.check') !== -1) {
                p.then(function(response) {
                    return response.clone().json();
                }).then(function(data) {
                    if (data.response && data.response.success_token) {
                        handleSuccessToken(data.response.success_token);
                    }
                }).catch(function() {});
            }
            return p;
        };
    }

    // Auto-clicker: clicks the "I am not a robot" checkbox once page finishes initial render
    function tryAutoClick() {
        var el = document.querySelector('input[type="checkbox"]') ||
                 document.querySelector('.Checkbox__input') ||
                 document.querySelector('[role="checkbox"]') ||
                 document.querySelector('.vkuiCheckbox') ||
                 document.querySelector('div[class*="Checkbox"]') ||
                 document.querySelector('svg[class*="Checkbox"]') ||
                 document.querySelector('[class*="notRobotCheckbox"]');
        if (el) {
            var target = el.closest('label') || el;
            var rect = target.getBoundingClientRect();
            var cx = rect.left + rect.width / 2;
            var cy = rect.top + rect.height / 2;

            target.dispatchEvent(new PointerEvent('pointermove', {bubbles: true, cancelable: true, clientX: cx, clientY: cy}));
            target.dispatchEvent(new MouseEvent('mousemove', {bubbles: true, cancelable: true, clientX: cx, clientY: cy}));
            target.dispatchEvent(new PointerEvent('pointerdown', {bubbles: true, cancelable: true, clientX: cx, clientY: cy}));
            target.dispatchEvent(new MouseEvent('mousedown', {bubbles: true, cancelable: true, clientX: cx, clientY: cy}));
            setTimeout(function() {
                target.dispatchEvent(new PointerEvent('pointerup', {bubbles: true, cancelable: true, clientX: cx, clientY: cy}));
                target.dispatchEvent(new MouseEvent('mouseup', {bubbles: true, cancelable: true, clientX: cx, clientY: cy}));
                target.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true, clientX: cx, clientY: cy}));
                if (target.click) target.click();
            }, 60);
            return true;
        }
        return false;
    }

    // Continuously check and trigger checkbox click until success_token is caught
    setTimeout(function() {
        var attempts = 0;
        autoClickInterval = setInterval(function() {
            attempts++;
            tryAutoClick();
            if (attempts > 30) {
                clearInterval(autoClickInterval);
            }
        }, 400);
    }, 400);
})();
</script>
`, localOrigin, upstreamOrigin)

	switch {
	case strings.Contains(html, "</head>"):
		return strings.Replace(html, "</head>", script+"</head>", 1)
	case strings.Contains(html, "</body>"):
		return strings.Replace(html, "</body>", script+"</body>", 1)
	default:
		return html + script
	}
}

func newCaptchaProxyTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}
}

func startCaptchaServer(srv *http.Server, logPrefix string) error {
	var listenErrs []string
	var listening bool

	for _, addr := range localCaptchaListenAddrs() {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			listenErrs = append(listenErrs, fmt.Sprintf("%s (%v)", addr, err))
			continue
		}
		listening = true
		go func(l net.Listener) {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("%s: %s", logPrefix, err)
			}
		}(listener)
	}

	if listening {
		return nil
	}

	return fmt.Errorf("captcha listeners failed: %s", strings.Join(listenErrs, "; "))
}

// SolveCaptchaViaBrowser opens local reverse proxy and browser for manual VK verification.
func SolveCaptchaViaBrowser(ctx context.Context, redirectURI string) (string, error) {
	keyCh := make(chan string, 1)

	targetURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %v", err)
	}

	transport := newCaptchaProxyTransport()

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			rewriteProxyRequest(req.Out, targetURL)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[Captcha Proxy] ERROR for %s %s: %v", r.Method, r.URL.String(), err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;padding:20px"><h2>Captcha proxy error</h2><p>%s %s</p><p>%v</p></body></html>`, r.Method, r.URL.String(), err)
		},
		ModifyResponse: func(res *http.Response) error {
			rewriteProxyCookies(res.Header)
			res.Header.Set("Access-Control-Allow-Origin", "*")
			res.Header.Set("Access-Control-Allow-Credentials", "true")

			if res.StatusCode >= 300 && res.StatusCode < 400 {
				if loc := res.Header.Get("Location"); loc != "" {
					log.Printf("[Captcha Proxy] Redirecting to: %s", loc)
					if rewritten, ok := rewriteProxyRedirectLocation(loc, targetURL); ok {
						res.Header.Set("Location", rewritten)
					} else {
						res.Header.Del("Location")
					}
				}
			}

			contentType := res.Header.Get("Content-Type")
			contentEncoding := res.Header.Get("Content-Encoding")
			log.Printf("[Captcha Proxy] %s %d | Content-Type: %q, Encoding: %q", res.Request.Method, res.StatusCode, contentType, contentEncoding)

			shouldInspectBody := strings.Contains(contentType, "text/html") ||
				strings.Contains(contentType, "application/xhtml+xml") ||
				strings.Contains(res.Request.URL.Path, "captchaNotRobot.check")

			if !shouldInspectBody {
				return nil
			}

			reader := res.Body
			if res.Header.Get("Content-Encoding") == "gzip" {
				gzReader, err := gzip.NewReader(res.Body)
				if err == nil {
					reader = gzReader
					defer func() {
						if err := gzReader.Close(); err != nil {
							log.Printf("failed to close gzip reader: %v", err)
						}
					}()
				}
			}

			bodyBytes, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			if err := res.Body.Close(); err != nil {
				return err
			}

			if strings.Contains(res.Request.URL.Path, "captchaNotRobot.check") {
				log.Printf("[Captcha Proxy] RAW check response: %s", string(bodyBytes))
				token := extractSuccessToken(bodyBytes)
				if token != "" {
					log.Printf("[Captcha Proxy] Extracted success_token: %s", token)
					select {
					case keyCh <- token:
					default:
					}
				} else {
					log.Printf("[Captcha Proxy] Warning: no success_token found in check response")
				}
			}

			if strings.Contains(contentType, "text/html") {
				for _, headerName := range []string{
					"Content-Security-Policy",
					"Content-Security-Policy-Report-Only",
					"X-Content-Security-Policy",
					"X-WebKit-CSP",
					"Cross-Origin-Opener-Policy",
					"Cross-Origin-Embedder-Policy",
					"Cross-Origin-Resource-Policy",
					"X-Frame-Options",
					"Strict-Transport-Security",
					"Alt-Svc",
				} {
					res.Header.Del(headerName)
				}

				bodyBytes = []byte(rewriteCaptchaHTML(string(bodyBytes), targetURL))
				res.Header.Del("Content-Encoding")
			}

			res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			res.ContentLength = int64(len(bodyBytes))
			res.Header.Set("Content-Length", fmt.Sprint(len(bodyBytes)))

			return nil
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/local-captcha-result", func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		if token != "" {
			select {
			case keyCh <- token:
			default:
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = fmt.Fprint(w, "ok")
	})

	mux.HandleFunc("/generic_proxy", func(w http.ResponseWriter, r *http.Request) {
		targetAuthURL := r.URL.Query().Get("proxy_url")
		targetParsed, err := neturl.Parse(targetAuthURL)
		if err != nil || targetParsed.Host == "" || targetParsed.Hostname() == "0.0.0.0" {
			http.Error(w, "Bad URL", http.StatusBadRequest)
			return
		}
		genericReverse := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(req *httputil.ProxyRequest) {
				req.Out.URL.Path = targetParsed.Path
				req.Out.URL.RawQuery = targetParsed.RawQuery
				rewriteProxyRequest(req.Out, targetParsed)
			},
		}
		genericReverse.ServeHTTP(w, r)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[Captcha Proxy] HTTP %s %s", r.Method, r.URL.String())
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/" && targetURL.Path != "" && targetURL.Path != "/" && r.URL.RawQuery == "" {
			log.Printf("[Captcha Proxy] Redirecting ROOT to: %s", localCaptchaURLForTarget(targetURL))
			http.Redirect(w, r, localCaptchaURLForTarget(targetURL), http.StatusTemporaryRedirect)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	srv := &http.Server{Handler: mux}
	if err := startCaptchaServer(srv, "[Captcha Server]"); err != nil {
		return "", err
	}

	captchaURL := localCaptchaURLForTarget(targetURL)
	log.Printf("[VK Captcha] Opening browser to solve captcha: %s", captchaURL)
	openBrowser(captchaURL)

	select {
	case token := <-keyCh:
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
		return token, nil
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
		return "", ctx.Err()
	}
}

func openBrowser(url string) {
	if openHeadlessBrowser(url) {
		return
	}
	for _, cmd := range browserOpenCommands(runtime.GOOS, url) {
		if err := exec.Command(cmd.name, cmd.args...).Start(); err == nil {
			return
		}
	}
}

func openHeadlessBrowser(url string) bool {
	userDataDir, err := os.MkdirTemp("", "turnp2p-chrome-*")
	if err != nil {
		userDataDir = "/tmp/turnp2p-chrome-tmp"
	}

	commonFlags := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-blink-features=AutomationControlled",
		"--disable-web-security",
		"--allow-running-insecure-content",
		"--window-size=1280,800",
		"--user-data-dir=" + userDataDir,
	}

	candidates := getBrowserCandidates()

	for _, bin := range candidates {
		args := append([]string{}, commonFlags...)
		args = append(args, url)
		cmd := exec.Command(bin, args...)
		setSysProcAttr(cmd)
		if err := cmd.Start(); err == nil {
			log.Printf("[VK Captcha] Запущен фоновый headless браузер: %s", bin)
			go func(p *os.Process, dir string) {
				time.Sleep(20 * time.Second)
				_ = p.Kill()
				_ = os.RemoveAll(dir)
			}(cmd.Process, userDataDir)
			return true
		}
	}
	return false
}

func browserOpenCommands(goos string, url string) []browserCommand {
	switch goos {
	case "windows":
		return []browserCommand{{name: "cmd", args: []string{"/c", "start", url}}}
	case "darwin":
		return []browserCommand{{name: "open", args: []string{url}}}
	case "linux":
		return []browserCommand{
			{name: "xdg-open", args: []string{url}},
			{name: "gio", args: []string{"open", url}},
		}
	case "android":
		return []browserCommand{
			{name: "termux-open-url", args: []string{url}},
			{name: "/system/bin/am", args: []string{"start", "-a", "android.intent.action.VIEW", "-d", url}},
			{name: "am", args: []string{"start", "-a", "android.intent.action.VIEW", "-d", url}},
			{name: "xdg-open", args: []string{url}},
		}
	case "ios":
		return []browserCommand{
			{name: "open", args: []string{url}},
			{name: "uiopen", args: []string{url}},
		}
	}
	return nil
}
