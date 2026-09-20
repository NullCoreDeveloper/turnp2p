package turn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/google/uuid"
)

// CleanVKLink extracts the raw join hash/ID from any VK call link format.
func CleanVKLink(raw string) string {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, "join/")
	link := parts[len(parts)-1]
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}
	return link
}

func vkDelay(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

var (
	credsCacheMu sync.RWMutex
	credsCache   = make(map[string]*Credentials)
)

// FetchVKTurnCredentials iterates over official VK App credentials and browser profiles to obtain TURN relay creds.
// Caches valid credentials for 10 minutes to avoid redundant captcha solving and API rate limits.
func FetchVKTurnCredentials(ctx context.Context, link string) (*Credentials, error) {
	cleanLink := CleanVKLink(link)
	if cleanLink == "" {
		return nil, fmt.Errorf("некорректная ссылка на VK звонок: %s", link)
	}

	// 1. Check in-memory cache
	credsCacheMu.RLock()
	if cached, exists := credsCache[cleanLink]; exists {
		if time.Now().Before(cached.ExpiresAt) {
			credsCacheMu.RUnlock()
			log.Printf("[VK Auth] Using cached credentials for %s (expires in %v)", cleanLink, time.Until(cached.ExpiresAt).Truncate(time.Second))
			return cached, nil
		}
	}
	credsCacheMu.RUnlock()

	var lastErr error

	for _, creds := range DefaultVKCredentials {
		prof := GetProfileForApp(creds.Name)
		jar := tlsclient.NewCookieJar()

		client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
			tlsclient.WithTimeoutSeconds(25),
			tlsclient.WithClientProfile(prof.ClientProfile),
			tlsclient.WithCookieJar(jar),
		)
		if err != nil {
			lastErr = err
			continue
		}

		name := GenerateRandomName()
		escapedName := neturl.QueryEscape(name)

		log.Printf("[VK Auth] Trying app: %s (%s) with User-Agent: %s (platform: %s, mobile: %s)", creds.Name, creds.ClientID, prof.UserAgent, prof.Platform, prof.SecChUaMobile)

		doRequest := func(data string, targetURL string) (map[string]interface{}, error) {
			parsedURL, err := neturl.Parse(targetURL)
			if err != nil {
				return nil, err
			}

			req, err := fhttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewBufferString(data))
			if err != nil {
				return nil, err
			}

			req.Host = parsedURL.Hostname()
			applyBrowserProfileFhttp(req, prof)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Origin", "https://vk.ru")
			req.Header.Set("Referer", "https://vk.ru/")
			req.Header.Set("Sec-Fetch-Site", "same-site")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Dest", "empty")

			httpResp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer httpResp.Body.Close()

			body, err := io.ReadAll(httpResp.Body)
			if err != nil {
				return nil, err
			}

			var resp map[string]interface{}
			if err := json.Unmarshal(body, &resp); err != nil {
				return nil, fmt.Errorf("ошибка парсинга JSON ответа: %w", err)
			}
			return resp, nil
		}

		// Warm-up: open join page like a real browser before requesting anonymous tokens
		if warmErr := openJoinPage(ctx, client, prof, cleanLink); warmErr != nil {
			log.Printf("[VK Auth] Warm-up join page warning: %v", warmErr)
		}
		vkDelay(300, 600)

		// Step 1: Get Anonymous Token with full scopes
		data := fmt.Sprintf("client_secret=%s&client_id=%s&scopes=audio_anonymous,video_anonymous,photos_anonymous,profile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=%s",
			creds.ClientSecret, creds.ClientID, creds.ClientID)
		resp1, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
		if err != nil {
			log.Printf("[VK Auth] get_anonym_token failed with %s: %v", creds.Name, err)
			lastErr = err
			continue
		}

		dataMap, ok := resp1["data"].(map[string]interface{})
		if !ok {
			lastErr = fmt.Errorf("неверный формат ответа токена: %v", resp1)
			continue
		}
		token1, ok := dataMap["access_token"].(string)
		if !ok {
			lastErr = fmt.Errorf("отсутствует access_token в ответе VK")
			continue
		}

		vkDelay(120, 200)

		fullJoinLink := fmt.Sprintf("https://vk.ru/call/join/%s", cleanLink)

		// Step 2: Call Preview
		data = fmt.Sprintf("vk_join_link=%s&fields=photo_200&access_token=%s", fullJoinLink, token1)
		_, _ = doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)

		vkDelay(150, 250)

		// Step 3: Get Anonymous Token for Call (with Captcha bypass)
		var token2 string
		data = fmt.Sprintf("vk_join_link=%s&name=%s&access_token=%s", fullJoinLink, escapedName, token1)

		for attempt := 0; attempt < 3; attempt++ {
			reqURL := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)
			resp2, err := doRequest(data, reqURL)
			if err != nil {
				lastErr = err
				break
			}
			log.Printf("[VK Auth] getAnonymousToken attempt %d response: %+v", attempt, resp2)

			if errObj, hasErr := resp2["error"].(map[string]interface{}); hasErr {
				captchaChallenge := ParseCaptchaError(errObj)
				if captchaChallenge != nil && captchaChallenge.RedirectURI != "" {
					var solvedToken string
					var solveErr error

					// 1. Run headless browser solver FIRST on the fresh redirectURI!
					log.Printf("[VK Auth] Запуск автономного фонового решателя капчи...")
					solvedToken, solveErr = SolveCaptchaViaBrowser(ctx, captchaChallenge.RedirectURI)

					// 2. If headless solver failed or unavailable, try API solver fallback
					if (solveErr != nil || solvedToken == "") && captchaChallenge.SessionToken != "" {
						log.Printf("[VK Auth] Фоновый браузер не решил капчу (%v). Пробуем API-решатель...", solveErr)
						solvedToken, solveErr = AutoSolveVkCaptcha(ctx, captchaChallenge.RedirectURI, captchaChallenge.SessionToken, client, prof)
					}

					if solveErr != nil || solvedToken == "" {
						log.Printf("[VK Auth] Авто-решение не удалось для %s (%v). Переходим к следующему приложению...", creds.Name, solveErr)
						lastErr = solveErr
						break
					}

					// Retry with success_token and captcha parameters
					retryVals := neturl.Values{}
					retryVals.Set("vk_join_link", fullJoinLink)
					retryVals.Set("name", name)
					retryVals.Set("access_token", token1)
					retryVals.Set("success_token", solvedToken)
					if captchaChallenge.CaptchaSid != "" {
						retryVals.Set("captcha_sid", captchaChallenge.CaptchaSid)
						retryVals.Set("captcha_key", "")
					}
					if captchaChallenge.CaptchaTs != "" {
						retryVals.Set("captcha_ts", captchaChallenge.CaptchaTs)
					}
					if captchaChallenge.CaptchaAttempt != "" {
						retryVals.Set("captcha_attempt", captchaChallenge.CaptchaAttempt)
					}
					data = retryVals.Encode()
					log.Printf("[VK Auth] Retrying getAnonymousToken with success_token...")
					continue
				}

				code, _ := errObj["error_code"].(float64)
				msg, _ := errObj["error_msg"].(string)
				lastErr = fmt.Errorf("ошибка VK API (код %d): %s", int(code), msg)
				break
			}

			respMap, ok := resp2["response"].(map[string]interface{})
			if !ok {
				lastErr = fmt.Errorf("неожиданный ответ getAnonymousToken: %v", resp2)
				break
			}

			token2, ok = respMap["token"].(string)
			if !ok {
				lastErr = fmt.Errorf("отсутствует токен звонка в ответе")
				break
			}
			break
		}

		if token2 == "" {
			continue
		}

		vkDelay(120, 200)

		// Step 4: Login to OK Calls platform
		sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New().String())
		data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
		resp3, err := doRequest(data, "https://calls.okcdn.ru/fb.do")
		if err != nil {
			lastErr = err
			continue
		}

		token3, ok := resp3["session_key"].(string)
		if !ok {
			lastErr = fmt.Errorf("отсутствует session_key в ответе OK Calls: %v", resp3)
			continue
		}

		vkDelay(120, 200)

		// Step 5: Join Conversation and extract TURN server info
		data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s",
			cleanLink, token2, token3)
		resp4, err := doRequest(data, "https://calls.okcdn.ru/fb.do")
		if err != nil {
			lastErr = err
			continue
		}

		log.Printf("[VK Auth] vchat.joinConversationByLink response: %v", resp4)

		tsRaw, ok := resp4["turn_server"].(map[string]interface{})
		if !ok {
			lastErr = fmt.Errorf("отсутствуют данные turn_server в ответе комнаты (возможно, звонок завершен)")
			continue
		}

		user, ok := tsRaw["username"].(string)
		if !ok {
			lastErr = fmt.Errorf("отсутствует username в turn_server")
			continue
		}
		pass, ok := tsRaw["credential"].(string)
		if !ok {
			lastErr = fmt.Errorf("отсутствует credential в turn_server")
			continue
		}
		urlsRaw, ok := tsRaw["urls"].([]interface{})
		if !ok || len(urlsRaw) == 0 {
			lastErr = fmt.Errorf("отсутствует список адресов в turn_server")
			continue
		}
		var serverAddrs []string
		for _, raw := range urlsRaw {
			if uStr, ok := raw.(string); ok && uStr != "" {
				clean := strings.Split(uStr, "?")[0]
				clean = strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
				// Check for duplicates
				duplicate := false
				for _, sa := range serverAddrs {
					if sa == clean {
						duplicate = true
						break
					}
				}
				if !duplicate {
					serverAddrs = append(serverAddrs, clean)
				}
			}
		}

		if len(serverAddrs) == 0 {
			lastErr = fmt.Errorf("отсутствует список адресов в turn_server")
			continue
		}

		wsEndpoint, _ := resp4["endpoint"].(string)

		result := &Credentials{
			Username:    user,
			Password:    pass,
			ServerAddr:  serverAddrs[0],
			ServerAddrs: serverAddrs,
			WsEndpoint:  wsEndpoint,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			Link:        cleanLink,
		}

		credsCacheMu.Lock()
		credsCache[cleanLink] = result
		credsCacheMu.Unlock()

		return result, nil
	}

	return nil, fmt.Errorf("не удалось получить TURN данные: %w", lastErr)
}

// InvalidateCredentialsCache removes cached credentials for a link.
func InvalidateCredentialsCache(link string) {
	clean := strings.TrimPrefix(link, "https://vk.com/call/join/")
	clean = strings.TrimPrefix(clean, "https://vk.ru/call/join/")
	clean = strings.TrimSpace(clean)
	credsCacheMu.Lock()
	delete(credsCache, clean)
	credsCacheMu.Unlock()
}

func openJoinPage(ctx context.Context, httpClient tlsclient.HttpClient, prof Profile, link string) error {
	req, err := fhttp.NewRequestWithContext(ctx, fhttp.MethodGet, "https://vk.ru/call/join/"+link, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Fetch-Site", "none")
	applyBrowserProfileFhttp(req, prof)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
