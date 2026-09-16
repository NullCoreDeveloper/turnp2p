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
		prof := GetRandomProfile()
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

		log.Printf("[VK Auth] Trying app: %s (%s) with User-Agent: %s", creds.Name, creds.ClientID, prof.UserAgent)

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
			req.Header.Set("User-Agent", prof.UserAgent)
			req.Header.Set("sec-ch-ua", prof.SecChUa)
			req.Header.Set("sec-ch-ua-mobile", prof.SecChUaMobile)
			req.Header.Set("sec-ch-ua-platform", prof.SecChUaPlatform)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Origin", "https://vk.com")
			req.Header.Set("Referer", "https://vk.com/")
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

		// Step 1: Get Anonymous Token
		data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s",
			creds.ClientID, creds.ClientSecret, creds.ClientID)
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

		// VK calls API strictly requires https://vk.com/call/join/<hash> (rejects id.vk.com with error 9008)
		fullJoinLink := fmt.Sprintf("https://vk.com/call/join/%s", cleanLink)

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

			if errObj, hasErr := resp2["error"].(map[string]interface{}); hasErr {
				captchaChallenge := ParseCaptchaError(errObj)
				if captchaChallenge != nil && captchaChallenge.RedirectURI != "" {
					var solvedToken string
					var solveErr error

					// 1. Try automatic background solver first
					if captchaChallenge.SessionToken != "" {
						log.Printf("[VK Auth] Попытка автоматического фонового решения капчи...")
						solvedToken, solveErr = AutoSolveVkCaptcha(ctx, captchaChallenge.RedirectURI, captchaChallenge.SessionToken, client, prof)
					}

					// 2. If auto-solver failed or not applicable, open browser fallback
					if solveErr != nil || solvedToken == "" {
						log.Printf("[VK Auth] Авто-решение не удалось (%v). Запуск браузера для подтверждения...", solveErr)
						solvedToken, solveErr = SolveCaptchaViaBrowser(ctx, captchaChallenge.RedirectURI)
					}

					if solveErr != nil {
						lastErr = fmt.Errorf("не удалось решить капчу: %w", solveErr)
						break
					}

					// Retry with success_token and captcha_attempt
					data = fmt.Sprintf("vk_join_link=%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
						fullJoinLink, escapedName, captchaChallenge.CaptchaSid, neturl.QueryEscape(solvedToken), captchaChallenge.CaptchaTs, captchaChallenge.CaptchaAttempt, token1)
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
