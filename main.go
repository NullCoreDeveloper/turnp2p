package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"runtime"
	"sync/atomic"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var iconPng []byte

//go:embed build/windows/icon.ico
var iconIco []byte

func main() {
	// Create an instance of the app structure
	app := NewApp()

	var (
		appCtx        context.Context
		windowVisible atomic.Bool
		mStatus       *systray.MenuItem
		mToggle       *systray.MenuItem
		mConnect      *systray.MenuItem
		mQuit         *systray.MenuItem
	)

	windowVisible.Store(true)

	getTrayIcon := func() []byte {
		if runtime.GOOS == "windows" {
			return iconIco
		}
		return iconPng
	}

	toggleWindow := func() {
		if appCtx == nil {
			return
		}
		if windowVisible.Load() {
			wailsRuntime.WindowHide(appCtx)
			windowVisible.Store(false)
			if mToggle != nil {
				mToggle.SetTitle("Показать TurnP2P")
			}
		} else {
			wailsRuntime.WindowShow(appCtx)
			wailsRuntime.WindowUnminimise(appCtx)
			windowVisible.Store(true)
			if mToggle != nil {
				mToggle.SetTitle("Скрыть TurnP2P")
			}
		}
	}

	// Setup systray
	startSystray, endSystray := systray.RunWithExternalLoop(func() {
		systray.SetIcon(getTrayIcon())
		systray.SetTitle("TurnP2P")
		systray.SetTooltip("TurnP2P - Защищенная P2P сеть через VK TURN")

		// 1. Статус сети (disabled header)
		mStatus = systray.AddMenuItem("TurnP2P: Отключено", "Текущий статус сети")
		mStatus.Disable()

		systray.AddSeparator()

		// 2. Открыть / Скрыть окно
		mToggle = systray.AddMenuItem("Скрыть TurnP2P", "Показать или скрыть главное окно")
		mToggle.Click(func() {
			toggleWindow()
		})

		// 3. Подключиться / Отключиться
		mConnect = systray.AddMenuItem("Подключиться", "Подключиться к P2P сети")
		mConnect.Click(func() {
			st := app.GetStatus()
			if st.Connected {
				go func() {
					_ = app.LeaveNetwork()
				}()
			} else {
				if app.HasLastJoinParams() {
					go func() {
						_, _ = app.ReconnectLast()
					}()
				} else {
					if appCtx != nil {
						wailsRuntime.WindowShow(appCtx)
						wailsRuntime.WindowUnminimise(appCtx)
						windowVisible.Store(true)
						if mToggle != nil {
							mToggle.SetTitle("Скрыть TurnP2P")
						}
					}
				}
			}
		})

		systray.AddSeparator()

		// 4. Выход
		mQuit = systray.AddMenuItem("Выход", "Полное завершение работы TurnP2P")
		mQuit.Click(func() {
			go func() {
				_ = app.LeaveNetwork()
				if appCtx != nil {
					wailsRuntime.Quit(appCtx)
				}
			}()
		})

		// ЛКМ: быстрое открытие и скрытие окна
		systray.SetOnClick(func(menu systray.IMenu) {
			toggleWindow()
		})

		// ПКМ: контекстное меню
		systray.SetOnRClick(func(menu systray.IMenu) {
			if menu != nil {
				_ = menu.ShowMenu()
			}
		})
	}, func() {
		log.Println("[Systray] Exit")
	})

	// Слушатель изменения статуса сети для динамического обновления меню
	app.OnStatusChange(func(st ConnectionStatus) {
		if mStatus != nil {
			if st.Connected {
				addr := st.VirtualIP
				if addr == "" {
					addr = st.Domain
				}
				mStatus.SetTitle(fmt.Sprintf("TurnP2P: В сети (%s)", addr))
				systray.SetTooltip(fmt.Sprintf("TurnP2P: В сети (%s)", addr))
			} else {
				mStatus.SetTitle("TurnP2P: Отключено")
				systray.SetTooltip("TurnP2P: Отключено")
			}
		}
		if mConnect != nil {
			if st.Connected {
				mConnect.SetTitle("Отключиться")
				mConnect.SetTooltip("Разорвать соединение с P2P сетью")
			} else {
				mConnect.SetTitle("Подключиться")
				mConnect.SetTooltip("Подключиться к P2P сети")
			}
		}
	})

	// Слушатель изменения видимости окна (от фронтенда / событий)
	app.OnVisibilityChange(func(visible bool) {
		windowVisible.Store(visible)
		if mToggle != nil {
			if visible {
				mToggle.SetTitle("Скрыть TurnP2P")
			} else {
				mToggle.SetTitle("Показать TurnP2P")
			}
		}
	})

	// Create application with options
	err := wails.Run(&options.App{
		Title:             "turnp2p",
		Width:             1024,
		Height:            768,
		HideWindowOnClose: true,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "turnp2p-p2p-client-lock-uuid",
			OnSecondInstanceLaunch: func(secondInstanceData options.SecondInstanceData) {
				if appCtx != nil {
					wailsRuntime.WindowShow(appCtx)
					wailsRuntime.WindowUnminimise(appCtx)
					windowVisible.Store(true)
					if mToggle != nil {
						mToggle.SetTitle("Скрыть TurnP2P")
					}
				}
			},
		},
		OnStartup: func(ctx context.Context) {
			appCtx = ctx
			app.startup(ctx)
			if startSystray != nil {
				startSystray()
			}
		},
		OnShutdown: func(ctx context.Context) {
			if endSystray != nil {
				endSystray()
			}
			_ = app.LeaveNetwork()
		},
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
