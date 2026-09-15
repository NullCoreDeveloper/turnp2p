import React, { useState, useEffect } from 'react';
import './App.css';

interface Peer {
  id: string;
  name: string;
  virtualIp: string;
  domain: string;
  relayAddr: string;
  sharedPorts?: number[];
  ping: number;
}

interface ForwardRule {
  id: string;
  name: string;
  protocol: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  enabled: boolean;
}

interface ConnectionStatus {
  connected: boolean;
  statusText: string;
  virtualIp: string;
  domain: string;
  nodeName: string;
  relayAddr: string;
  obfProfile: string;
  link: string;
  firewallMode?: string;
  sharedPorts?: number[];
  streamsCount?: number;
}

declare global {
  interface Window {
    go?: {
      main?: {
        App?: {
          JoinNetwork: (link: string, nickname: string, customDomain: string, obfKey: string, streamsCount: number) => Promise<ConnectionStatus>;
          LeaveNetwork: () => Promise<void>;
          GetStatus: () => Promise<ConnectionStatus>;
          GetPeers: () => Promise<Peer[]>;
          AddForwardRule: (rule: Partial<ForwardRule>) => Promise<void>;
          RemoveForwardRule: (id: string) => Promise<void>;
          GetForwardRules: () => Promise<ForwardRule[]>;
          GenerateRandomKey: () => Promise<string>;
          SetFirewallMode: (mode: string) => Promise<void>;
          AllowInboundPort: (port: number) => Promise<void>;
          DisallowInboundPort: (port: number) => Promise<void>;
        };
      };
    };
    runtime?: {
      EventsOn: (event: string, callback: (data: any) => void) => () => void;
    };
  }
}

export function App() {
  const [activeTab, setActiveTab] = useState<'network' | 'forwarding' | 'firewall' | 'obfuscation'>('network');
  const [vkLink, setVkLink] = useState('');
  const [nickname, setNickname] = useState('');
  const [customDomain, setCustomDomain] = useState('');
  const [obfKey, setObfKey] = useState('');
  const [streamsCount, setStreamsCount] = useState<number>(10);
  const [isConnected, setIsConnected] = useState(false);
  const [statusText, setStatusText] = useState('Отключено');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [localInfo, setLocalInfo] = useState<{ virtualIp: string; domain: string; name: string; streams: number }>({
    virtualIp: '',
    domain: '',
    name: '',
    streams: 10,
  });
  const [peers, setPeers] = useState<Peer[]>([]);
  const [forwardRules, setForwardRules] = useState<ForwardRule[]>([]);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Firewall state
  const [firewallMode, setFirewallMode] = useState<string>('whitelist');
  const [allowedPorts, setAllowedPorts] = useState<number[]>([25565]);
  const [newAllowedPort, setNewAllowedPort] = useState('');

  // Port Forwarding state
  const [newRule, setNewRule] = useState({
    name: '',
    localPort: '',
    remoteIp: '',
    remotePort: '',
    protocol: 'TCP',
  });

  useEffect(() => {
    generateNewKey();

    if (window.runtime) {
      window.runtime.EventsOn('status_change', (status: ConnectionStatus) => {
        setIsConnected(status.connected);
        setStatusText(status.statusText);
        if (status.connected) {
          setErrorMessage(null);
          setLocalInfo({
            virtualIp: status.virtualIp,
            domain: status.domain,
            name: status.nodeName,
            streams: status.streamsCount || 10,
          });
          if (status.firewallMode) setFirewallMode(status.firewallMode);
          if (status.sharedPorts) setAllowedPorts(status.sharedPorts);
        }
      });

      window.runtime.EventsOn('peers_updated', (updatedPeers: Peer[]) => {
        setPeers(updatedPeers || []);
      });
    }
  }, []);

  const generateNewKey = async () => {
    if (window.go?.main?.App?.GenerateRandomKey) {
      const key = await window.go.main.App.GenerateRandomKey();
      setObfKey(key);
    } else {
      const arr = new Uint8Array(32);
      window.crypto.getRandomValues(arr);
      const hex = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
      setObfKey(hex);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const cleanErrorMessage = (raw: string): string => {
    if (raw.includes('error_code: 14') || raw.includes('error_code:14') || raw.includes('Captcha need')) {
      return 'Требуется проверка VK (Капча). Открывается окно браузера для подтверждения...';
    }
    if (raw.includes('не удалось получить TURN данные')) {
      return 'Не удалось подключиться к VK звонку. Проверьте правильность ссылки.';
    }
    return raw.replace(/^failed to get TURN credentials:\s*/i, '').replace(/^failed to fetch VK TURN credentials with all available API clients:\s*/i, '');
  };

  const handleConnect = async () => {
    if (!vkLink) return;
    setErrorMessage(null);
    setStatusText(`Подключение (${streamsCount} потоков)...`);

    if (window.go?.main?.App?.JoinNetwork) {
      try {
        const res = await window.go.main.App.JoinNetwork(vkLink, nickname, customDomain, obfKey, streamsCount);
        setIsConnected(res.connected);
        setStatusText(res.statusText);
        setLocalInfo({
          virtualIp: res.virtualIp,
          domain: res.domain,
          name: res.nodeName,
          streams: res.streamsCount || streamsCount,
        });
      } catch (err: any) {
        const rawErr = err?.message || String(err);
        const niceErr = cleanErrorMessage(rawErr);
        setErrorMessage(niceErr);
        setStatusText('Ошибка подключения');
      }
    } else {
      setTimeout(() => {
        setIsConnected(true);
        setStatusText(`Подключено (${streamsCount} потоков, rtpopus3)`);
        setLocalInfo({
          virtualIp: '10.42.18.5',
          domain: customDomain ? `${customDomain}.vkturn` : `${nickname || 'NetHunter'}.vkturn`,
          name: nickname || 'NetHunter',
          streams: streamsCount,
        });
        setPeers([
          {
            id: 'peer-1',
            name: 'Alex-Server',
            virtualIp: '10.42.18.6',
            domain: 'mc-server.vkturn',
            relayAddr: '185.100.22.1:3478',
            sharedPorts: [25565, 8080],
            ping: 18,
          },
        ]);
      }, 1000);
    }
  };

  const handleDisconnect = async () => {
    if (window.go?.main?.App?.LeaveNetwork) {
      await window.go.main.App.LeaveNetwork();
    }
    setIsConnected(false);
    setStatusText('Отключено');
    setErrorMessage(null);
    setPeers([]);
  };

  const handleFirewallModeChange = async (mode: string) => {
    setFirewallMode(mode);
    if (window.go?.main?.App?.SetFirewallMode) {
      await window.go.main.App.SetFirewallMode(mode);
    }
  };

  const handleAddAllowedPort = async (e: React.FormEvent) => {
    e.preventDefault();
    const port = parseInt(newAllowedPort, 10);
    if (!port || port < 1 || port > 65535) return;

    if (!allowedPorts.includes(port)) {
      const updated = [...allowedPorts, port];
      setAllowedPorts(updated);
      if (window.go?.main?.App?.AllowInboundPort) {
        await window.go.main.App.AllowInboundPort(port);
      }
    }
    setNewAllowedPort('');
  };

  const handleRemoveAllowedPort = async (port: number) => {
    setAllowedPorts(allowedPorts.filter(p => p !== port));
    if (window.go?.main?.App?.DisallowInboundPort) {
      await window.go.main.App.DisallowInboundPort(port);
    }
  };

  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRule.localPort || !newRule.remoteIp || !newRule.remotePort) return;

    const ruleObj: Partial<ForwardRule> = {
      name: newRule.name || `Forward ${newRule.localPort}`,
      localPort: parseInt(newRule.localPort, 10),
      remoteIp: newRule.remoteIp,
      remotePort: parseInt(newRule.remotePort, 10),
      protocol: newRule.protocol,
    };

    if (window.go?.main?.App?.AddForwardRule) {
      try {
        await window.go.main.App.AddForwardRule(ruleObj);
        const rules = await window.go.main.App.GetForwardRules();
        setForwardRules(rules);
      } catch (err: any) {
        alert(err?.message || err);
      }
    } else {
      setForwardRules(prev => [
        ...prev,
        {
          id: Math.random().toString(),
          name: ruleObj.name!,
          localPort: ruleObj.localPort!,
          remoteIp: ruleObj.remoteIp!,
          remotePort: ruleObj.remotePort!,
          protocol: ruleObj.protocol!,
          enabled: true,
        },
      ]);
    }

    setNewRule({ name: '', localPort: '', remoteIp: '', remotePort: '', protocol: 'TCP' });
  };

  const handleRemoveRule = async (id: string) => {
    if (window.go?.main?.App?.RemoveForwardRule) {
      await window.go.main.App.RemoveForwardRule(id);
      const rules = await window.go.main.App.GetForwardRules();
      setForwardRules(rules);
    } else {
      setForwardRules(prev => prev.filter(r => r.id !== id));
    }
  };

  return (
    <div className="main-container">
      {/* App Header */}
      <div className="app-header">
        <div>
          <h1 className="app-title">TurnP2P</h1>
          <p className="app-subtitle">Виртуальная P2P сеть поверх VK TURN</p>
        </div>
        <div className="status-badge">
          <div
            className={`status-dot ${
              isConnected ? 'online' : statusText.includes('...') ? 'connecting' : 'offline'
            }`}
          />
          <span>{statusText}</span>
        </div>
      </div>

      {/* Error Banner */}
      {errorMessage && (
        <div
          className="animate-fade-in"
          style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            borderRadius: '10px',
            padding: '12px 16px',
            marginBottom: '16px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '0.85rem',
            color: '#fca5a5',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <span>{errorMessage}</span>
          </div>
          <button
            style={{ background: 'transparent', border: 'none', color: '#fca5a5', cursor: 'pointer', fontSize: '1rem' }}
            onClick={() => setErrorMessage(null)}
          >
            ✕
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="tab-bar">
        <button
          className={`tab-btn ${activeTab === 'network' ? 'active' : ''}`}
          onClick={() => setActiveTab('network')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
          </svg>
          Сеть
        </button>
        <button
          className={`tab-btn ${activeTab === 'forwarding' ? 'active' : ''}`}
          onClick={() => setActiveTab('forwarding')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="16 3 21 3 21 8" />
            <line x1="4" y1="20" x2="21" y2="3" />
            <polyline points="21 16 21 21 16 21" />
            <line x1="15" y1="15" x2="21" y2="21" />
            <line x1="4" y1="4" x2="9" y2="9" />
          </svg>
          Проброс портов
        </button>
        <button
          className={`tab-btn ${activeTab === 'firewall' ? 'active' : ''}`}
          onClick={() => setActiveTab('firewall')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          Брандмауэр
        </button>
        <button
          className={`tab-btn ${activeTab === 'obfuscation' ? 'active' : ''}`}
          onClick={() => setActiveTab('obfuscation')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          Маскировка (rtpopus3)
        </button>
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeTab === 'network' && (
          <div className="animate-fade-in">
            {!isConnected ? (
              <div>
                <div className="input-group">
                  <label htmlFor="vk-link">Ссылка на VK Звонок</label>
                  <input
                    id="vk-link"
                    className="input"
                    value={vkLink}
                    onChange={e => setVkLink(e.target.value)}
                    placeholder="https://vk.com/call/join/..."
                    type="text"
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <div className="input-group">
                    <label htmlFor="nickname">Имя узла</label>
                    <input
                      id="nickname"
                      className="input"
                      value={nickname}
                      onChange={e => setNickname(e.target.value)}
                      placeholder="MyNode"
                      type="text"
                    />
                  </div>
                  <div className="input-group">
                    <label htmlFor="custom-domain">Свой домен (опционально)</label>
                    <input
                      id="custom-domain"
                      className="input"
                      value={customDomain}
                      onChange={e => setCustomDomain(e.target.value)}
                      placeholder="mygame.vkturn"
                      type="text"
                    />
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '12px' }}>
                  <div className="input-group">
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <label htmlFor="obf-key">Ключ маскировки rtpopus3</label>
                      <span
                        style={{ fontSize: '0.72rem', color: 'var(--accent)', cursor: 'pointer' }}
                        onClick={generateNewKey}
                      >
                        Сгенерировать
                      </span>
                    </div>
                    <input
                      id="obf-key"
                      className="input"
                      style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                      value={obfKey}
                      onChange={e => setObfKey(e.target.value)}
                      placeholder="64 hex символа"
                      type="text"
                    />
                  </div>
                  <div className="input-group">
                    <label htmlFor="streams-count">Потоков (N)</label>
                    <input
                      id="streams-count"
                      className="input"
                      type="number"
                      min={1}
                      max={30}
                      value={streamsCount}
                      onChange={e => setStreamsCount(Math.max(1, parseInt(e.target.value, 10) || 1))}
                    />
                  </div>
                </div>

                <button
                  className="btn"
                  onClick={handleConnect}
                  disabled={!vkLink}
                  style={{ width: '100%', marginTop: '8px' }}
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                  </svg>
                  Войти в P2P комнату ({streamsCount} потоков)
                </button>
              </div>
            ) : (
              <div>
                {/* Local Node Info Card */}
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Локальный узел</span>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <span className="badge" style={{ color: '#60a5fa' }}>{localInfo.streams} Потоков</span>
                      <span className="badge obf">rtpopus3</span>
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '0.88rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Виртуальный IP: </span>
                      <strong
                        style={{ cursor: 'pointer', color: '#60a5fa' }}
                        onClick={() => copyToClipboard(localInfo.virtualIp)}
                        title="Нажмите для копирования"
                      >
                        {localInfo.virtualIp}
                      </strong>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Домен: </span>
                      <strong
                        style={{ cursor: 'pointer', color: '#c084fc' }}
                        onClick={() => copyToClipboard(localInfo.domain)}
                        title="Нажмите для копирования"
                      >
                        {localInfo.domain}
                      </strong>
                    </div>
                  </div>
                  {copiedText && (
                    <p style={{ fontSize: '0.75rem', color: 'var(--success)', marginTop: '6px' }}>
                      Скопировано в буфер обмена: {copiedText}
                    </p>
                  )}
                </div>

                {/* Peers in Network */}
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Участники в комнате ({peers.length})</span>
                  </div>
                  {peers.length === 0 ? (
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '12px 0' }}>
                      Ожидание обнаружения других участников в комнате...
                    </p>
                  ) : (
                    peers.map(p => (
                      <div key={p.id} className="peer-row">
                        <div>
                          <strong>{p.name}</strong>
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                            {p.domain}
                            {p.sharedPorts && p.sharedPorts.length > 0 && (
                              <span style={{ marginLeft: '6px', color: '#34d399' }}>
                                (Открыты порты: {p.sharedPorts.join(', ')})
                              </span>
                            )}
                          </div>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span
                            className="badge"
                            style={{ cursor: 'pointer' }}
                            onClick={() => copyToClipboard(p.domain || p.virtualIp)}
                            title="Копировать адрес"
                          >
                            {p.virtualIp}
                          </span>
                          <span className="badge ping">{p.ping} ms</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <button
                  className="btn btn-danger"
                  onClick={handleDisconnect}
                  style={{ width: '100%', marginTop: '8px' }}
                >
                  Отключиться от сети
                </button>
              </div>
            )}
          </div>
        )}

        {activeTab === 'forwarding' && (
          <div className="animate-fade-in">
            {/* Add Forwarding Rule */}
            <form onSubmit={handleAddRule} className="card">
              <div className="card-title" style={{ marginBottom: '12px' }}>
                Добавить клиентский проброс порта
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div className="input-group">
                  <label>Название правила</label>
                  <input
                    className="input"
                    placeholder="Напр. Minecraft Server"
                    value={newRule.name}
                    onChange={e => setNewRule({ ...newRule, name: e.target.value })}
                  />
                </div>
                <div className="input-group">
                  <label>Локальный порт (на вашем ПК)</label>
                  <input
                    className="input"
                    placeholder="25565"
                    type="number"
                    value={newRule.localPort}
                    onChange={e => setNewRule({ ...newRule, localPort: e.target.value })}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: '10px' }}>
                <div className="input-group">
                  <label>IP или домен пира (напр. alex.vkturn)</label>
                  <input
                    className="input"
                    placeholder="10.42.18.6 или mygame.vkturn"
                    value={newRule.remoteIp}
                    onChange={e => setNewRule({ ...newRule, remoteIp: e.target.value })}
                  />
                </div>
                <div className="input-group">
                  <label>Порт пира</label>
                  <input
                    className="input"
                    placeholder="25565"
                    type="number"
                    value={newRule.remotePort}
                    onChange={e => setNewRule({ ...newRule, remotePort: e.target.value })}
                  />
                </div>
                <div className="input-group">
                  <label>Протокол</label>
                  <select
                    className="input"
                    value={newRule.protocol}
                    onChange={e => setNewRule({ ...newRule, protocol: e.target.value })}
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                  </select>
                </div>
              </div>

              <button type="submit" className="btn btn-secondary" style={{ width: '100%', marginTop: '6px' }}>
                + Активировать проброс
              </button>
            </form>

            {/* Rules List */}
            <div className="card">
              <div className="card-header">
                <span className="card-title">Активные пробросы</span>
              </div>
              {forwardRules.length === 0 ? (
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '12px 0' }}>
                  Нет активных правил. Добавьте порт выше для подключения к серверам друзей.
                </p>
              ) : (
                forwardRules.map(r => (
                  <div key={r.id} className="peer-row">
                    <div>
                      <strong>{r.name}</strong>
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                        127.0.0.1:{r.localPort} ➔ {r.remoteIp}:{r.remotePort} ({r.protocol})
                      </div>
                    </div>
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => handleRemoveRule(r.id)}
                    >
                      Удалить
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === 'firewall' && (
          <div className="animate-fade-in card">
            <div className="card-title" style={{ marginBottom: '14px' }}>
              Контроль доступа входящих соединений (Брандмауэр)
            </div>

            {/* Policy Selection */}
            <div className="input-group" style={{ marginBottom: '20px' }}>
              <label>Политика входящих подключений:</label>
              <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                <button
                  type="button"
                  className={`btn btn-sm ${firewallMode === 'whitelist' ? 'btn' : 'btn-secondary'}`}
                  onClick={() => handleFirewallModeChange('whitelist')}
                >
                  Только разрешенные (Whitelist)
                </button>
                <button
                  type="button"
                  className={`btn btn-sm ${firewallMode === 'block_all' ? 'btn-danger' : 'btn-secondary'}`}
                  onClick={() => handleFirewallModeChange('block_all')}
                >
                  Блокировать все
                </button>
                <button
                  type="button"
                  className={`btn btn-sm ${firewallMode === 'allow_all' ? 'btn' : 'btn-secondary'}`}
                  onClick={() => handleFirewallModeChange('allow_all')}
                >
                  Разрешить все
                </button>
              </div>
            </div>

            {/* Shared Ports Form */}
            {firewallMode === 'whitelist' && (
              <div>
                <form onSubmit={handleAddAllowedPort} style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
                  <input
                    className="input"
                    placeholder="Порт для открытия (напр. 25565)"
                    type="number"
                    style={{ flex: 1 }}
                    value={newAllowedPort}
                    onChange={e => setNewAllowedPort(e.target.value)}
                  />
                  <button type="submit" className="btn btn-secondary btn-sm">
                    + Открыть порт
                  </button>
                </form>

                <div className="card-title" style={{ marginBottom: '8px' }}>
                  Открытые сервисы на вашем ПК:
                </div>
                {allowedPorts.length === 0 ? (
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                    Нет открытых портов. Другие участники не смогут подключаться к вашим локальным службам.
                  </p>
                ) : (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {allowedPorts.map(p => (
                      <span key={p} className="badge" style={{ padding: '6px 10px', fontSize: '0.82rem' }}>
                        Порт {p}
                        <span
                          style={{ marginLeft: '6px', cursor: 'pointer', color: 'var(--danger)' }}
                          onClick={() => handleRemoveAllowedPort(p)}
                          title="Закрыть порт"
                        >
                          ✕
                        </span>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === 'obfuscation' && (
          <div className="animate-fade-in card">
            <div className="card-title" style={{ marginBottom: '14px' }}>
              Параметры маскировки трафика (DPI Bypass)
            </div>
            <div style={{ fontSize: '0.85rem', lineHeight: '1.6', color: 'var(--text-muted)' }}>
              <p style={{ marginBottom: '10px' }}>
                <strong style={{ color: 'var(--text-main)' }}>Профиль: </strong>
                <span className="badge obf">rtpopus3 (WebRTC Voice Emulation)</span>
              </p>
              <p style={{ marginBottom: '10px' }}>
                Трафик оверлейной сети упаковывается в заголовки <strong>RTP Opus (PT 111)</strong> с расширениями <strong>RFC 8285</strong> (audio-level + transport-cc) и шифруется алгоритмом <strong>ChaCha20-Poly1305</strong>.
              </p>
              <div style={{ marginTop: '14px', padding: '12px', background: 'rgba(0,0,0,0.25)', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>Ключ симметричного шифрования (AEAD):</div>
                <div style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: '#60a5fa', wordBreak: 'break-all', marginTop: '4px' }}>
                  {obfKey || 'Ключ не задан'}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
