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

interface ConnectionStatus {
  connected: boolean;
  statusText: string;
  virtualIp: string;
  domain: string;
  nodeName: string;
  relayAddr: string;
  obfProfile: string;
  obfKey?: string;
  link: string;
  firewallMode?: string;
  sharedPorts?: number[];
  streamsCount?: number;
  networkMode?: string;
  hostsSync?: boolean;
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
          ConnectPeer: (address: string) => Promise<void>;
          GenerateRandomKey: () => Promise<string>;
          SetFirewallMode: (mode: string) => Promise<void>;
          AllowInboundPort: (port: number) => Promise<void>;
          DisallowInboundPort: (port: number) => Promise<void>;
          SetNetworkMode: (mode: string) => Promise<void>;
        };
      };
    };
    runtime?: {
      EventsOn: (event: string, callback: (data: any) => void) => () => void;
    };
  }
}

export function App() {
  const [activeTab, setActiveTab] = useState<'network' | 'firewall'>('network');
  const [vkLink, setVkLink] = useState(() => localStorage.getItem('turnp2p_vkLink') || '');
  const [nickname, setNickname] = useState(() => localStorage.getItem('turnp2p_nickname') || '');
  const [customDomain, setCustomDomain] = useState(() => localStorage.getItem('turnp2p_customDomain') || '');
  const [obfKey, setObfKey] = useState(() => localStorage.getItem('turnp2p_obfKey') || '');
  const [streamsCount, setStreamsCount] = useState<number>(() => {
    const saved = localStorage.getItem('turnp2p_streamsCount');
    return saved ? Math.min(parseInt(saved, 10) || 3, 5) : 3;
  });
  const [networkMode, setNetworkMode] = useState<'userspace' | 'tun'>(() => {
    const saved = localStorage.getItem('turnp2p_networkMode');
    return saved === 'tun' ? 'tun' : 'userspace';
  });
  const [isConnected, setIsConnected] = useState(false);
  const [statusText, setStatusText] = useState('Отключено');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [manualPeerAddr, setManualPeerAddr] = useState('');
  const [manualConnectMsg, setManualConnectMsg] = useState<string | null>(null);
  const [localInfo, setLocalInfo] = useState<{
    virtualIp: string;
    domain: string;
    name: string;
    relayAddr: string;
    streams: number;
    networkMode: string;
    hostsSync: boolean;
    obfKey: string;
  }>({
    virtualIp: '',
    domain: '',
    name: '',
    relayAddr: '',
    streams: 3,
    networkMode: 'userspace',
    hostsSync: false,
    obfKey: '',
  });
  const [peers, setPeers] = useState<Peer[]>([]);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Firewall state
  const [firewallMode, setFirewallMode] = useState<string>(() => localStorage.getItem('turnp2p_firewallMode') || 'whitelist');
  const [allowedPorts, setAllowedPorts] = useState<number[]>(() => {
    try {
      const saved = localStorage.getItem('turnp2p_allowedPorts');
      return saved ? JSON.parse(saved) : [25565];
    } catch {
      return [25565];
    }
  });
  const [newAllowedPort, setNewAllowedPort] = useState('');

  // Persist state changes
  useEffect(() => { localStorage.setItem('turnp2p_vkLink', vkLink); }, [vkLink]);
  useEffect(() => { localStorage.setItem('turnp2p_nickname', nickname); }, [nickname]);
  useEffect(() => { localStorage.setItem('turnp2p_customDomain', customDomain); }, [customDomain]);
  useEffect(() => { if (obfKey) localStorage.setItem('turnp2p_obfKey', obfKey); }, [obfKey]);
  useEffect(() => { localStorage.setItem('turnp2p_streamsCount', String(streamsCount)); }, [streamsCount]);
  useEffect(() => { localStorage.setItem('turnp2p_networkMode', networkMode); }, [networkMode]);
  useEffect(() => { localStorage.setItem('turnp2p_firewallMode', firewallMode); }, [firewallMode]);
  useEffect(() => { localStorage.setItem('turnp2p_allowedPorts', JSON.stringify(allowedPorts)); }, [allowedPorts]);

  useEffect(() => {
    if (!obfKey) {
      generateNewKey();
    }

    // Sync saved settings with backend
    if (window.go?.main?.App) {
      if (networkMode) window.go.main.App.SetNetworkMode(networkMode);
      if (firewallMode) window.go.main.App.SetFirewallMode(firewallMode);
      for (const p of allowedPorts) {
        window.go.main.App.AllowInboundPort(p);
      }
    }

    if (window.runtime) {
      window.runtime.EventsOn('status_change', (status: ConnectionStatus) => {
        setIsConnected(status.connected);
        setStatusText(status.statusText);
        if (status.networkMode === 'tun' || status.networkMode === 'userspace') {
          setNetworkMode(status.networkMode);
        }
        if (status.connected) {
          setErrorMessage(null);
          setLocalInfo({
            virtualIp: status.virtualIp,
            domain: status.domain,
            name: status.nodeName,
            relayAddr: status.relayAddr || '',
            streams: status.streamsCount || 10,
            networkMode: status.networkMode || 'userspace',
            hostsSync: status.hostsSync ?? true,
            obfKey: status.obfKey || obfKey,
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

  const copyToClipboard = (text: string, label?: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label || text);
    setTimeout(() => setCopiedText(null), 2500);
  };

  const cleanErrorMessage = (raw: string): string => {
    if (raw.includes('Quota Reached') || raw.includes('486')) {
      return 'Лимит одновременных сессий VK TURN исчерпан. Пожалуйста, подождите 1 минуту или создайте новую ссылку на звонок.';
    }
    if (raw.includes('error_code: 14') || raw.includes('error_code:14') || raw.includes('Captcha need')) {
      return 'Требуется проверка VK (Капча). Проверьте окно капчи...';
    }
    if (raw.includes('не удалось получить TURN данные')) {
      return 'Не удалось подключиться к VK звонку. Проверьте правильность ссылки.';
    }
    return raw.replace(/^failed to get TURN credentials:\s*/i, '').replace(/^failed to fetch VK TURN credentials with all available API clients:\s*/i, '');
  };

  const handleNetworkModeChange = async (mode: 'userspace' | 'tun') => {
    setNetworkMode(mode);
    if (window.go?.main?.App?.SetNetworkMode) {
      await window.go.main.App.SetNetworkMode(mode);
    }
  };

  const handleManualConnectPeer = async (e: React.FormEvent) => {
    e.preventDefault();
    const addr = manualPeerAddr.trim();
    if (!addr) return;

    try {
      if (window.go?.main?.App?.ConnectPeer) {
        await window.go.main.App.ConnectPeer(addr);
      }
      setManualConnectMsg(`Запрос отправлен на ${addr}`);
      setTimeout(() => setManualConnectMsg(null), 3000);
      setManualPeerAddr('');
    } catch (err: any) {
      setManualConnectMsg(`Ошибка: ${err?.message || err}`);
      setTimeout(() => setManualConnectMsg(null), 4000);
    }
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
          relayAddr: res.relayAddr || '',
          streams: res.streamsCount || streamsCount,
          networkMode: res.networkMode || networkMode,
          hostsSync: res.hostsSync ?? true,
          obfKey: res.obfKey || obfKey,
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
          relayAddr: '91.231.135.87:54321',
          streams: streamsCount,
          networkMode: networkMode,
          hostsSync: true,
          obfKey: obfKey || '342b8fdbfcb5b548405c56ea37f1856e6776629b1554d2d2005f8d343527f253',
        });
        setPeers([
          {
            id: 'peer-1',
            name: 'Alex-Server',
            virtualIp: '10.42.18.6',
            domain: 'mc-server.vkturn',
            relayAddr: '185.100.22.1:3478',
            sharedPorts: [25565],
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

  return (
    <div className="main-container">
      {/* App Header */}
      <div className="app-header">
        <div>
          <h1 className="app-title">TurnP2P</h1>
          <p className="app-subtitle">Виртуальная P2P сеть поверх VK TURN (WebRTC rtpopus3)</p>
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

      {/* Tabs (Clean 2-Tab Navigation) */}
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
          className={`tab-btn ${activeTab === 'firewall' ? 'active' : ''}`}
          onClick={() => setActiveTab('firewall')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          Брандмауэр / Доступ
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
                      <label htmlFor="obf-key">Ключ шифрования rtpopus3</label>
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

                {/* Network Mode Selection */}
                <div className="input-group" style={{ marginBottom: '14px' }}>
                  <label>Режим работы сети</label>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '4px' }}>
                    <button
                      type="button"
                      className={`btn btn-sm ${networkMode === 'userspace' ? 'btn' : 'btn-secondary'}`}
                      style={{ padding: '8px', fontSize: '0.8rem', textAlign: 'center' }}
                      onClick={() => handleNetworkModeChange('userspace')}
                    >
                      👤 Userspace + Hosts (без root)
                    </button>
                    <button
                      type="button"
                      className={`btn btn-sm ${networkMode === 'tun' ? 'btn' : 'btn-secondary'}`}
                      style={{ padding: '8px', fontSize: '0.8rem', textAlign: 'center' }}
                      onClick={() => handleNetworkModeChange('tun')}
                    >
                      🛡️ TUN L3 Адаптер (10.42.x.x)
                    </button>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    {networkMode === 'userspace'
                      ? '✓ Автоматический проброс портов в фоне. Имена *.vkturn синхронизируются в hosts.'
                      : '✓ Создает системный интерфейс turnp2p0 (10.42.0.0/16). Требует root/admin.'}
                  </div>
                </div>

                <button
                  className="btn"
                  onClick={handleConnect}
                  disabled={!vkLink}
                  style={{ width: '100%', marginTop: '4px' }}
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
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                      <span className="badge" style={{ color: '#34d399', background: 'rgba(52, 211, 153, 0.15)' }}>
                        {localInfo.networkMode === 'tun' ? '🛡️ TUN L3' : '👤 Userspace'}
                      </span>
                      <span className="badge" style={{ color: '#60a5fa' }}>{localInfo.streams} Потоков</span>
                      <span
                        className="badge obf"
                        style={{ cursor: 'pointer' }}
                        onClick={() => copyToClipboard(localInfo.obfKey, 'Ключ шифрования')}
                        title="Нажмите для копирования ключа шифрования rtpopus3"
                      >
                        🔒 rtpopus3
                      </span>
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '0.88rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Виртуальный IP: </span>
                      <strong
                        style={{ cursor: 'pointer', color: '#60a5fa' }}
                        onClick={() => copyToClipboard(localInfo.virtualIp, 'Виртуальный IP')}
                        title="Нажмите для копирования"
                      >
                        {localInfo.virtualIp}
                      </strong>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Домен: </span>
                      <strong
                        style={{ cursor: 'pointer', color: '#c084fc' }}
                        onClick={() => copyToClipboard(localInfo.domain, 'Домен')}
                        title="Нажмите для копирования"
                      >
                        {localInfo.domain}
                      </strong>
                    </div>
                  </div>

                  {localInfo.relayAddr && (
                    <div style={{ marginTop: '8px', fontSize: '0.82rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255,255,255,0.04)', padding: '6px 10px', borderRadius: '6px' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Ваш TURN Relay: </span>
                        <code style={{ color: '#38bdf8', fontWeight: 600 }}>{localInfo.relayAddr}</code>
                      </div>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        style={{ padding: '2px 8px', fontSize: '0.72rem' }}
                        onClick={() => copyToClipboard(localInfo.relayAddr, 'Relay адрес')}
                      >
                        Копировать Relay
                      </button>
                    </div>
                  )}

                  {/* Compact Obfuscation Key Row */}
                  <div style={{ marginTop: '8px', padding: '8px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.78rem' }}>
                    <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span>🔑 Ключ маскировки:</span>
                      <span style={{ fontFamily: 'monospace', color: '#93c5fd' }}>
                        {localInfo.obfKey ? `${localInfo.obfKey.substring(0, 16)}...${localInfo.obfKey.substring(localInfo.obfKey.length - 8)}` : 'Не задан'}
                      </span>
                    </div>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      style={{ padding: '2px 8px', fontSize: '0.72rem' }}
                      onClick={() => copyToClipboard(localInfo.obfKey, 'Ключ маскировки')}
                    >
                      Копировать
                    </button>
                  </div>

                  {localInfo.hostsSync && (
                    <div style={{ fontSize: '0.75rem', color: '#34d399', marginTop: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <span>✓</span>
                      <span>Файл hosts синхронизирован: домены <strong>*.vkturn</strong> доступны для прямого подключения</span>
                    </div>
                  )}
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
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Авто-обмен через WebSocket</span>
                  </div>

                  {/* Manual peer connect helper */}
                  <form onSubmit={handleManualConnectPeer} style={{ display: 'flex', gap: '8px', marginBottom: '12px', background: 'rgba(255,255,255,0.03)', padding: '8px', borderRadius: '8px' }}>
                    <input
                      className="input"
                      style={{ padding: '6px 10px', fontSize: '0.8rem', flex: 1 }}
                      placeholder="Relay друга (напр. 91.231.135.87:51234)"
                      value={manualPeerAddr}
                      onChange={e => setManualPeerAddr(e.target.value)}
                    />
                    <button
                      type="submit"
                      className="btn btn-secondary btn-sm"
                      style={{ whiteSpace: 'nowrap', padding: '6px 12px', fontSize: '0.78rem' }}
                    >
                      🔗 Прямой коннект
                    </button>
                  </form>
                  {manualConnectMsg && (
                    <p style={{ fontSize: '0.75rem', color: manualConnectMsg.includes('Ошибка') ? '#fca5a5' : '#34d399', marginBottom: '8px' }}>
                      {manualConnectMsg}
                    </p>
                  )}

                  {peers.length === 0 ? (
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '16px 0' }}>
                      Ожидание обнаружения других участников в комнате...
                    </p>
                  ) : (
                    peers.map(p => (
                      <div key={p.id} className="peer-row" style={{ alignItems: 'center' }}>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <strong>{p.name}</strong>
                            <strong
                              style={{ color: '#c084fc', cursor: 'pointer', fontSize: '0.82rem' }}
                              onClick={() => copyToClipboard(p.domain, `Домен ${p.domain}`)}
                              title="Нажмите для копирования домена"
                            >
                              {p.domain}
                            </strong>
                          </div>
                          {p.sharedPorts && p.sharedPorts.length > 0 && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Открытые сервисы:</span>
                              {p.sharedPorts.map(port => (
                                <span
                                  key={port}
                                  className="badge"
                                  style={{ padding: '2px 6px', fontSize: '0.72rem', background: 'rgba(52, 211, 153, 0.15)', color: '#34d399', border: '1px solid rgba(52, 211, 153, 0.3)', cursor: 'pointer' }}
                                  onClick={() => copyToClipboard(`${p.domain}:${port}`, `${p.domain}:${port}`)}
                                  title={`Кликните чтобы скопировать адрес ${p.domain}:${port} для игры`}
                                >
                                  :{port} (Готов)
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span
                            className="badge"
                            style={{ cursor: 'pointer' }}
                            onClick={() => copyToClipboard(p.virtualIp, `IP ${p.virtualIp}`)}
                            title="Копировать IP"
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
                  Открытые сервисы на вашем ПК (будут доступны друзьям):
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
      </div>
    </div>
  );
}

export default App;
