export namespace main {
	
	export class ConnectionStatus {
	    connected: boolean;
	    statusText: string;
	    virtualIp: string;
	    domain: string;
	    nodeName: string;
	    relayAddr: string;
	    obfProfile: string;
	    obfKey: string;
	    link: string;
	    firewallMode: string;
	    sharedPorts: number[];
	    streamsCount: number;
	    networkMode: string;
	    hostsSync: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.connected = source["connected"];
	        this.statusText = source["statusText"];
	        this.virtualIp = source["virtualIp"];
	        this.domain = source["domain"];
	        this.nodeName = source["nodeName"];
	        this.relayAddr = source["relayAddr"];
	        this.obfProfile = source["obfProfile"];
	        this.obfKey = source["obfKey"];
	        this.link = source["link"];
	        this.firewallMode = source["firewallMode"];
	        this.sharedPorts = source["sharedPorts"];
	        this.streamsCount = source["streamsCount"];
	        this.networkMode = source["networkMode"];
	        this.hostsSync = source["hostsSync"];
	    }
	}

}

export namespace p2p {
	
	export class Peer {
	    id: string;
	    name: string;
	    virtualIp: string;
	    domain: string;
	    relayAddr: string;
	    sharedPorts: number[];
	    ping: number;
	    // Go type: time
	    lastSeen: any;
	
	    static createFrom(source: any = {}) {
	        return new Peer(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.virtualIp = source["virtualIp"];
	        this.domain = source["domain"];
	        this.relayAddr = source["relayAddr"];
	        this.sharedPorts = source["sharedPorts"];
	        this.ping = source["ping"];
	        this.lastSeen = this.convertValues(source["lastSeen"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace proxy {
	
	export class ForwardingRule {
	    id: string;
	    name: string;
	    protocol: string;
	    localIp: string;
	    localPort: number;
	    remoteIp: string;
	    remotePort: number;
	    enabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ForwardingRule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.protocol = source["protocol"];
	        this.localIp = source["localIp"];
	        this.localPort = source["localPort"];
	        this.remoteIp = source["remoteIp"];
	        this.remotePort = source["remotePort"];
	        this.enabled = source["enabled"];
	    }
	}

}

