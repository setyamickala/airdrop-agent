// Agent EIP-1193 provider. Every call is forwarded to Python (binding __aaWallet)
// where policy, scam_check and caps decide. The page never signs by itself.
(() => {
  const conf = window.__AA_CONF || {};
  if (!conf.address || window.__aaEthereumInstalled) return;
  window.__aaEthereumInstalled = true;

  const listeners = {};
  let chainId = conf.chainId || "0x1";
  let selected = conf.address;

  const emit = (ev, data) => (listeners[ev] || []).slice().forEach((fn) => { try { fn(data); } catch (_) {} });

  async function request({ method, params }) {
    if (method === "eth_chainId") return chainId;
    if (method === "eth_accounts" && !conf.connected) return [];
    const raw = await window.__aaWallet(method, JSON.stringify(params || []));
    const res = JSON.parse(raw || "{}");
    if (res.error) {
      const err = new Error(res.error.message || "Rejected");
      err.code = res.error.code || 4001;
      throw err;
    }
    if (method === "wallet_switchEthereumChain" || method === "wallet_addEthereumChain") {
      chainId = res.chainId || chainId;
      emit("chainChanged", chainId);
      return null;
    }
    if (method === "eth_requestAccounts" || method === "wallet_requestPermissions") {
      conf.connected = true;
      const accts = res.result && res.result[0] ? res.result : [selected];
      selected = accts[0];
      emit("accountsChanged", accts);
      emit("connect", { chainId });
      return method === "wallet_requestPermissions" ? [{ parentCapability: "eth_accounts" }] : accts;
    }
    return res.result;
  }

  const provider = {
    isMetaMask: true,
    isRabby: false,
    isAgentWallet: true,
    get chainId() { return chainId; },
    get networkVersion() { return String(parseInt(chainId, 16)); },
    get selectedAddress() { return conf.connected ? selected : null; },
    request,
    enable: () => request({ method: "eth_requestAccounts" }),
    on(ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); return provider; },
    once(ev, fn) { const w = (d) => { provider.removeListener(ev, w); fn(d); }; return provider.on(ev, w); },
    removeListener(ev, fn) { listeners[ev] = (listeners[ev] || []).filter((f) => f !== fn); return provider; },
    off(ev, fn) { return provider.removeListener(ev, fn); },
    removeAllListeners(ev) { if (ev) delete listeners[ev]; else Object.keys(listeners).forEach((k) => delete listeners[k]); },
    send(a, b) {
      if (typeof a === "string") return request({ method: a, params: b });
      if (typeof b === "function") return request(a).then((r) => b(null, { id: a.id, jsonrpc: "2.0", result: r }), (e) => b(e));
      return request(a);
    },
    sendAsync(payload, cb) {
      request(payload).then((r) => cb(null, { id: payload.id, jsonrpc: "2.0", result: r }), (e) => cb(e));
    },
    _metamask: { isUnlocked: async () => true, requestBatch: async (b) => Promise.all(b.map(request)) },
  };

  try {
    Object.defineProperty(window, "ethereum", { value: provider, writable: false, configurable: true });
  } catch (_) { window.ethereum = provider; }

  const info = {
    uuid: conf.uuid || "6d0b8a6e-0000-4000-8000-000000000001",
    name: "MetaMask", icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%23f6851b'/%3E%3C/svg%3E",
    rdns: "io.metamask",
  };
  const announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider",
    { detail: Object.freeze({ info, provider }) }));
  window.addEventListener("eip6963:requestProvider", announce);
  announce();
  setTimeout(() => emit("connect", { chainId }), 0);
})();
