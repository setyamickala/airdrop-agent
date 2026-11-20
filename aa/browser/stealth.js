// Small, honest stealth shim: remove the obvious automation tells without faking
// a full browser fingerprint (no canvas/WebGL/audio/font spoofing is implemented
// here — do not claim otherwise).
//
// This file is a TEMPLATE. aa/browser/fingerprint.py fills its tokens
// with one identity's deterministic values before it is injected as an init
// script (see fingerprint.render_stealth_js). Do not load this file raw.
(() => {
  const LANGUAGES = __AA_LANGUAGES_JSON__;
  const HARDWARE_CONCURRENCY = __AA_HARDWARE_CONCURRENCY__;
  const DEVICE_MEMORY = __AA_DEVICE_MEMORY__;
  const PLATFORM = __AA_PLATFORM__;
  try {
    Object.defineProperty(navigator, "webdriver", { get: () => undefined });
  } catch (_) {}
  try {
    if (!window.chrome) window.chrome = {};
    if (!window.chrome.runtime) window.chrome.runtime = {};
  } catch (_) {}
  // navigator.plugins must look like real Plugin objects, not numbers:
  // each plugin carries name/description/filename and a MimeType entry, and
  // the array itself answers item()/namedItem() like a PluginArray.
  function _mime(type, suffixes, description, plugin) {
    return { type, suffixes, description, enabledPlugin: plugin };
  }
  function _plugin(name, description, filename, type, suffixes) {
    const plug = { name, description, filename, length: 1,
      item(i) { return this[i] || null; },
      namedItem(n) { return this[0] && this[0].type === n ? this[0] : null; } };
    plug[0] = _mime(type, suffixes, description, plug);
    return plug;
  }
  const _plugins = [
    _plugin("Chrome PDF Plugin", "Portable Document Format", "internal-pdf-viewer",
            "application/pdf", "pdf"),
    _plugin("Chrome PDF Viewer", "Portable Document Format", "internal-pdf-viewer",
            "application/pdf", "pdf"),
    _plugin("Native Client", "Native Client Executable", "internal-nacl-plugin",
            "application/x-nacl", ""),
  ];
  _plugins.item = function (i) { return this[i] || null; };
  _plugins.namedItem = function (n) {
    for (const p of this) if (p.name === n) return p;
    return null;
  };
  try {
    Object.defineProperty(navigator, "languages", { get: () => LANGUAGES.slice() });
    Object.defineProperty(navigator, "platform", { get: () => PLATFORM });
    Object.defineProperty(navigator, "plugins", { get: () => _plugins });
    Object.defineProperty(navigator, "hardwareConcurrency", { get: () => HARDWARE_CONCURRENCY });
    Object.defineProperty(navigator, "deviceMemory", { get: () => DEVICE_MEMORY });
  } catch (_) {}
  const origQuery = window.navigator.permissions && window.navigator.permissions.query;
  if (origQuery) {
    window.navigator.permissions.query = (p) =>
      p && p.name === "notifications" ? Promise.resolve({ state: Notification.permission }) : origQuery(p);
  }
})();
