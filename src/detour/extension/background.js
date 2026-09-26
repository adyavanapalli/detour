// Detour Sentry: Background Service Worker (Manifest V3)

const POLL_MINUTES = 15;
const ALARM_SYNC = "sync-rules";
// Settings that older versions kept in storage. The values now come from config.json only.
const LEGACY_KEYS = ["gist_url", "user_agent", "poll_minutes"];

const RULE_MAIN_FRAME = 1001;
const RULE_SUBRESOURCES = 1002;
const RULE_BLOCK_LEAKS = 1003;

const SUBRESOURCE_TYPES = [
  "sub_frame",
  "stylesheet",
  "script",
  "image",
  "font",
  "object",
  "xmlhttprequest",
  "ping",
  "csp_report",
  "media",
  "websocket",
  "webtransport",
  "webbundle",
  "other",
];

const BUILTIN_HOSTS = ["localhost", "127.0.0.1", "::1"];

// -------------------------------------------------------------
// Storage & State Helpers
// -------------------------------------------------------------

// detour linux install writes config.json from the [linux] table of ~/.config/detour/config.toml:
// gist_url comes from rules_url, and user_agent comes from user_agent.
let configPromise = null;

function getConfig() {
  configPromise ??= fetch(chrome.runtime.getURL("config.json"))
    .then((res) => {
      if (!res.ok) throw new Error(`config.json: HTTP ${res.status}`);
      return res.json();
    })
    .then((conf) => {
      if (!conf.gist_url || !conf.user_agent) {
        throw new Error("config.json must set gist_url and user_agent. Run detour linux install.");
      }
      return conf;
    })
    .catch((err) => {
      configPromise = null; // read the file again on the next attempt
      throw err;
    });
  return configPromise;
}

async function getState() {
  return chrome.storage.local.get({ domains: [], last_sync: 0, last_error: null });
}

// -------------------------------------------------------------
// JSONC Parser
// -------------------------------------------------------------

function stripJsonComments(text) {
  let out = "";
  let inString = false;
  let inSingleComment = false;
  let inMultiComment = false;
  let escape = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const next = text[i + 1];

    if (inSingleComment) {
      if (char === "\n") {
        inSingleComment = false;
        out += char;
      }
      continue;
    }

    if (inMultiComment) {
      if (char === "*" && next === "/") {
        inMultiComment = false;
        i++;
      }
      continue;
    }

    if (inString) {
      out += char;
      if (escape) {
        escape = false;
      } else if (char === "\\") {
        escape = true;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }

    if (char === '"') {
      inString = true;
      out += char;
      continue;
    }

    if (char === "/" && next === "/") {
      inSingleComment = true;
      i++;
      continue;
    }

    if (char === "/" && next === "*") {
      inMultiComment = true;
      i++;
      continue;
    }

    out += char;
  }

  return out.replace(/(,\s*)(\}|\])/g, "$2");
}

function parseDomainList(rawText) {
  const clean = stripJsonComments(rawText);
  const data = JSON.parse(clean);
  const domains = new Set();

  if (Array.isArray(data.rules)) {
    for (const rule of data.rules) {
      if (Array.isArray(rule.domain_suffix)) {
        for (const d of rule.domain_suffix) {
          if (typeof d === "string") domains.add(normalizeDomain(d));
        }
      }
      if (Array.isArray(rule.domain)) {
        for (const d of rule.domain) {
          if (typeof d === "string") domains.add(normalizeDomain(d));
        }
      }
    }
  }

  return [...domains].filter(Boolean).sort();
}

function normalizeDomain(raw) {
  let d = raw.trim().toLowerCase();
  for (const prefix of ["https://", "http://", "wss://", "ws://"]) {
    if (d.startsWith(prefix)) d = d.slice(prefix.length);
  }
  d = d.split("/")[0].split(":")[0].replace(/\.$/, "");
  if (d.startsWith("*.")) d = d.slice(2);
  return d;
}

function getPlatformFromUserAgent(ua) {
  if (!ua) return '"Windows"';
  const lower = ua.toLowerCase();
  if (lower.includes("windows")) return '"Windows"';
  if (lower.includes("macintosh") || lower.includes("mac os")) return '"macOS"';
  if (lower.includes("android")) return '"Android"';
  if (lower.includes("linux")) return '"Linux"';
  return '"Windows"';
}

// -------------------------------------------------------------
// Declarative Net Request Rules
// -------------------------------------------------------------

async function applyDnrRules(domains, userAgent) {
  const removeRuleIds = [RULE_MAIN_FRAME, RULE_SUBRESOURCES, RULE_BLOCK_LEAKS];
  const addRules = [];

  if (domains.length > 0) {
    const setHeaders = {
      type: "modifyHeaders",
      requestHeaders: [
        { header: "User-Agent", operation: "set", value: userAgent },
        { header: "Sec-Ch-Ua-Platform", operation: "set", value: getPlatformFromUserAgent(userAgent) },
      ],
    };

    // Rule 1: Modify User-Agent and Sec-Ch-Ua-Platform for top-level navigation
    addRules.push({
      id: RULE_MAIN_FRAME,
      priority: 2,
      action: setHeaders,
      condition: {
        requestDomains: domains,
        resourceTypes: ["main_frame"],
      },
    });

    // Rule 2: Modify headers for approved subresources matching listed domains
    addRules.push({
      id: RULE_SUBRESOURCES,
      priority: 2,
      action: setHeaders,
      condition: {
        initiatorDomains: domains,
        requestDomains: domains,
        resourceTypes: SUBRESOURCE_TYPES,
      },
    });

    // Rule 3: Anti-leak sandbox: block any subresource to unlisted external domains
    addRules.push({
      id: RULE_BLOCK_LEAKS,
      priority: 1,
      action: {
        type: "block",
      },
      condition: {
        initiatorDomains: domains,
        excludedRequestDomains: [...domains, ...BUILTIN_HOSTS],
        resourceTypes: SUBRESOURCE_TYPES,
      },
    });
  }

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules,
  });

  console.log(
    `[Detour Sentry] Applied ${addRules.length} dynamic rules for ${domains.length} domains`
  );
}

// -------------------------------------------------------------
// Gist Synchronization
// -------------------------------------------------------------

async function syncFromGist() {
  try {
    const { gist_url, user_agent } = await getConfig();
    const res = await fetch(gist_url, { cache: "no-store" });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    const text = await res.text();
    const domains = parseDomainList(text);

    await applyDnrRules(domains, user_agent);

    await chrome.storage.local.set({
      domains,
      last_sync: Date.now(),
      last_error: null,
    });
  } catch (err) {
    const errorMsg = `Sync failed: ${err.message}`;
    console.error(`[Detour Sentry] ${errorMsg}`);
    await chrome.storage.local.set({ last_error: errorMsg });
  }
  await updateAllTabs();
}

// -------------------------------------------------------------
// Toolbar icon: the whole user interface
// -------------------------------------------------------------
//
// There is no popup. The icon shows the state of the active tab, the badge shows the number of
// blocked requests on it (like uBlock Origin), the tooltip gives the details, and a click syncs
// the rule list at once.
//   blue (icon-*):        the tab is on a listed domain: tunneled, with the User-Agent set
//   gray (icon-direct-*): the tab is not on a listed domain, or it is not a web page
//   red (icon-error-*):   the last sync failed; the rules from the last good sync still apply

const WEB_PROTOCOLS = ["http:", "https:", "ws:", "wss:"];

function iconSet(prefix) {
  return { 16: `icons/${prefix}-16.png`, 32: `icons/${prefix}-32.png` };
}

const ICONS = {
  tunneled: iconSet("icon"),
  direct: iconSet("icon-direct"),
  error: iconSet("icon-error"),
};

// One badge style for every tab. Only the text changes per tab.
chrome.action.setBadgeBackgroundColor({ color: "#475569" });
chrome.action.setBadgeTextColor({ color: "#ffffff" });

function badgeText(blocked) {
  if (blocked <= 0) return "";
  return blocked > 999 ? "999+" : String(blocked);
}

function isProtectedDomain(hostname, domains) {
  if (!hostname) return false;
  const host = hostname.toLowerCase();
  for (const d of domains) {
    if (host === d || host.endsWith("." + d)) {
      return true;
    }
  }
  return false;
}

function hostOf(url) {
  try {
    const parsed = new URL(url);
    return WEB_PROTOCOLS.includes(parsed.protocol) ? parsed.hostname : null;
  } catch {
    return null;
  }
}

function syncLine(state) {
  if (!state.last_sync) return "Never synced";
  const time = new Date(state.last_sync).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  return `Synced at ${time}`;
}

// The icon, badge, and tooltip for a tab, from its URL, the sync state, and its blocked-request count.
// The badge carries the count, so the tooltip does not repeat it.
function tabView(url, state, blocked) {
  const host = hostOf(url);
  const listed = Boolean(host) && isProtectedDomain(host, state.domains);
  let kind = listed ? "tunneled" : "direct";
  const lines = [listed ? "TUNNELED" : "DIRECT"];
  if (state.last_error) {
    kind = "error";
    lines.unshift(state.last_error);
  }
  lines.push(syncLine(state), "Click to sync now");
  return {
    icon: ICONS[kind],
    badge: listed ? badgeText(blocked) : "",
    title: `Detour Sentry\n${lines.join("\n")}`,
  };
}

async function refreshTab(tabId, url) {
  if (tabId === undefined || tabId < 0) return;
  try {
    if (url === undefined) url = (await chrome.tabs.get(tabId)).url;
    const key = blockedKey(tabId);
    const [state, counts] = await Promise.all([getState(), chrome.storage.session.get(key)]);
    const view = tabView(url, state, counts[key] || 0);
    await chrome.action.setIcon({ tabId, path: view.icon });
    await chrome.action.setBadgeText({ tabId, text: view.badge });
    await chrome.action.setTitle({ tabId, title: view.title });
  } catch {
    // The tab closed while we worked.
  }
}

async function updateAllTabs() {
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map((tab) => refreshTab(tab.id, tab.url)));
}

chrome.tabs.onActivated.addListener((info) => refreshTab(info.tabId));

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === "loading") {
    refreshTab(tabId, tab.url);
  }
});

// A per-tab badge hides the global one, so the progress mark goes on the clicked tab.
// The sync refreshes every tab, which puts the count back.
chrome.action.onClicked.addListener(async (tab) => {
  await chrome.action.setBadgeText({ tabId: tab.id, text: "…" });
  try {
    await syncFromGist();
  } finally {
    await refreshTab(tab.id);
  }
});

// -------------------------------------------------------------
// Blocked-request count, per tab
// -------------------------------------------------------------
//
// Rule RULE_BLOCK_LEAKS blocks requests from a listed page to an unlisted domain. Chrome reports
// every request that an extension blocked as net::ERR_BLOCKED_BY_CLIENT. We count those that match
// the rule. If another extension blocked the same request, it counts too. The count lives in
// session storage, because the service worker stops when it is idle, and it resets when the tab
// loads a new page.

function blockedKey(tabId) {
  return `blocked_${tabId}`;
}

let countQueue = Promise.resolve(); // one update at a time, so no increment is lost

function changeCount(tabId, change) {
  countQueue = countQueue.then(async () => {
    const key = blockedKey(tabId);
    const { [key]: count = 0 } = await chrome.storage.session.get(key);
    await chrome.storage.session.set({ [key]: change(count) });
  });
  return countQueue.then(() => refreshTab(tabId));
}

chrome.webRequest.onErrorOccurred.addListener(
  async (details) => {
    if (details.error !== "net::ERR_BLOCKED_BY_CLIENT" || details.tabId < 0) return;
    const { domains } = await getState();
    const from = details.initiator ? hostOf(details.initiator) : null;
    if (!isProtectedDomain(from, domains) || isProtectedDomain(hostOf(details.url), domains)) return;
    changeCount(details.tabId, (count) => count + 1);
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId >= 0) changeCount(details.tabId, () => 0);
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(blockedKey(tabId)));

// -------------------------------------------------------------
// Alarms & Lifecycle
// -------------------------------------------------------------

async function setupAlarm() {
  // An alarm with the same name replaces the old one, including an old interval.
  await chrome.alarms.create(ALARM_SYNC, { periodInMinutes: POLL_MINUTES });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_SYNC) {
    syncFromGist();
  }
});

// Also runs on an update, so a new config.json takes effect at once.
chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.remove(LEGACY_KEYS);
  await setupAlarm();
  syncFromGist();
});

// Chrome forgets per-tab icons when it restarts, so set them again.
chrome.runtime.onStartup.addListener(() => {
  setupAlarm();
  updateAllTabs();
});
