// Runs the extension's background.js with fake chrome and fetch objects, and prints what it did as JSON.
// tests/test_extension.py runs this with Node and checks the output.
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(process.argv[2], "utf8");
const RULES = '{"version":5,"rules":[{"domain_suffix":["example.com"]}]}';

function fakeChrome() {
  const listeners = {};
  const on = (name) => ({ addListener: (fn) => (listeners[name] = fn) });
  const local = {}, session = {}, icons = {}, titles = {}, badges = {}, badgeLog = [];
  const tabs = { 1: "https://www.example.com/page", 2: "https://other.org/", 3: "chrome://extensions/" };
  const area = (store) => ({
    get: async (k) => (typeof k === "string" ? (k in store ? { [k]: store[k] } : {}) : { ...k, ...store }),
    set: async (o) => Object.assign(store, o),
    remove: async (k) => { for (const key of [].concat(k)) delete store[key]; },
  });
  const chrome = {
    runtime: { getURL: (p) => "ext://" + p, onInstalled: on("installed"), onStartup: on("startup") },
    storage: { local: area(local), session: area(session) },
    declarativeNetRequest: { updateDynamicRules: async () => {} },
    alarms: { create: async () => {}, onAlarm: on("alarm") },
    tabs: {
      query: async () => Object.entries(tabs).map(([id, url]) => ({ id: Number(id), url })),
      get: async (id) => ({ id, url: tabs[id] }),
      onActivated: on("activated"), onUpdated: on("updated"), onRemoved: on("removed"),
    },
    action: {
      setIcon: async ({ tabId, path }) => (icons[tabId] = path[16]),
      setTitle: async ({ tabId, title }) => (titles[tabId] = title),
      setBadgeText: async ({ tabId, text }) => { badges[tabId] = text; badgeLog.push([tabId, text]); },
      setBadgeBackgroundColor: () => {},
      setBadgeTextColor: () => {},
      onClicked: on("clicked"),
    },
    webRequest: { onErrorOccurred: on("error"), onBeforeRequest: on("request") },
  };
  return { chrome, listeners, icons, titles, badges, badgeLog, session };
}

async function run(config) {
  const f = fakeChrome();
  const fetch = async (url) => url === "ext://config.json"
    ? { ok: true, status: 200, json: async () => config }
    : { ok: true, text: async () => RULES };
  const ctx = vm.createContext({ chrome: f.chrome, fetch, console: { log() {}, error() {} }, Date, URL });
  vm.runInContext(source, ctx);
  await f.listeners.clicked({ id: 1 });  // a click in tab 1 syncs
  const clickLog = f.badgeLog.filter(([tabId]) => tabId === 1).map(([, text]) => text);
  const settle = () => new Promise((r) => setTimeout(r, 20));
  // two blocked requests from the listed tab to an unlisted domain, one to a listed domain, one unrelated error
  const blocked = (url, error = "net::ERR_BLOCKED_BY_CLIENT") =>
    f.listeners.error({ tabId: 1, url, initiator: "https://www.example.com", error });
  await blocked("https://tracker.net/a.js");
  await blocked("https://tracker.net/b.js");
  await blocked("https://cdn.example.com/c.js");
  await blocked("https://tracker.net/d.js", "net::ERR_CONNECTION_RESET");
  await settle();
  const afterBlocks = { ...f.titles };
  const badgesAfterBlocks = { ...f.badges };
  f.listeners.request({ tabId: 1, type: "main_frame" });  // a new page in tab 1
  await settle();
  return { icons: f.icons, titlesAfterBlocks: afterBlocks, titlesAfterNavigation: f.titles,
           badgesAfterBlocks, badgesAfterNavigation: { ...f.badges }, clickLog };
}

const ok = await run({ gist_url: "https://g/x", user_agent: "test-agent/1" });
const failed = await run({ gist_url: "https://g/x" });  // no user_agent: the sync fails
console.log(JSON.stringify({ ok, failed }));
