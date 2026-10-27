importScripts("config.js");

const CHECK_PAGE = chrome.runtime.getURL("check.html");
const GUARD_RULE_ID = 1;
const PASS_SECONDS = 10;   // an approved URL must start loading within this window

/**
 * One rule does the interception: every top-level http(s) page load, whether from a clicked link,
 * a Google result, or a URL typed in the address bar, is redirected to check.html with the
 * original URL after the '#'. The page never starts loading until the check page lets it.
 *
 * Only GET navigations are intercepted. Form submissions (POST), such as sending your username
 * and password, go straight through: redirecting them would throw away what you typed. The page
 * holding the form was itself checked when it loaded.
 */
async function installGuardRule() {
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [GUARD_RULE_ID],
    addRules: [{
      id: GUARD_RULE_ID,
      priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: CHECK_PAGE + "#\\0" } },
      condition: {
        regexFilter: "^https?://.*",
        resourceTypes: ["main_frame"],
        requestMethods: ["get"],
        excludedRequestDomains: [...URLSENSE.TRUSTED_DOMAINS, ...URLSENSE.SIGN_IN_DOMAINS]
      }
    }]
  });
}
chrome.runtime.onInstalled.addListener(installGuardRule);
chrome.runtime.onStartup.addListener(installGuardRule);

// ---------------------------------------------------------------- one-time passes
//
// A pass is a short-lived "allow" rule for ONE exact URL in ONE tab. It is removed as soon as
// that tab commits a page, fails a load, closes, or after PASS_SECONDS, whichever comes first.
// Passes are tracked in session storage because this service worker can be stopped at any time.

async function getPasses() {
  return (await chrome.storage.session.get("passes")).passes || {};
}

async function revokePass(tabId, onlyRuleId) {
  const passes = await getPasses();
  const pass = passes[tabId];
  if (!pass || (onlyRuleId && pass.ruleId !== onlyRuleId)) return;
  delete passes[tabId];
  await chrome.storage.session.set({ passes });
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [pass.ruleId] });
}

function escapeRegex(s) {
  return s.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

/** Matches exactly this URL and nothing else (no other paths, no subdomains). */
function exactUrlCondition(url, tabId) {
  const base = { tabIds: [tabId], resourceTypes: ["main_frame"], isUrlFilterCaseSensitive: true };
  return /[*^|]/.test(url)
    ? { ...base, regexFilter: "^" + escapeRegex(url) + "$" }
    : { ...base, urlFilter: "|" + url + "|" };
}

async function grantPass(tabId, url) {
  const prev = (await getPasses())[tabId];
  if (prev && prev.url === url && Date.now() - prev.created < PASS_SECONDS * 1000) {
    // The same URL bounced straight back to the check page, so the exact-match rule didn't match
    // what Chrome actually requested. Stop rather than loop or fall back to a looser rule.
    await revokePass(tabId);
    return { ok: false, error: "Chrome changed this address while opening it, so it can't be let through safely." };
  }
  await revokePass(tabId);

  const ruleId = 100 + Math.floor(Math.random() * 1e9);
  await chrome.declarativeNetRequest.updateSessionRules({
    addRules: [{ id: ruleId, priority: 2, action: { type: "allow" }, condition: exactUrlCondition(url, tabId) }]
  });
  const passes = await getPasses();
  passes[tabId] = { ruleId, url, created: Date.now() };
  await chrome.storage.session.set({ passes });
  setTimeout(() => revokePass(tabId, ruleId), PASS_SECONDS * 1000);
  return { ok: true, url };
}

// ---------------------------------------------------------------- trusted sites
//
// When a page passes the check (verdict "safe"), its host is trusted until Chrome is closed:
// an allow rule for that host means later pages on it (a new Canvas assignment, a different
// query string) load without being sent to the app at all. Only that exact host and its
// subdomains are trusted, not the rest of the parent domain. "Open anyway" never grants this.

async function getTrusted() {
  return (await chrome.storage.session.get("trusted")).trusted || {};
}

async function trustSite(host) {
  const trusted = await getTrusted();
  if (trusted[host]) return;
  const ruleId = 100 + Math.floor(Math.random() * 1e9);
  await chrome.declarativeNetRequest.updateSessionRules({
    addRules: [{
      id: ruleId,
      priority: 2,
      action: { type: "allow" },
      condition: { requestDomains: [host], resourceTypes: ["main_frame"] }
    }]
  });
  const latest = await getTrusted();
  latest[host] = ruleId;
  await chrome.storage.session.set({ trusted: latest });
}

/** Clears passes left behind if the worker was stopped before its timers ran. */
async function revokeExpiredPasses() {
  const passes = await getPasses();
  const live = new Set(Object.values(await getTrusted()));   // trusted-site rules are kept
  for (const [tabId, pass] of Object.entries(passes)) {
    if (Date.now() - pass.created >= PASS_SECONDS * 1000) await revokePass(Number(tabId));
    else live.add(pass.ruleId);
  }
  const orphans = (await chrome.declarativeNetRequest.getSessionRules())
    .map(r => r.id).filter(id => !live.has(id));
  if (orphans.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: orphans });
}
revokeExpiredPasses();

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only our check page, open as a whole tab (never inside another site's frame), may ask.
  if (sender.id !== chrome.runtime.id || !sender.tab || sender.frameId !== 0
      || !sender.url?.startsWith(CHECK_PAGE)) return;
  if (msg?.type !== "allowOnce" && msg?.type !== "trustSite") return;
  let url;
  try {
    url = new URL(msg.url);
  } catch {
    return;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return;
  url.hash = "";
  const work = msg.type === "trustSite"
    ? trustSite(url.hostname).then(() => ({ ok: true }))
    : grantPass(sender.tab.id, url.href);
  work.then(
    sendResponse,
    err => sendResponse({ ok: false, error: String(err) })
  );
  return true; // keep the channel open for the async reply
});

chrome.webNavigation.onCommitted.addListener(({ tabId, frameId, url }) => {
  if (frameId === 0 && !url.startsWith(CHECK_PAGE)) revokePass(tabId);
});
chrome.webNavigation.onErrorOccurred.addListener(({ tabId, frameId }) => {
  if (frameId === 0) revokePass(tabId);   // includes links that turn into downloads
});
chrome.tabs.onRemoved.addListener(tabId => revokePass(tabId));
