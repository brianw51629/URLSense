const $ = id => document.getElementById(id);

// The URL to check, normalized the same way Chrome normalizes it, without any #fragment.
const target = (() => {
  try {
    const u = new URL(location.hash.slice(1));
    u.hash = "";
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : "";
  } catch {
    return "";
  }
})();
const CACHE_KEY = "safe:" + target;
const host = target ? new URL(target).hostname : "";

/**
 * True for addresses that are part of logging in: sign-in pages, and the hops back from a
 * sign-in service, which carry one-time codes (?code=…&state=…, SAML responses, tokens).
 */
function isSignInUrl(href) {
  const u = new URL(href);
  const signInSegment = /^(log-?in|log-?on|sign-?in|sign-?on|sso|saml2?|oauth2?|openid|oidc|auth|authorize|authorization|callback|session|sessions)$/i;
  if (u.pathname.split("/").some(seg => signInSegment.test(seg))) return true;
  const q = u.searchParams;
  return (q.has("code") && q.has("state")) || q.has("SAMLResponse") || q.has("SAMLRequest")
      || q.has("id_token") || q.has("access_token");
}

function show(verdict, heading, details, confidence = "") {
  $("card").className = verdict;
  $("verdict").textContent = heading;
  $("confidence").textContent = confidence;
  $("details").textContent = details;
  const done = verdict !== "checking";
  $("back").hidden = !done;
  $("proceed").hidden = !done || verdict === "blocked";
  $("retry").hidden = verdict !== "error";
}

async function proceed() {
  const reply = await chrome.runtime.sendMessage({ type: "allowOnce", url: target });
  if (!reply?.ok) {
    show("blocked", "Couldn't open the page", reply?.error || "The extension couldn't let this page through.");
    return;
  }
  location.replace(reply.url);
}

async function goBack() {
  if (history.length > 1) { history.back(); return; }
  const tab = await chrome.tabs.getCurrent();   // nothing to go back to: close the tab instead
  if (tab) chrome.tabs.remove(tab.id);
}

async function check() {
  show("checking", "Checking…", "If URLSense needs to ask you something, its window will pop up.");

  const cached = (await chrome.storage.session.get(CACHE_KEY))[CACHE_KEY];
  if (cached && Date.now() - cached < URLSENSE.SAFE_CACHE_MINUTES * 60_000) return proceed();

  // Logging in: check only the site itself (https://host/), never the sign-in address with its
  // codes. (Sites that already passed are trusted and never reach this page at all.)
  const signIn = isSignInUrl(target);
  const urlToCheck = signIn ? new URL(target).origin + "/" : target;

  let r;
  try {
    const resp = await fetch(`http://127.0.0.1:${URLSENSE.PORT}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlToCheck })
    });
    if (resp.status === 403) throw new Error("URLSense refused the request. Check EXTENSION_ID in config.properties.");
    if (!resp.ok && resp.status !== 429) throw new Error("URLSense answered with HTTP " + resp.status + ".");
    r = await resp.json();
  } catch (e) {
    const msg = e instanceof TypeError
      ? "The URLSense app isn't running, so this link hasn't been checked. Start the app and try again."
      : e.message;
    show("error", "Not checked", msg);
    return;
  }

  const details = (signIn ? "This is a sign-in address, so only the site " + host + " was checked.\n\n" : "")
      + r.reasoning + (r.redFlags ? "\n\n" + r.redFlags : "");
  switch (r.verdict) {
    case "safe":
      await chrome.storage.session.set({ [CACHE_KEY]: Date.now() });
      await chrome.runtime.sendMessage({ type: "trustSite", url: target });   // stop checking this site
      return proceed();
    case "unsafe":
      show("unsafe", "Unsafe", details, r.confidence);
      break;
    case "unsure":
      show("unsure", "Unsure", details, r.confidence);
      break;
    default:
      show("error", "Not checked", details);
  }
}

if (window.top !== window) {
  // Another site has put this page inside a frame, likely to trick a click on "Open anyway".
  // Show nothing and contact nothing.
  document.body.replaceChildren();
} else {
  $("url").textContent = target;
  $("back").addEventListener("click", goBack);
  $("retry").addEventListener("click", check);
  $("proceed").addEventListener("click", proceed);

  if (!target) {
    show("blocked", "Nothing to check", "This page was opened without a link to check.");
  } else if (document.prerendering) {
    // Chrome sometimes preloads the top search result. Don't start a check (and pop up the app)
    // until the user actually opens it.
    document.addEventListener("prerenderingchange", check, { once: true });
  } else {
    check();
  }
}
