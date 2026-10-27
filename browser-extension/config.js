// Shared settings for the background worker and the check page.
const URLSENSE = {
  // Must match LISTENER_PORT in the Java app's config.properties (default 47615).
  PORT: 47615,

  // Pages on these hosts (and their subdomains) load without a check. Keep it short:
  // www.google.com is here so typing a search doesn't trigger a check. Don't add plain
  // "google.com", because that would also skip sites.google.com, a common phishing host.
  TRUSTED_DOMAINS: ["www.google.com", "localhost", "127.0.0.1"],

  // Sign-in services that many sites send you through when you log in. Pages on these exact hosts
  // (and their subdomains) are never checked. Lookalike domains are not covered by this list.
  SIGN_IN_DOMAINS: [
    "accounts.google.com",
    "login.microsoftonline.com", "login.live.com", "login.microsoft.com",
    "appleid.apple.com", "idmsa.apple.com"
  ],

  // How long a "safe" verdict is remembered for the same URL (this browser session only).
  // Sites that pass are also trusted as a whole until Chrome closes, so this mostly matters
  // when a trusted site's rule was cleared.
  SAFE_CACHE_MINUTES: 30
};
