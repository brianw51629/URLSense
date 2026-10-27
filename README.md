# URLSense
Senior Project

## Browser integration

`browser-extension/` is a Chrome extension that sends every page you open to the running URL Checker app before the page loads.

1. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, and pick the `browser-extension` folder.
2. Copy the extension's ID from that page into `config.properties` as `EXTENSION_ID=...` (optionally set `LISTENER_PORT`; it must match `PORT` in `browser-extension/config.js`).
3. Start the app and keep its window open (there is no manual URL box; links only come from Chrome). Links you click and URLs you type are now held on a "Checking…" page; safe ones open automatically, unsafe or unsure ones stay blocked with a Go back / Open anyway choice.

Logging in: form submissions (like sending your password) are never intercepted, and the big sign-in services in `SIGN_IN_DOMAINS` are skipped. For a sign-in address on any other site, only the site itself (`https://host/`) is checked.

Trusted sites: once a page passes (verdict Safe), its host is trusted until Chrome closes, so moving around that site (new pages, changed parameters) isn't checked again. "Open anyway" doesn't trust the site; it only opens that one page.
