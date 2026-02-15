---
title: 0xfunCTF - WEB - ManOfAuth
description: Exploiting SSRF and Digest Authentication Relay via Tunneling
date: 2026-02-14 00:00:00+0000
image: image.png
categories:
    - CTF
tags:
    - SSRF
    - HTTP Digest Auth Relay
    - Request Reflection
    - Session Hijacking
weight: 100
---


![image](https://hackmd.io/_uploads/ryLACTCvbe.png)

## Challenge Overview
- Challenge Name: ManOfAuth
- Target: http://chall.0xfun.org:48157
- Category: Web Exploitation
- Security Mechanism: **HTTP Digest Authentication**
- Vulnerability: **Server-Side Request Forgery (SSRF) via Referer header**


## Vulnerability Analysis

- The target application has a protected endpoint at /auth using HTTP Digest Authentication. Unlike Basic Auth, Digest Auth uses a challenge-response mechanism involving a nonce (number used once) to prevent simple replay attacks.

- However, the application also features an SSRF vulnerability at /api/check. By providing a URL in the Referer header, the server's backend attempts to visit that URL.

The Attack Idea:  Digest Relay

- Since the backend server acts as a client when performing the SSRF, we can:
1. Fetch a valid nonce from the target server.
2. Host a malicious "Trap" server that demands Digest Authentication using that specific nonce.
3. Trigger the SSRF to make the target server visit our Trap.
4. The target (thinking it needs to authenticate to us) will generate a valid response hash using its internal credentials.
5. Capture this header and relay it back to the target's /auth endpoint to gain access.

## Exploitation 

Step 1: Reconnaissance
We request the `/auth` endpoint to receive the `401 Unauthorized` response. From the `WWW-Authenticate header`, we extract: `realm, nonce, and opaque values.` ; `The Flask session cookie` (to ensure our final request matches the session the nonce was generated for).
![image](https://hackmd.io/_uploads/HJ_veCAv-l.png)

Step 2: Setting up the Local Trap
We run a local Python HTTP server. When the target server hits our trap, our script: Sends a `401` response back to the target.

Includes the `WWW-Authenticate header` populated with the target's own nonce and realm.
 

Step 3: Creating a Public Tunnel
Since the target cannot see our localhost, we use Serveo to create a public HTTPS tunnel:

```  
ssh -R 80:127.0.0.1:9001 serveo.net
```
![image](https://hackmd.io/_uploads/SJZreACwZx.png)

Step 4: Triggering the **SSRF**
We send a request to `/api/check` with the `Referer header` set to our Server URL. The backend of the target server makes a request to **our trap**, sees the 401 challenge, and automatically sends back a **valid Authorization header containing the MD5 response**.
![image](https://hackmd.io/_uploads/SyLkg0CDbl.png)

Step 5: Replaying the Header
Once the trap captures the Authorization header, the script immediately sends it to the target's `/auth` endpoint along with the original session cookie.
![image](https://hackmd.io/_uploads/HkGxlACw-g.png)

