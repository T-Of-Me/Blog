---
title: H-01
description:  
date: 2026-01-01 00:00:00+0000
image: image.png
categories:
    - HACKING
tags:
    - hacking
weight: Medium
---

# Từ endpoint printer -> sqli

![](image-1.png)

-> từ đây Ctrl + U 

![](image-2.png)

-> phát hiện server tạo 2 hub khi client vào endpoint nào thì server gọi hàm tương tự 
-> tuy nhiên khi truy cập vào `/QMMonitor.aspx`

![](image-3.png)

-> server không để lộ chức năng này 
Quay lại recon target phát hiện `/sitemap.xml`

![](image-4.png)

-> 1 trang khác có vẻ được host lên cùng với trang ở ban đầu 
-> Nếu trang này cùng codebase thì cũng sẽ gọi đến `/QMMonitor.aspx`

![](image-5.png)

-> Ngay khi truy cập thử vào `/QMMonitor.aspx` đã expose 
-> đọc hàm `doPoll()`
-> Hàm gọi  `WebMethod /getNo` với param `channel` do ta kiểm soát 
-> Như vậy đã trigger được hàm `doPoll()`
-> list check ngay các vul quen thuộc 

![](image-6.png)
-> SQLi BINGOOOOO
**Đương nhiên để tìm được con đường nhìn có vẻ ngắn này thì phải trải qua rất nhiều lần thử khác nhau**

- Bài học rút ra 
    - Lỗi có thể xuất hiện ở mọi tham số
    - Def tập trung web chính mà bỏ quên 1 con web đằng sau 
    - Luôn tìm mọi endpoint có thể của trang web -> fuzzingggggggg