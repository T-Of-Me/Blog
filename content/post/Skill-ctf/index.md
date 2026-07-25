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

```code
Khi gặp bài Windows Registry Forensics tương tự, trước hết hãy kiểm kê artefact và tính SHA-256 để bảo toàn bằng chứng, sau đó xác định hive người dùng liên quan (NTUSER.DAT) bằng cách tìm các nhánh ứng dụng đáng ngờ; luôn replay NTUSER.DAT.LOG1/LOG2 vào một bản sao bằng công cụ như regipy để khôi phục thay đổi chưa commit rồi so sánh với hive gốc. Tiếp theo, phân tích các key lịch sử của ứng dụng—với 7-Zip là Software\7-Zip\Extraction, Compression và FM—đồng thời kiểm tra artefact bổ trợ như Explorer\TypedPaths, RecentDocs và ComDlg32. Đừng bỏ qua REG_BINARY: hãy trích và decode chuỗi UTF-16LE để đọc PathHistory, FolderHistory, CopyHistory và ArcHistory; dùng FolderHistory để xác định các thư mục đã enumerate, CopyHistory để tìm nơi staging, ArcHistory cùng Archiver để xác định archive đầu ra, và PanelPath0 kết hợp mục MRU mới nhất để tìm thư mục kết thúc. Cuối cùng, dựng timeline từ Registry LastWrite time, chỉ gán timestamp khi artefact thực sự cung cấp, đối chiếu mỗi kết luận qua ít nhất hai nguồn nếu có thể, và khi submit hãy ưu tiên raw value nguyên bản—đúng full path, extension và dấu \—thay vì câu trả lời rút gọn theo cách diễn đạt của đề.
```

