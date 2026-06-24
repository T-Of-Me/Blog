---
title: SmartHire - HTB
description: 1 prompt từ chatgpt
date: 2026-01-01 00:00:00+0000
image: image copy.png
categories:
    - HTB
tags:
    - Linux
weight: Medium
---
## Scan 
- Scan port
![alt text](image.png)
- Thấy redirect về :  `http://smarthire.htb/`
![alt text](image-1.png)
- Kiểm tra với curl bằng `--resolve`
![alt text](image-2.png)

## Scan Subdomain
- phát hiện subdomain mới `models.smarthire.htb` với credential gussey : admin/password :
![alt text](image-3.png)

## Register model 
- up file train.csv lên để đăng kí model 
![alt text](image-4.png)
- Tạo MLflow run mới 
![alt text](image-5.png)

## Tạo model giả để lấy RCE
- Tạo file `.pkl` bằng đoạn python sau:
![alt text](image-6.png)
- Tạo file `payload_model` với run id mới
![alt text](image-7.png)
- Tiếp tục tạo các file đủ điều kiện 
![alt text](image-8.png)
- Tạo 1 version mới trỏ vào mẫu độc hại
![alt text](image-9.png)
- Trigger bind shell
![alt text](image-10.png)
- flag user : 199f55bcf91b34cf00241c62727ec0c6

## Lấy root
- Kiểm tra bằng `sudo -l` ta thấy user có quyền chạy python với quyền `root`
![alt text](image-11.png)
- Kiểm tra plugin để kết hợp với python để leo 
![alt text](image-12.png)
- Viết payload vào plugin để tìm được
```python
echo aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImNobW9kIHUrcyAvYmluL2Jhc2giKQo= | base64 -d > /opt/tools/mlflow_ctl/plugins/dev/rootme.pth
```
- Trigger để lên root
![alt text](image-14.png)

- flag root : 8c545a2ed33e4bf3ec27ddeed8eca7bb