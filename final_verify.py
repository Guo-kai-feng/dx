"""最终验证: 使用自定义30字符base64字母表编码"""
import base64 as std_base64
import json
from dingxiang_constid_decoder import *

PLAINTEXT = {"cache":True,"lid":"7e2ac174cb6109c37176066140750adbd2b14ae88179070d3256384658beef1595e2d19d","lidType":1,"token":"6a17f04fEDF005UVLlsLSlIPCmLnIZnAHH0tGfO1","appKey":"5f6727ec854786a86cd4c3c171d13499"}

# 浏览器自定义字母表 (30字符)
BROWSER_ALPHABET = "$J\x1cA+N\x17a/x=z\x02g\x01S\x1e2\\O\x1au8; f[5\x1fE"

# 浏览器结果
BROWSER_RESULT = "5646#$\x1e$\x02f\\=AJE5+O\\/$J\x1eS==S\x17x;A+;zzx[\x1fx[f\x02x\x1f\x1faS\x17a[[\x1af=SS\x17;\x01/"
BROWSER_RAW_HEX = "01 00 0c 65 29 2a 28 30 5d 6f 51 13 4b 32 2f 02 00 50 cf a3 ca ae 8c b6 94 a3 c6 f4 95 f6 c7 f0 c4 a7 c5 f3 c2 f2 cb a8 9b ac 9d aa 9c ac 9a ac 9d a9 99 ae 9b ab ca ae cc a8 9a f8 c9 fd 9c f9 c1 f9 c8 ff c6 f6 c1 f1 95 a6 94 a1 97 a4 9c a8 9e ab 93 f1 94 f1 97 a6 93 aa 9f fa c8 ac 9d a4 c0 e2 03 00 0b 1a 5a 0e 03 39 41 3a 0d 1a 69 7f 04 00 32 e1 b7 e9 a4 55 ed 70 95 ae 15 9f 9e 7f 45 ba 7b 02 46 b2 49 d0 73 77 3a ea 2f 02 9c b4 b0 16 46 c4 00 0b 03 fe 4a 68 41 ad eb 96 1f dc e4 0c 80 f5 a1 05 00 2b 92 27 08 cf 1c 8f b4 9b bd e2 ed 4d 43 e9 09 d0 89 fe bb 95 80 11 2c 84 57 be f6 bb 4f 41 bd 08 84 dd aa b2 c4 85 15 20 8b 0f a4"

# 修复后的 encode_param 验证 (标准base64版本)
py_param = encode_param(PLAINTEXT)
print("=== 标准base64编码 (POST 版本) ===")
print(f"Python: {py_param[:80]}...")

# 解码用户完整 Param
print("\n=== 尝试解码用户POST Param ===")
USER_PARAM_PREFIX = "5646%23X8XIOhylijm4k93Rhwn0Xrm8wqFieStNcF68lOESzlLIlIeGtBK4lWp0t00vB7wKwHtHevtSzl0nl7p0AiEWxIDtM0BUe7dBt0A4"
from urllib.parse import unquote
decoded = unquote(USER_PARAM_PREFIX)
print(f"URL decoded first part: {decoded[:80]}")

# 用标准base64解码
version, b64 = decoded.split("#", 1)
raw = std_base64.b64decode(b64)
print(f"Raw bytes length: {len(raw)}")
print(f"First header: func_idx={raw[0]-1}, len={(raw[1]<<8)|raw[2]}")

# 尝试完整解码 (只有前段)
result = decode_param(USER_PARAM_PREFIX)
print(f"Decoded fields so far: {list(result.keys())}")
for k, v in result.items():
    print(f"  {k}: {str(v)[:100]}")
