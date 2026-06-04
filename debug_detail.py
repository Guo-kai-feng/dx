"""精确调试: 逐个对比浏览器编码 vs Python实现"""
import base64
from dingxiang_constid_decoder import *

# 浏览器生成的完整编码值
BROWSER_PARAM = "5646#X8XIOhylijm4k93Rhwn0Xrm8wqFieStNciF1bvDNMBj3xgDw20sslvpoz+lWevloz+AOexpetlGIlve5tHNWKWP7tFB1boPMc++/SOJyziEJl7FMcF1DxxUlzBenevNy2UnjXXo+6r5jU/3qjTxxH28XIp1dq+TaGDYaeC6HzzbupzoYTevvVPZdUpS0XxtVomO1MXXsXB7i+31Qq7fHdU8IrF6Cm8XeyEWnwMtFQvpb5p9Z8KyvVnzKp76X3ht3aGGNpVbm08E3d+ltMn/annoFxX=="

# 已知明文
PLAINTEXT = {"cache":True,"lid":"7e2ac174cb6109c37176066140750adbd2b14ae88179070d3256384658beef1595e2d19d","lidType":1,"token":"6a17f04fEDF005UVLlsLSlIPCmLnIZnAHH0tGfO1","appKey":"5f6727ec854786a86cd4c3c171d13499"}

# 1. 浏览器编码的 raw bytes
version, b64 = BROWSER_PARAM.split("#", 1)
raw = base64.b64decode(b64)
print(f"Version: {version}")
print(f"Raw length: {len(raw)} bytes")
print(f"First 30 bytes: {[hex(b) for b in raw[:30]]}")

# 2. 解析第一个字段: header + data
#   func_idx = raw[0] - 1 = ?
#   len = raw[1] << 8 | raw[2] = ?
func_idx = raw[0] - 1
data_len = (raw[1] << 8) | raw[2]
print(f"\nField 0: func_idx={func_idx}, data_len={data_len}")

xored = raw[3:3+data_len]
print(f"XORed data (hex): {' '.join(hex(b) for b in xored)}")
print(f"XORed data (repr): {repr(xored.decode('latin-1'))}")

# 3. 尝试每个 g_decode 函数
print("\n尝试所有 30 个 decode 函数:")
for i in range(min(30, 10)):
    try:
        decoded = G_DECODE_FUNCTIONS[i](xored.decode("latin-1"))
        print(f"  g{i}_decode: {repr(decoded[:50])}")
    except Exception as e:
        print(f"  g{i}_decode: ERROR {e}")

# 4. 用正确的 func_idx (0) 解码
print(f"\n使用 g{func_idx}_decode:")
decoded = G_DECODE_FUNCTIONS[func_idx](xored.decode("latin-1"))
print(f"  解码结果: {repr(decoded)}")
json_str = "{" + decoded + "}"
print(f"  还原JSON: {json_str}")

# 5. 对比: Python 编码同样的明文
print("\n" + "="*50)
print("对比 Python 编码 vs 浏览器编码:")
py_encoded = encode_param(PLAINTEXT)
py_version, py_b64 = py_encoded.split("#", 1)
py_raw = base64.b64decode(py_b64)
print(f"Python raw length: {len(py_raw)} bytes")
print(f"Python first 30 bytes: {[hex(b) for b in py_raw[:30]]}")
print(f"Browser first 30 bytes: {[hex(b) for b in raw[:30]]}")
print(f"\nMatch: {'YES' if py_raw == raw else 'NO'}")
if py_raw != raw:
    # Find first difference
    for i in range(min(len(py_raw), len(raw))):
        if py_raw[i] != raw[i]:
            print(f"First diff at byte {i}: py={hex(py_raw[i])}, browser={hex(raw[i])}")
            break
