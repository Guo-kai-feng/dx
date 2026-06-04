"""验证完整编码匹配浏览器"""
import base64
from dingxiang_constid_decoder import encode_param, decode_param

PLAINTEXT = {"cache":True,"lid":"7e2ac174cb6109c37176066140750adbd2b14ae88179070d3256384658beef1595e2d19d","lidType":1,"token":"6a17f04fEDF005UVLlsLSlIPCmLnIZnAHH0tGfO1","appKey":"5f6727ec854786a86cd4c3c171d13499"}

# 浏览器编码结果
BROWSER_B64 = "X8XIOhylijm4k93Rhwn0Xrm8wqFieStNciF1bvDNMBj3xgDw20sslvpoz+lWevloz+AOexpetlGIlve5tHNWKWP7tFB1boPMc++/SOJyziEJl7FMcF1DxxUlzBenevNy2UnjXXo+6r5jU/3qjTxxH28XIp1dq+TaGDYaeC6HzzbupzoYTevvVPZdUpS0XxtVomO1MXXsXB7i+31Qq7fHdU8IrF6Cm8XeyEWnwMtFQvpb5p9Z8KyvVnzKp76X3ht3aGGNpVbm08E3d+ltMn/annoFxX=="
BROWSER_RAW_HEX = "01 00 0c 65 29 2a 28 30 5d 6f 51 13 4b 32 2f 02 00 50 cf a3 ca ae 8c b6 94 a3 c6 f4 95 f6 c7 f0 c4 a7 c5 f3 c2 f2 cb a8 9b ac 9d aa 9c ac 9a ac 9d a9 99 ae 9b ab ca ae cc a8 9a f8 c9 fd 9c f9 c1 f9 c8 ff c6 f6 c1 f1 95 a6 94 a1 97 a4 9c a8 9e ab 93 f1 94 f1 97 a6 93 aa 9f fa c8 ac 9d a4 c0 e2 03 00 0b 1a 5a 0e 03 39 41 3a 0d 1a 69 7f 04 00 32 e1 b7 e9 a4 55 ed 70 95 ae 15 9f 9e 7f 45 ba 7b 02 46 b2 49 d0 73 77 3a ea 2f 02 9c b4 b0 16 46 c4 00 0b 03 fe 4a 68 41 ad eb 96 1f dc e4 0c 80 f5 a1 05 00 2b 92 27 08 cf 1c 8f b4 9b bd e2 ed 4d 43 e9 09 d0 89 fe bb 95 80 11 2c 84 57 be f6 bb 4f 41 bd 08 84 dd aa b2 c4 85 15 20 8b 0f a4"

py_param = encode_param(PLAINTEXT)
version, py_b64 = py_param.split("#", 1)

print(f"Python base64: {py_b64}")
print(f"Browser base64: {BROWSER_B64}")
print(f"\nBase64 match: {py_b64 == BROWSER_B64}")

# Compare raw bytes
py_raw = base64.b64decode(py_b64)
br_raw = base64.b64decode(BROWSER_B64)
print(f"Raw lengths: py={len(py_raw)}, browser={len(br_raw)}")

if py_raw == br_raw:
    print("\n✅ FULL MATCH! Python encoding matches browser.")
else:
    # Find first difference
    for i in range(min(len(py_raw), len(br_raw))):
        if py_raw[i] != br_raw[i]:
            print(f"\nFirst diff at byte {i}: py={hex(py_raw[i])}, br={hex(br_raw[i])}")
            print(f"Python raw hex: {' '.join(hex(b) for b in py_raw[:i+5])}")
            print(f"Browser raw hex: {' '.join(hex(b) for b in br_raw[:i+5])}")
            break

# Decode test
decoded = decode_param(py_param)
print(f"\nDecode round-trip: {decoded == PLAINTEXT}")
