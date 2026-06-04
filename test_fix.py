"""验证修复后的解码器 - v2"""
from dingxiang_constid_decoder import decode_param, encode_param
import json
import base64

print("=== Test 1: XDeDiMEkw 5-field round-trip ===")
test = {"cache": True, "lid": "abc123", "lidType": 1, "token": "tok123", "appKey": "key456"}
enc = encode_param(test)
print(f"Encoded: {enc[:60]}...")
dec = decode_param(enc)
print(f"Decoded keys: {list(dec.keys())}")
print(f"Round-trip: {'PASS' if dec == test else 'FAIL'}")
print()

print("=== Test 2: POST format detection (simulated) ===")
post_raw = bytes([0x5f, 0xc5, 0xc8]) + bytes(range(3, 100))
post_b64 = base64.b64encode(post_raw).decode()
post_param = "5646#" + post_b64
dec2 = decode_param(post_param)
print(f"Format: {dec2.get('_format')}")
print(f"Raw len: {dec2.get('_raw_len')}")
print(f"First bytes: {dec2.get('_first_bytes')}")
print(f"Hint: {dec2.get('_hint')}")
print()

print("=== Test 3: Invalid Base64 handling ===")
dec3 = decode_param("5646#!!!not_base64!!!")
print(f"Error: {dec3.get('_error')}")
