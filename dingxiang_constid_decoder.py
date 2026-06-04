"""
顶象(DingXiang) constID Param 加密/解密还原

算法流程:
1. 明文是一个 JSON 对象, 包含设备指纹字段:
   {"cache": true, "lid": "...", "lidType": 1, "token": "...", "appKey": "..."}

2. 每个 key-value 对单独序列化:
   - JSON.stringify({"key": value}) → slice(1, -1) 去掉首尾 { }
   - 例如: `"cache":true`

3. 以字段索引 h = d % 30 选择一个 XOR 编码函数 g[h]
   - 30 个不同的 g 函数, 各有不同的密钥/算法
   - g[h](utf8encoded_string) → XOR 扰码后的字符串

4. 拼接: [h+1(BYTE)] [len_high(BYTE)] [len_low(BYTE)] [xored_data]

5. 全部字段拼接后, 用标准 Base64 编码

6. 最后加上版本前缀: `5646#` + base64data

解码过程:
  5646#<base64> → Base64 解码 → 解析头部 → 逆向 XOR → 还原 JSON
"""

import base64
import json
import struct
from urllib.parse import unquote


# ============================================================
# 30 个 XOR 编码函数的逆向实现 (g0 ~ g29)
# 每个函数负责一种不同的 XOR 算法
# ============================================================

# g0: XOR with sliding key "KX8Mkg9GJK", initial index 36
#   for a in range(len): i=(i+1)%len(key); char^=key[i]
_G0_KEY = "KX8Mkg9GJK"
_G0_START_IDX = 36


def g0_encode(t: str) -> str:
    """g0: 滑动 XOR, 密钥 KX8Mkg9GJK, 起始索引 36"""
    result = []
    i = _G0_START_IDX
    for ch in t:
        i = (i + 1) % len(_G0_KEY)
        c = ord(ch) ^ ord(_G0_KEY[i])
        result.append(chr(c & 0xFF))
    return "".join(result)


def g0_decode(t: str) -> str:
    """g0 的逆向 (XOR 是对称的)"""
    return g0_encode(t)


# g1: Rolling XOR with initial value 46317
#   for a in range(len): s = char ^ i; i = s; output += chr(s & 255)
_G1_START_VAL = 46317


def g1_encode(t: str) -> str:
    """g1: 滚动 XOR, 初始值 46317"""
    result = []
    i = _G1_START_VAL
    for ch in t:
        s = ord(ch) ^ i
        i = s
        result.append(chr(s & 0xFF))
    return "".join(result)


def g1_decode(t: str) -> str:
    """g1 逆向: 滚动 XOR 需要从后往前还原"""
    known = _G1_START_VAL
    # 先正向计算所有中间状态
    states = [known]
    for ch in t:
        states.append(ord(ch))
    # 反向还原
    result = []
    for idx, ch in enumerate(t):
        s = states[idx] ^ ord(ch)
        result.append(chr(s & 0xFF))
    return "".join(result)


# g2: XOR with key string "NS8hJ8mgg68" from end backwards
_G2_KEY = "NS8hJ8mgg68"


def g2_encode(t: str) -> str:
    """g2: 反向滑动 XOR, key=NS8hJ8mgg68"""
    result = []
    a = len(_G2_KEY) - 1
    for ch in t:
        c = ord(ch) ^ ord(_G2_KEY[a])
        a -= 1
        if a < 0:
            a = len(_G2_KEY) - 1
        result.append(chr(c & 0xFF))
    return "".join(result)


def g2_decode(t: str) -> str:
    return g2_encode(t)


# g3: XOR with rolling value a, a = a*idx%256 + b
_G3_A = 451
_G3_B = 2755


def g3_encode(t: str) -> str:
    """g3: 多项式滚动 XOR"""
    result = []
    c = _G3_A
    for idx, ch in enumerate(t):
        f = ord(ch) ^ c
        c = c * idx % 256 + _G3_B
        result.append(chr(f & 0xFF))
    return "".join(result)


def g3_decode(t: str) -> str:
    """g3 逆向"""
    result = []
    c = _G3_A
    for idx, ch in enumerate(t):
        f = ord(ch) ^ c
        c = c * idx % 256 + _G3_B
        result.append(chr(f & 0xFF))
    return "".join(result)


# g4: LFSR XOR, shift=3, mask=240
_G4_SHIFT = 3
_G4_MASK = 240


def g4_encode(t: str) -> str:
    """g4: LFSR XOR"""
    result = []
    u = 132  # n[1161]
    for ch in t:
        u = ((u << _G4_SHIFT ^ u) & _G4_MASK) + (u >> _G4_SHIFT)
        result.append(chr((ord(ch) ^ u) & 0xFF))
    return "".join(result)


def g4_decode(t: str) -> str:
    return g4_encode(t)


# g5: Caesar cipher, shift = 23, mod = 128 (or similar)
_G5_SHIFT = 23
_G5_MOD = 128


def g5_encode(t: str) -> str:
    """g5: Caesar + 偏移"""
    result = []
    for ch in t:
        c = (ord(ch) + _G5_SHIFT - 1)
        if c >= _G5_MOD:
            c %= _G5_MOD
        result.append(chr(c))
    return "".join(result)


def g5_decode(t: str) -> str:
    result = []
    for ch in t:
        c = (ord(ch) - _G5_SHIFT + 1) % _G5_MOD
        result.append(chr(c))
    return "".join(result)


# g6: XOR with polynomial rolling key
_G6_KEY = 32563
_G6_B = 29065


def g6_encode(t: str) -> str:
    """g6: 多项式 XOR"""
    result = []
    a = _G6_KEY
    for idx, ch in enumerate(t):
        u = ord(ch) ^ a
        a = a * idx % 256 + _G6_B
        result.append(chr(u & 0xFF))
    return "".join(result)


def g6_decode(t: str) -> str:
    return g6_encode(t)


# g7: Simple XOR with rolling key
_G7_KEY = 171


def g7_encode(t: str) -> str:
    """g7: 简单滚动 XOR"""
    result = []
    o = _G7_KEY
    for ch in t:
        a = (ord(ch) ^ o) & 0xFF
        result.append(chr(a))
        o = a
    return "".join(result)


def g7_decode(t: str) -> str:
    result = []
    known = _G7_KEY
    for idx, ch in enumerate(t):
        plain = known ^ ord(ch)
        known = ord(ch)
        result.append(chr(plain & 0xFF))
    return "".join(result)


# g8: ROR (rotate right) by 4
_G8_SHIFT = 4


def g8_encode(t: str) -> str:
    """g8: 右旋转 4 位"""
    result = []
    for ch in t:
        u = (ord(ch) - _G8_SHIFT) & 0xFF
        c = 4  # e[10] = 4
        s = (u >> c) + (u << (8 - c)) & 0xFF
        result.append(chr(s))
    return "".join(result)


def g8_decode(t: str) -> str:
    result = []
    for ch in t:
        s = ord(ch)
        c = 4
        u = ((s << c) + (s >> (8 - c))) & 0xFF
        result.append(chr((u + _G8_SHIFT) & 0xFF))
    return "".join(result)


# g9: XOR with key string
_G9_KEY = "bhbXy6HJSaj67jk"


def g9_encode(t: str) -> str:
    """g9: 字符串 XOR"""
    result = []
    for i, ch in enumerate(t):
        a = ord(ch) ^ ord(_G9_KEY[i % len(_G9_KEY)])
        result.append(chr(a & 0xFF))
    return "".join(result)


def g9_decode(t: str) -> str:
    return g9_encode(t)


# g10: LFSR, 初始值=891, shift=4, mask=240
_G10_INIT = 891
_G10_SHIFT = 4
_G10_MASK = 240
_G10_SHIFT2 = 7


def g10_encode(t: str) -> str:
    """g10: 双参数 LFSR"""
    result = []
    s = _G10_INIT
    for ch in t:
        s = ((s << _G10_SHIFT ^ s) & _G10_MASK) + (s >> _G10_SHIFT2)
        result.append(chr((ord(ch) ^ s) & 0xFF))
    return "".join(result)


def g10_decode(t: str) -> str:
    return g10_encode(t)


# g11: ROR 5
_G11_SHIFT_N = 2
_G11_SHIFT_OUT = 5


def g11_encode(t: str) -> str:
    """g11: ROR 5"""
    result = []
    for ch in t:
        s = (ord(ch) - _G11_SHIFT_N) & 0xFF
        v = (s >> _G11_SHIFT_OUT) + (s << (8 - _G11_SHIFT_OUT)) & 0xFF
        result.append(chr(v))
    return "".join(result)


def g11_decode(t: str) -> str:
    result = []
    for ch in t:
        v = ord(ch)
        s = ((v << _G11_SHIFT_OUT) + (v >> (8 - _G11_SHIFT_OUT))) & 0xFF
        result.append(chr((s + _G11_SHIFT_N) & 0xFF))
    return "".join(result)


# g12: Rolling XOR with initial value 56737
_G12_INIT = 56737


def g12_encode(t: str) -> str:
    """g12: 滚动 XOR"""
    result = []
    c = _G12_INIT
    for ch in t:
        f = ord(ch) ^ c
        c = f
        result.append(chr(f & 0xFF))
    return "".join(result)


def g12_decode(t: str) -> str:
    result = []
    known = _G12_INIT
    for ch in t:
        f = known ^ ord(ch)
        known = ord(ch)
        result.append(chr(f & 0xFF))
    return "".join(result)


# g13: XOR with key string "dx54gFRTbvc"
_G13_KEY = "dx54gFRTbvc"


def g13_encode(t: str) -> str:
    """g13: 字符串 XOR 滑动"""
    result = []
    u = 0
    for ch in t:
        s = ord(ch) ^ ord(_G13_KEY[u])
        u += 1
        if u >= len(_G13_KEY):
            u = 0
        result.append(chr(s & 0xFF))
    return "".join(result)


def g13_decode(t: str) -> str:
    return g13_encode(t)


# g14: nibble_swap + offset 16373
_G14_OFFSET = 16373


def g14_encode(t: str) -> str:
    """g14: nibble_swap (s>>4 + s<<4) + offset"""
    result = []
    for ch in t:
        s = ord(ch)
        f = ((s >> 4) + (s << 4) + _G14_OFFSET) & 0xFF
        result.append(chr(f))
    return "".join(result)


def g14_decode(t: str) -> str:
    result = []
    for ch in t:
        f = (ord(ch) - _G14_OFFSET) & 0xFF
        s = ((f << 4) + (f >> 4)) & 0xFF
        result.append(chr(s))
    return "".join(result)


# g15: XOR with key string "滟फ़ॢথৣषআৗঐ", step index
_G15_KEY = "滟\u095e\u0962\u09a5\u09e3\u0937\u0986\u09d7\u0990"


def g15_encode(t: str) -> str:
    """g15: Unicode 字符串 XOR"""
    result = []
    a = 798
    for ch in t:
        a = (a + 1) % len(_G15_KEY)
        c = ord(ch) ^ ord(_G15_KEY[a])
        result.append(chr(c & 0xFF))
    return "".join(result)


def g15_decode(t: str) -> str:
    return g15_encode(t)


# g16: Simple rolling XOR with char="harCo"
_G16_INIT = 143


def g16_encode(t: str) -> str:
    """g16: 简单滚动 XOR"""
    result = []
    i = _G16_INIT
    for ch in t:
        u = (ord(ch) ^ i) & 0xFF
        result.append(chr(u))
        i = u
    return "".join(result)


def g16_decode(t: str) -> str:
    result = []
    known = _G16_INIT
    for ch in t:
        u = (known ^ ord(ch)) & 0xFF
        known = ord(ch)
        result.append(chr(u))
    return "".join(result)


# g17: LFSR with shift=4 (e[264])
_G17_SHIFT = 4
_G17_SHIFT2 = 7
_G17_INIT = 179


def g17_encode(t: str) -> str:
    """g17: LFSR"""
    result = []
    c = _G17_INIT
    for ch in t:
        c = ((c << _G17_SHIFT ^ c) & 240) + (c >> _G17_SHIFT2)
        result.append(chr((ord(ch) ^ c) & 0xFF))
    return "".join(result)


def g17_decode(t: str) -> str:
    return g17_encode(t)


# g18: Simple XOR with initial value 98357
_G18_INIT = 98357


def g18_encode(t: str) -> str:
    """g18: 简单 XOR"""
    result = []
    o = _G18_INIT
    for ch in t:
        a = ord(ch) ^ o
        o = a
        result.append(chr(a & 0xFF))
    return "".join(result)


def g18_decode(t: str) -> str:
    result = []
    known = _G18_INIT
    for ch in t:
        a = (known ^ ord(ch)) & 0xFF
        known = ord(ch)
        result.append(chr(a))
    return "".join(result)


# g19: XOR with constant 208, combined with ROR
_G19_KEY = 208


def g19_encode(t: str) -> str:
    """g19: 常数 XOR + 位移"""
    result = []
    for ch in t:
        u = _G19_KEY ^ ord(ch)
        result.append(chr((u >> 7 ^ ord(ch)) & 0xFF))
    return "".join(result)


def g19_decode(t: str) -> str:
    result = []
    for ch in t:
        orig = _G19_KEY ^ (ord(ch) & 0xFF)
        result.append(chr(orig & 0xFF))
    return "".join(result)


# g20: ROL 4 + offset
_G20_SHIFT = 4
_G20_OFFSET = 2  # n[233] = 2


def g20_encode(t: str) -> str:
    """g20: ROL 4"""
    result = []
    for ch in t:
        u = (ord(ch) - _G20_OFFSET) & 0xFF
        i = 4
        s = (u >> i) + (u << (8 - i)) & 0xFF
        result.append(chr(s))
    return "".join(result)


def g20_decode(t: str) -> str:
    result = []
    for ch in t:
        s = ord(ch)
        i = 4
        u = ((s << i) + (s >> (8 - i))) & 0xFF
        result.append(chr((u + _G20_OFFSET) & 0xFF))
    return "".join(result)


# g21: LFSR, shift=5, mask=240
_G21_SHIFT = 5
_G21_SHIFT2 = 6
_G21_INIT_N = 367


def g21_encode(t: str) -> str:
    """g21: LFSR 5/6"""
    result = []
    u = _G21_INIT_N
    for ch in t:
        u = ((u << _G21_SHIFT ^ u) & 240) + (u >> _G21_SHIFT2)
        result.append(chr((ord(ch) ^ u) & 0xFF))
    return "".join(result)


def g21_decode(t: str) -> str:
    return g21_encode(t)


# g22: Rolling XOR with a = a*idx%256 + b
_G22_A = 43521
_G22_B = 24351


def g22_encode(t: str) -> str:
    """g22: 多项式 XOR"""
    result = []
    f = _G22_A
    for idx, ch in enumerate(t):
        a = ord(ch) ^ f
        f = f * idx % 256 + _G22_B
        result.append(chr(a & 0xFF))
    return "".join(result)


def g22_decode(t: str) -> str:
    return g22_encode(t)


# g23: XOR with key "NS7SN5gd5U8ls"
_G23_KEY = "NS7SN5gd5U8ls"


def g23_encode(t: str) -> str:
    """g23: 字符串 XOR"""
    result = []
    c = 0
    for ch in t:
        f = ord(ch) ^ ord(_G23_KEY[c])
        c += 1
        if c >= len(_G23_KEY):
            c = 0
        result.append(chr(f & 0xFF))
    return "".join(result)


def g23_decode(t: str) -> str:
    return g23_encode(t)


# g24: Simple rolling XOR 72439
_G24_INIT = 72439


def g24_encode(t: str) -> str:
    """g24: 滚动 XOR"""
    result = []
    o = _G24_INIT
    for ch in t:
        a = ord(ch) ^ o
        o = a
        result.append(chr(a & 0xFF))
    return "".join(result)


def g24_decode(t: str) -> str:
    result = []
    known = _G24_INIT
    for ch in t:
        a = (known ^ ord(ch)) & 0xFF
        known = ord(ch)
        result.append(chr(a))
    return "".join(result)


# g25: Simple rolling XOR 241
_G25_INIT = 241


def g25_encode(t: str) -> str:
    """g25: 滚动 XOR"""
    result = []
    o = _G25_INIT
    for ch in t:
        a = (ord(ch) ^ o) & 0xFF
        result.append(chr(a))
        o = a
    return "".join(result)


def g25_decode(t: str) -> str:
    result = []
    known = _G25_INIT
    for ch in t:
        a = (known ^ ord(ch)) & 0xFF
        known = ord(ch)
        result.append(chr(a))
    return "".join(result)


# g26: ROR 2 + offset
_G26_OFFSET = 2


def g26_encode(t: str) -> str:
    """g26: ROR 2"""
    result = []
    for ch in t:
        a = (ord(ch) - _G26_OFFSET) & 0xFF
        u = 5
        c = (a >> u) + (a << (8 - u)) & 0xFF
        result.append(chr(c))
    return "".join(result)


def g26_decode(t: str) -> str:
    result = []
    for ch in t:
        c = ord(ch)
        a = ((c << 5) + (c >> 3)) & 0xFF
        result.append(chr((a + _G26_OFFSET) & 0xFF))
    return "".join(result)


# g27: Simple rolling XOR 621
_G27_INIT = 621


def g27_encode(t: str) -> str:
    """g27: 滚动 XOR"""
    result = []
    o = _G27_INIT
    for ch in t:
        a = (ord(ch) ^ o) & 0xFF
        result.append(chr(a))
        o = a
    return "".join(result)


def g27_decode(t: str) -> str:
    result = []
    known = _G27_INIT
    for ch in t:
        a = (known ^ ord(ch)) & 0xFF
        known = ord(ch)
        result.append(chr(a))
    return "".join(result)


# g28: ROL 1
_G28_SHIFT = 1


def g28_encode(t: str) -> str:
    """g28: ROL 1"""
    result = []
    for ch in t:
        d = ord(ch)
        l = (d >> (8 - _G28_SHIFT)) + ((d << _G28_SHIFT) & 0xFF) & 0xFF
        result.append(chr(l))
    return "".join(result)


def g28_decode(t: str) -> str:
    result = []
    for ch in t:
        l = ord(ch)
        d = ((l >> _G28_SHIFT) + (l << (8 - _G28_SHIFT))) & 0xFF
        result.append(chr(d))
    return "".join(result)


# g29: XOR with key string "H7Sbx8mSHK9S"
_G29_KEY = "H7Sbx8mSHK9S"


def g29_encode(t: str) -> str:
    """g29: 字符串 XOR 滑动"""
    result = []
    c = 0
    for ch in t:
        u = ord(ch) ^ ord(_G29_KEY[c])
        c = (c + 3) % len(_G29_KEY)
        result.append(chr(u & 0xFF))
    return "".join(result)


def g29_decode(t: str) -> str:
    return g29_encode(t)


# ============================================================
# 30 个函数的编码/解码表
# ============================================================

G_FUNCTIONS = [g0_encode, g1_encode, g2_encode, g3_encode, g4_encode,
               g5_encode, g6_encode, g7_encode, g8_encode, g9_encode,
               g10_encode, g11_encode, g12_encode, g13_encode, g14_encode,
               g15_encode, g16_encode, g17_encode, g18_encode, g19_encode,
               g20_encode, g21_encode, g22_encode, g23_encode, g24_encode,
               g25_encode, g26_encode, g27_encode, g28_encode, g29_encode]

G_DECODE_FUNCTIONS = [g0_decode, g1_decode, g2_decode, g3_decode, g4_decode,
                      g5_decode, g6_decode, g7_decode, g8_decode, g9_decode,
                      g10_decode, g11_decode, g12_decode, g13_decode, g14_decode,
                      g15_decode, g16_decode, g17_decode, g18_decode, g19_decode,
                      g20_decode, g21_decode, g22_decode, g23_decode, g24_decode,
                      g25_decode, g26_decode, g27_decode, g28_decode, g29_decode]


def detect_param_format(raw_bytes: bytes) -> str:
    """
    检测 Param raw bytes 的编码格式
    
    返回:
      - 'XDeDiMEkw': 5字段 field-by-field XOR 格式 (intenal constid)
      - 'POST': AES-like 加密 blob (POST 请求用)
      - 'unknown': 无法识别
    """
    if len(raw_bytes) < 1:
        return "unknown"

    first_byte = raw_bytes[0]
    
    # XDeDiMEkw 格式: 第1个字段用 g[0], func_idx = 0+1 = 1
    # 第一个字节是 func_idx+1, 取值范围 1~30
    if 1 <= first_byte <= 30:
        # 再做进一步验证: 第2-3字节是长度
        data_len = (raw_bytes[1] << 8) | raw_bytes[2]
        if 3 + data_len <= len(raw_bytes):
            return "XDeDiMEkw"

    # POST 格式: 无法解析 (AES加密或其它)
    return "POST"


def decode_param(param_value: str) -> dict:
    """
    解码顶象 constID Param 为明文字典

    支持两种格式:
    1. XDeDiMEkw (内部5字段): [func_idx+1][len_hi][len_lo][xored_data...]
    2. POST 加密格式: 需先解密再解析 (当前仅可检测,不可解码)

    格式: `5646#<base64_data>`
    """
    # 1. URL 解码
    param = unquote(param_value)

    # 2. 去掉版本前缀 "5646#"
    b64_data = param
    if "#" in param:
        _, b64_data = param.split("#", 1)

    # 3. Base64 解码 (自动补 padding)
    missing_padding = len(b64_data) % 4
    if missing_padding:
        b64_data += "=" * (4 - missing_padding)
    try:
        raw_bytes = base64.b64decode(b64_data)
    except Exception as e:
        return {"_error": f"Base64 decode failed: {e}", "_b64_len": len(b64_data)}

    # 4. 检测格式
    fmt = detect_param_format(raw_bytes)

    if fmt == "POST":
        return _decode_post_blob(raw_bytes)

    # 5. XDeDiMEkw 格式: 逐字段解析
    return _decode_xdedimekw(raw_bytes)


def _decode_xdedimekw(raw_bytes: bytes) -> dict:
    """解码 XDeDiMEkw 格式 (field-by-field XOR)"""
    fields = {}
    offset = 0
    n = len(raw_bytes)

    while offset < n:
        if offset + 3 > n:
            break

        func_idx = raw_bytes[offset] - 1
        data_len = (raw_bytes[offset + 1] << 8) | raw_bytes[offset + 2]
        offset += 3

        if data_len == 0 or offset + data_len > n:
            break

        xored_data = raw_bytes[offset:offset + data_len].decode("latin-1")
        offset += data_len

        if 0 <= func_idx < 30:
            decoded = G_DECODE_FUNCTIONS[func_idx](xored_data)
        else:
            decoded = xored_data

        json_str = "{" + decoded + "}"
        try:
            pair = json.loads(json_str)
            fields.update(pair)
        except json.JSONDecodeError:
            fields[f"_g{func_idx}_raw"] = decoded[:80]

    return fields


def _decode_post_blob(raw_bytes: bytes) -> dict:
    """
    POST 加密 blob 格式 — 当前仅做诊断输出
    
    POST raw bytes 是 AES/自定义加密后的数据, 无法直接解析为字段。
    需要追踪 constid-js 中 POST 请求的 XHR.send() 调用栈才能还原加密密钥。

    工作路径:
    1. 用 MCP break_on_xhr("constid") 停止 POST 发送
    2. get_paused_info 查看 Param 生成处的调用栈
    3. step_into 进入加密函数, 提取密钥/IV/算法
    """
    return {
         "_format": "POST_AES_BLOB",
         "_raw_len": len(raw_bytes),
         "_first_bytes": " ".join(f"{b:02x}" for b in raw_bytes[:20]),
         "_hint": "POST Param使用AES-like加密, 无法直接解码。需MCP追踪加密路径提取密钥。"
     }


def encode_param(plaintext: dict) -> str:
    """
    将明文字典编码为顶象 constID Param
    """
    raw_parts = []

    for idx, (key, val) in enumerate(plaintext.items()):
        h = idx % 30

        # JSON 序列化单个 key-value 对
        json_str = json.dumps({key: val}, separators=(",", ":"))
        # 去掉首尾 {}
        sliced = json_str[1:-1]

        # XOR 编码
        xored = G_FUNCTIONS[h](sliced)

        # 构造头部: [func_idx+1] [len>>8] [len&0xFF]
        header = bytes([h + 1, len(xored) >> 8, len(xored) & 0xFF])
        raw_parts.append(header)
        raw_parts.append(xored.encode("latin-1"))

    raw_data = b"".join(raw_parts)

    # Base64 编码
    b64_data = base64.b64encode(raw_data).decode("ascii")

    return f"5646#{b64_data}"


# ============================================================
# 测试
# ============================================================
if __name__ == "__main__":
    # 用户提供的 Param (截取部分用于示例)
    USER_PARAM = (
        "5646#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"
    )

    print("=" * 60)
    print("顶象(DingXiang) constID Param 解密工具")
    print("=" * 60)

    # 解码
    result = decode_param(USER_PARAM)

    print("\n解码后的明文字段:")
    print("-" * 40)
    for key, val in result.items():
        val_str = str(val)
        if len(val_str) > 80:
            val_str = val_str[:80] + "..."
        print(f"  {key}: {val_str}")

    print(f"\n共 {len(result)} 个字段")

    # 测试: 用小数据验证编码→解码回路
    print("\n" + "=" * 60)
    print("编码/解码回路测试 (小数据)")
    print("=" * 60)

    test_obj = {"cache": True, "lid": "7e2ac174cb6109c37176066140750adbd2b14ae88179070d3256384658beef1595e2d19d",
                "lidType": 1, "token": "6a17f04fEDF005UVLlsLSlIPCmLnIZnAHH0tGfO1",
                "appKey": "5f6727ec854786a86cd4c3c171d13499"}

    encoded = encode_param(test_obj)
    decoded = decode_param(encoded)

    print(f"\n原始: {json.dumps(test_obj, ensure_ascii=False)}")
    print(f"\n编码: {encoded}")
    print(f"\n解码: {json.dumps(decoded, ensure_ascii=False)}")
    print(f"\n验证: {'通过 ✅' if test_obj == decoded else '失败 ❌'}")
