"""
测试: POST Param 是否使用自定义 base30 字母表 (而非标准 Base64)
如果 POST 用的是 XDeDiMEkw 路径，raw bytes 格式应该是 [func_idx+1][len_hi][len_lo][data...]
"""
import struct
from urllib.parse import unquote

# 浏览器提取的自定义 base30 字母表 (30字符)
BROWSER_ALPHABET = "$J\x1cA+N\x17a/x=z\x02g\x01S\x1e2\\O\x1au8; f[5\x1fE"

# 标准 Base64 字母表
STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# 用户 POST Param 片段
POST_PARAM_SHORT = (
    "5646%23X8XIOhylijm4k93Rhwn0Xrm8wqFieStNcF68lOESzlLIlIeGtBK4lWp0t00vB7wKwHtHevtSzl0"
    "nl7p0AiEWxIDtM0BUe7dBt0A4KOKow0KJxosM2HHPS7eBAlqkKWASzGVjXXo%2B6r5jU%2F3qjTxxH28"
    "XiU1r7q3hpDYfqCp4Adr%2BGd2POo4QVDnrjnSPDZLZ9TClgDx%2F40uCX2VuX3Jhv8Ls44j09U%2B7py7"
    "Uo9lJL0E5w4aH4QWZqq1ChTjcaS%2BaBK%2BkN%2F4QVuUboix3uGbOE76AGoPZTP1v6KJ7py7Uo9lJL0"
    "E5rrfXijEZJdr5%2FjCqRVc1TyOIRDCgTz47R%2FciJVMZJyb1J3bZTVC7RPxPRwrPmXSTGzpFlpoMno0Uu"
    "EL55PmUXAcivI7bnK34%2FSQjeq6eROTXduzavReQL%2F4plv8mGnToz3lx5Iq%2FkYhmXK7GhkLJGicqz"
    "%2BL7Czd%2FyFrUnnmK%2B8%2FGM2q%2FUoigT%2FcgHzHWWadWJfutMTOA5hTQ%2Bfyv1ZJ6Nq2rxAzbm"
    "ceMEKdmWwqeL9Hr7xOPev8i%2BnzsfNEvQAsWsn2lkYAjdxTkOj9nlrfH%2FNTk6u9reOSChbNm617tBSj"
    "xMG7rp3rbbI1cBJVPh%2Bugwn1Zu5acX%2FRo%2B6NxCK5Zetu8Xr9rWKj4%2FeoGAb1%2BaL9PZ639ueK"
    "Lb9NGSbQI10vQpGYIKHlih3tb4JKyjYYv2KTG2BNSjAPCgh5hpgadDDIlj8F%2FJtzC1Yth6kJir8PRJK9"
    "FMhb2lsONWlt%2FRKPsniOLAJwI0cysL8BbHXPTLejSFbdgLU5OpgdRFzs1ZVIfuQf3L6wVVr%2FWkdbTM"
    "6o9lu%2B%2F8OgSnxvATRKLDX6Gb4E6vvbCGzcxgOzJ768ocecjKHdm%2B%2BqOnd01zYoewUxtwt6jXuX"
    "crbDrZLccYfVsPNZba9a3FUhS1VD9laToO0AR0JJaZF2%2F%2BnpiCJj51NpJsKYb22KeTLyPCDgawF%2B"
    "lhv8baMguaADEATz5%2BZp%2BM2nharmimYeqEZMbCkz4%2F8efHlt4EKzcVACAQy0LSTSCAJGAfoRw7RI"
    "agFfUiij4%2B9bvurg3VzoxBNoixAtuAk3OV9kDh4WoUSEWH%2F6KlAGgr8Jm%2Fsi2qvToUn%2FF5aW%2B"
    "7St5GYjtoqkkFfdudNuDGX9tYhDPXnazgQn4mN7S%2FsOkmvvbdAi91rAeOyfu099PAoLKcEK3WUTPHkE"
    "AGb5D1elIWpdwddh6yEC62n2osIjShZbcehCwaesSwmVBH2NNYXuR%2B3fmH2wuyLmI5eyZ690tllDQLjR"
    "6YAhqLn0BxYOs0rFbQb%2Fy038SUguknHGNp31jiuOmsVMaVSXIgzz4Agotu1rJhtg0plscDf6CV%2FWkw"
    "PGcL%2BLR9QmSOx9FbOWnFvBbg3dYglIRsQYus8E%2BGcvtRE%2FPXgT6nFC%2BYxaSyvNsXbCo9rPzju"
    "hiEPO7SxT1wFnp01hsxHp7%2BwE1YByyFop0Ag%2FZweKyMLKmNoySHFflhm8b9MKua06KXXSA6ANe%2B"
    "h1L%2Bx9Xrjow0z4IFxvIRnkOKkozozUq%2FAGsAQLliy6OluGUd0vVev858B%2BnijkZK9BvUGV3RAKxS"
    "JIoY3SyQrSnDzMaWyICbqyC6KzCsNMgqSY67Sr2B87hSnthKHVk%2Bg3swvjlPvOhF2DJOhBQwGCnzLSUU"
    "Eas8W1emJaKwkkZXCvbu9%2F3Of1nMAq6yQaW3Qcccl%2BH5Hqi6c1ekW1D1h1m7J7b2gKy1hzmE2rXmS"
    "z7EqARSryXmK31cpuLVEIiX14XXrTq8M8siwgnY3TJ%2FhV8Y82wuagA%2BC8UPc7JYaX0UVnZImfFvhWv"
    "X9%2FIvwbYsTSoY94wmwnRmcZjPcXMj8%2FdPmf4XdIQX9uHPcXMX8g8PubwPwVnPuZu1%2FoCs%2FvQRm"
    "fuswWnP9oaY2XP7Izhr5p8r22X4r1kKrPmXaxe2wQR%2FBxxA6uMgj1lUNIR%2Bqpsg1ihgPcMfDPvgiS"
    "Gfq1TtHYwSO37gFcwW9IklCojhLpR%2BOAvl61vSHXMhLih6cvTguIGhM02iCoshNo7gXSwrNQk1Nc7yk"
    "uCW6uMfDP2E0SLKSIG%2BOAvl61vS83ZXIqjbxHwVJ0vopGIeQtbVGH3AslXNqjgdewUeg1cK40C0OBWQ"
    "I%2BxMidfQJzs7GpOG5e5EKiZ5GK4xB0OqZwypveztGjowlwJ0b19qW0MefBnxgE02q%2B1M%2BdHoZN5"
    "7IklQxRECB61G5jpoxYlbQRcVJA9cKe10JPjS4UtdsLyM0trrotL9BE7yZir2%2BBscG6OMJJTbnk9zFU4"
    "2JFOC%2BJJxB0OxFzaE%2B01lWpEwl0d9JKvqnRdyeGE2sjW0WA02ssHrq1kMK6tNGDT0oAq7oh7A25Xj"
    "3f6TTO4OX%2Fbj3aTTrgXjTJGR1oDAmJWJgWxNTW8XXO3mwuCfr%2FTXXqQ2qkhC0KFqoLtVUhjSTnXuu"
    "zjYvamc%2FpIP4fDMmqIP4fDMmqa32X%2FuNIOU23LfCu51ROcj62YO89omhW%2FXXyQHA8QZYnqZL5aX"
    "X%2BjwiNjCA%2F6XXk7MTkTj4XDXXWL4cjBVpas1XX1kjvaWD8u18X19keJBIkN1rXPVGj%2FbowBwToX3"
    "81j15om28u7pfuMtDcMoD3mPXX8Rt7WHyTAaN7Wku4AaAvhWmVXjM1wAMPT3kzvy4Avrf1x3T5XjNSaPA"
    "ct8uaGWucWJzChR23XO6%2F5UNcE1CV0nTyTnt5gF%2FxNiXbsiYWp%2B2CgYVoM%2FYnbsLcLJt%2FOY"
    "u8pFtOeYP2shwu8nLVpU6Z9vXraaL8csRb5HhyIXCyDjr9ejc3SPXvsHmVpiTZTU%2FouRY5AFNfMaAVG"
    "ndbcXrXswqGilnl29eHklIVjXXf%2BDrQua2y3XXkCSUeQYefuXXEhZ8t4k4G7EXfXjjCqELC8U1xBESv"
    "GUXWX4MPgfI1tg98cVZVi4BJ1WyvFiX5uwdStQ2v%2BKRz%2BMlgft1kATZIEWGzeDdKBy%2FBPgEK"
    "AOSL0GO5LFvVP5RWN75JSQjHY5lwHJQsk9hxtMNyOPdGjanOQoH7IP68BjeOPmqZGcV1Hijs2aA26rzcQ"
    "SJsYcC1oao23YXXiEJpPxOKeAqi%2Bl2yXYKu1mSkCf9Ij%2FwIRYrXP8X28JyI%2F%2BroXmKRO2fUsr7"
    "IIXXfmUNIm2D3ZXmYjq7LV9pwfqQFzdpLHG4REjrX8TrcXuc9dfAZT8a46RXnI%2Frgm7T4Gh92DAmJop"
    "CWsPYQGEwMsiwMIP3pqu7EqudM56sSDQGSD15ogNVoossSDAsSD6jEquGJquMoWYboGssSDAilopCWkPX0"
    "kUGSDAsSDiDoWqgpsRIpquGJqu9MsPYtsqbpqu7Equ2r5JsSDwsJopCWkPX0kUGSDAsSD%2BJ0e%2BGQsb"
    "tcGPU0shGSDQGSDD3oWsn0eNGSDAsSDYjC5pCHIQqtquMoWYboGpCJfpCHOqwwzYfWOPX0kUGSDQGSDD3"
    "oWsn0eNGSDAsSDEnEqugwiQGSD6VtGp9xsPYtsqbp7Et2gpCJflltquMoWYboGpCJfpCWxJMwet5QItGS"
    "DQGSDD3oWsn0eNGSDAsSDYjC59BLD%2B1CSJZJn%2BsSDwsJopCWkPX0kUGSDAsSD%2BJ0e%2BGQsbtcG"
    "PU0shGSDQGSDD3oWsn0eNGSDAsSDYjC59BLD%2B1CSJZJn%2BsSDwsJopCWkPX0kUGSDAsSDNJog72AP"
    "1T2sNwpquGJqu9MsPYtsqbpqu7Equ5En9BLDKZH5pCHIteJqug0e15pGhGSDAuosptMsQGSDtKoGhGpqu7"
    "EquGSDQGSDBsosFu0ePIpqu7EquNlsNw0ekYtquGJquBtGYwMkqMws6yoWsn0eNGSDAsSD%2BZH59BEqu"
    "g2D3XXhTXfrf6numu9TD9uz4N51m9v438XneWqqAii8xx%2FhXXQOdMHa6fV49CH3PCIXYM4B3db4O2u"
    "rjPg%2BuXXss6ZzOYVVk6xzJ65aXXpjRItZr5fI%2BgtQqMfXm0zhmb3ZVTWXmEZo%2FGziGMrXmN2LTRM"
    "oj9fOXY0aQIhVB7eL2H0OGnlgEGAUq5E2Ck110SLxVJJ35ZhdCUH654YVCk%2BYp5ir"
)

param = unquote(POST_PARAM_SHORT)
_, b64 = param.split("#", 1)

# 测试1: POST 字符是否都在自定义字母表中
bad = [c for c in b64 if c not in BROWSER_ALPHABET and c != '=']
print(f"POST中有 {len(bad)} 个字符不在自定义字母表中")
if len(bad) <= 20:
    print(f"  bad chars: {set(bad)}")

# 测试2: POST 字符是否在标准Base64中
bad2 = [c for c in b64 if c not in STD_B64 and c != '=' and c != '\n']
print(f"POST中有 {len(bad2)} 个字符不在标准Base64中")

# 测试3: 用自定义字母表解码 
# base30 解码: 每个字符 = alphabet.index(char), 6位一组
def base30_decode(data, alphabet):
    result = bytearray()
    bits = 0
    bitcount = 0
    for ch in data:
        if ch == '=' or ch not in alphabet:
            continue
        idx = alphabet.index(ch)
        bits = (bits << 5) | idx  # 5 bits per char (30 < 2^5)
        bitcount += 5
        while bitcount >= 8:
            bitcount -= 8
            result.append((bits >> bitcount) & 0xFF)
    return bytes(result)

b30_raw = base30_decode(b64, BROWSER_ALPHABET)
print(f"\nBase30 decode: {len(b30_raw)} bytes")
if len(b30_raw) > 0:
    print(f"首10字节: {' '.join(f'{b:02x}' for b in b30_raw[:10])}")
    f0 = b30_raw[0] - 1 if b30_raw[0] > 0 else -1
    print(f"func_idx={f0}, len={(b30_raw[1]<<8)|b30_raw[2] if len(b30_raw)>=3 else 'N/A'}")

# 测试4: 用标准Base64解码并尝试不同偏移
import base64
std_raw = base64.b64decode(b64)
print(f"\n标准Base64 decode: {len(std_raw)} bytes")
print(f"首10字节: {' '.join(f'{b:02x}' for b in std_raw[:10])}")

# 尝试跳过首字节作为signature/delimiter
print(f"\n尝试跳过首字节:")
f0a = std_raw[1] - 1
print(f"  跳过0x{std_raw[0]:02x} → func_idx={f0a}, len={(std_raw[2]<<8)|std_raw[3] if len(std_raw)>=4 else 'N/A'}")

# 尝试跳过前N个字节看有没有规律
print(f"\n扫描前20字节模式:")
for i in range(min(20, len(std_raw))):
    b = std_raw[i]
    desc = ""
    if 1 <= b <= 30: desc = " ✅ valid func_idx"
    elif 32 <= b <= 126: desc = f" ASCII '{chr(b)}'"
    print(f"  offset {i}: 0x{b:02x} = {b}{desc}")
