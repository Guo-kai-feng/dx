"""
诊断: 为什么 decode_param 对完整 POST Param 返回 0 字段

根因: POST Param 和 5-字段内部分码使用不同的编码路径
- 5-字段 (XDeDiMEkw): 自定义30字符base30 + 3字节头部格式
- POST Param: 标准Base64 + 不同头部格式 (或完全不同算法)
"""
import base64
from urllib.parse import unquote
from dingxiang_constid_decoder import *

# 用户 POST 里的完整 Param (从聊天记录提取，简略版)
POST_PARAM_SHORT = (
    "5646%23X8XIOhylijm4k93Rhwn0Xrm8wqFieStNcF68lOESzlLIlIeGtBK4lWp0t00vB7wKwHtHevtSzl0"
    "nl7p0AiEWxIDtM0BUe7dBt0A4KOKow0KJxosM2HHPS7eBAlqkKWASzGVjXXo%2B6r5jU%2F3qjTxxH28"
    "XiU1r7q3hpDYfqCp4Adr%2BGd2POo4QVDnrjnSPDZLZ9TClgDx%2F40uCX2VuX3Jhv8Ls44j09U%2B7py7"
    "Uo9lJL0E5w4aH4QWZqq1ChTjcaS%2BaBK%2BkN%2F4QVuUboix3uGbOE76AGoPZTP1v6KJ7py7Uo9lJL0"
    "E5rrfXijEZJdr5%2FjCqRVc1TyOIRDCgTz47R%2FciJVMZJyb1J3bZTVC7RPxPRwrPmXSTGzpFlpoMno0"
    "UuEL55PmUXAcivI7bnK34%2FSQjeq6eROTXduzavReQL%2F4plv8mGnToz3lx5Iq%2FkYhmXK7GhkLJGic"
    "qz%2BL7Czd%2FyFrUnnmK%2B8%2FGM2q%2FUoigT%2FcgHzHWWadWJfutMTOA5hTQ%2Bfyv1ZJ6Nq2rx"
    "AzbmceMEKdmWwqeL9Hr7xOPev8i%2BnzsfNEvQAsWsn2lkYAjdxTkOj9nlrfH%2FNTk6u9reOSChbNm61"
    "7tBSjxMG7rp3rbbI1cBJVPh%2Bugwn1Zu5acX%2FRo%2B6NxCK5Zetu8Xr9rWKj4%2FeoGAb1%2BaL9PZ6"
    "39ueKLb9NGSbQI10vQpGYIKHlih3tb4JKyjYYv2KTG2BNSjAPCgh5hpgadDDIlj8F%2FJtzC1Yth6kJir"
    "8PRJK9FMhb2lsONWlt%2FRKPsniOLAJwI0cysL8BbHXPTLejSFbdgLU5OpgdRFzs1ZVIfuQf3L6wVVr%2F"
    "WkdbTM6o9lu%2B%2F8OgSnxvATRKLDX6Gb4E6vvbCGzcxgOzJ768ocecjKHdm%2B%2BqOnd01zYoewUxt"
    "wt6jXuXcrbDrZLccYfVsPNZba9a3FUhS1VD9laToO0AR0JJaZF2%2F%2BnpiCJj51NpJsKYb22KeTLyPCD"
    "gawF%2Blhv8baMguaADEATz5%2BZp%2BM2nharmimYeqEZMbCkz4%2F8efHlt4EKzcVACAQy0LSTSCAJGA"
    "foRw7RIagFfUiij4%2B9bvurg3VzoxBNoixAtuAk3OV9kDh4WoUSEWH%2F6KlAGgr8Jm%2Fsi2qvToUn%2F"
    "F5aW%2B7St5GYjtoqkkFfdudNuDGX9tYhDPXnazgQn4mN7S%2FsOkmvvbdAi91rAeOyfu099PAoLKcEK3"
    "WUTPHkEAGb5D1elIWpdwddh6yEC62n2osIjShZbcehCwaesSwmVBH2NNYXuR%2B3fmH2wuyLmI5eyZ690"
    "tllDQLjR6YAhqLn0BxYOs0rFbQb%2Fy038SUguknHGNp31jiuOmsVMaVSXIgzz4Agotu1rJhtg0plscDf"
    "6CV%2FWkwPGcL%2BLR9QmSOx9FbOWnFvBbg3dYglIRsQYus8E%2BGcvtRE%2FPXgT6nFC%2BYxaSyvNsXb"
    "Co9rPzjuhiEPO7SxT1wFnp01hsxHp7%2BwE1YByyFop0Ag%2FZweKyMLKmNoySHFflhm8b9MKua06KXXS"
    "A6ANe%2Bh1L%2Bx9Xrjow0z4IFxvIRnkOKkozozUq%2FAGsAQLliy6OluGUd0vVev858B%2BnijkZK9BvU"
    "GV3RAKxSJIoY3SyQrSnDzMaWyICbqyC6KzCsNMgqSY67Sr2B87hSnthKHVk%2Bg3swvjlPvOhF2DJOhBQ"
    "wGCnzLSUUEas8W1emJaKwkkZXCvbu9%2F3Of1nMAq6yQaW3Qcccl%2BH5Hqi6c1ekW1D1h1m7J7b2gKy"
    "1hzmE2rXmSz7EqARSryXmK31cpuLVEIiX14XXrTq8M8siwgnY3TJ%2FhV8Y82wuagA%2BC8UPc7JYaX0U"
    "VnZImfFvhWvX9%2FIvwbYsTSoY94wmwnRmcZjPcXMj8%2FdPmf4XdIQX9uHPcXMX8g8PubwPwVnPuZu1%2"
    "FoCs%2FvQRmfuswWnP9oaY2XP7Izhr5p8r22X4r1kKrPmXaxe2wQR%2FBxxA6uMgj1lUNIR%2Bqpsg1ih"
    "gPcMfDPvgiSGfq1TtHYwSO37gFcwW9IklCojhLpR%2BOAvl61vSHXMhLih6cvTguIGhM02iCoshNo7gXS"
    "wrNQk1Nc7ykuCW6uMfDP2E0SLKSIG%2BOAvl61vS83ZXIqjbxHwVJ0vopGIeQtbVGH3AslXNqjgdewUeg"
    "1cK40C0OBWQI%2BxMidfQJzs7GpOG5e5EKiZ5GK4xB0OqZwypveztGjowlwJ0b19qW0MefBnxgE02q%2B1"
    "M%2BdHoZN57IklQxRECB61G5jpoxYlbQRcVJA9cKe10JPjS4UtdsLyM0trrotL9BE7yZir2%2BBscG6OMJ"
    "JTbnk9zFU42JFOC%2BJJxB0OxFzaE%2B01lWpEwl0d9JKvqnRdyeGE2sjW0WA02ssHrq1kMK6tNGDT0oAq"
    "7oh7A25Xj3f6TTO4OX%2Fbj3aTTrgXjTJGR1oDAmJWJgWxNTW8XXO3mwuCfr%2FTXXqQ2qkhC0KFqoLtV"
    "UhjSTnXuuzjYvamc%2FpIP4fDMmqIP4fDMmqa32X%2FuNIOU23LfCu51ROcj62YO89omhW%2FXXyQHA8Q"
    "ZYnqZL5aXX%2BjwiNjCA%2F6XXk7MTkTj4XDXXWL4cjBVpas1XX1kjvaWD8u18X19keJBIkN1rXPVGj%2F"
    "bowBwToX381j15om28u7pfuMtDcMoD3mPXX8Rt7WHyTAaN7Wku4AaAvhWmVXjM1wAMPT3kzvy4Avrf1x3"
    "T5XjNSaPAct8uaGWucWJzChR23XO6%2F5UNcE1CV0nTyTnt5gF%2FxNiXbsiYWp%2B2CgYVoM%2FYnbsLc"
    "LJt%2FOYu8pFtOeYP2shwu8nLVpU6Z9vXraaL8csRb5HhyIXCyDjr9ejc3SPXvsHmVpiTZTU%2FouRY5A"
    "FNfMaAVGndbcXrXswqGilnl29eHklIVjXXf%2BDrQua2y3XXkCSUeQYefuXXEhZ8t4k4G7EXfXjjCqELC"
    "8U1xBESvGUXWX4MPgfI1tg98cVZVi4BJ1WyvFiX5uwdStQ2v%2BKRz%2BMlgft1kATZIEWGzeDdKBy%2F"
    "BPgEKAOSL0GO5LFvVP5RWN75JSQjHY5lwHJQsk9hxtMNyOPdGjanOQoH7IP68BjeOPmqZGcV1Hijs2aA2"
    "6rzcQSJsYcC1oao23YXXiEJpPxOKeAqi%2Bl2yXYKu1mSkCf9Ij%2FwIRYrXP8X28JyI%2F%2BroXmKRO2"
    "fUsr7IIXXfmUNIm2D3ZXmYjq7LV9pwfqQFzdpLHG4REjrX8TrcXuc9dfAZT8a46RXnI%2Frgm7T4Gh92D"
    "AmJopCWsPYQGEwMsiwMIP3pqu7EqudM56sSDQGSD15ogNVoossSDAsSD6jEquGJquMoWYboGssSDAilop"
    "CWkPX0kUGSDAsSDiDoWqgpsRIpquGJqu9MsPYtsqbpqu7Equ2r5JsSDwsJopCWkPX0kUGSDAsSD%2BJ0e"
    "%2BGQsbtcGPU0shGSDQGSDD3oWsn0eNGSDAsSDYjC5pCHIQqtquMoWYboGpCJfpCHOqwwzYfWOPX0kUGS"
    "DQGSDD3oWsn0eNGSDAsSDEnEqugwiQGSD6VtGp9xsPYtsqbp7Et2gpCJflltquMoWYboGpCJfpCWxJMwe"
    "t5QItGSDQGSDD3oWsn0eNGSDAsSDYjC59BLD%2B1CSJZJn%2BsSDwsJopCWkPX0kUGSDAsSD%2BJ0e%2B"
    "GQsbtcGPU0shGSDQGSDD3oWsn0eNGSDAsSDYjC59BLD%2B1CSJZJn%2BsSDwsJopCWkPX0kUGSDAsSDN"
    "Jog72AP1T2sNwpquGJqu9MsPYtsqbpqu7Equ5En9BLDKZH5pCHIteJqug0e15pGhGSDAuosptMsQGSDtK"
    "oGhGpqu7EquGSDQGSDBsosFu0ePIpqu7EquNlsNw0ekYtquGJquBtGYwMkqMws6yoWsn0eNGSDAsSD%2B"
    "ZH59BEqug2D3XXhTXfrf6numu9TD9uz4N51m9v438XneWqqAii8xx%2FhXXQOdMHa6fV49CH3PCIXYM4B"
    "3db4O2urjPg%2BuXXss6ZzOYVVk6xzJ65aXXpjRItZr5fI%2BgtQqMfXm0zhmb3ZVTWXmEZo%2FGziGMr"
    "XmN2LTRMoj9fOXY0aQIhVB7eL2H0OGnlgEGAUq5E2Ck110SLxVJJ35ZhdCUH654YVCk%2BYp5ir"
)

print("=" * 60)
print("诊断: POST Param 解码失败根因分析")
print("=" * 60)

# 1. URL 解码
param = unquote(POST_PARAM_SHORT)
version, b64 = param.split("#", 1)
print(f"\nVersion: {version}")
print(f"Base64 长度: {len(b64)} 字符")

# 2. 标准 Base64 解码
raw = base64.b64decode(b64)
print(f"Raw bytes 长度: {len(raw)} 字节")
print(f"首 10 字节: {' '.join(f'{b:02x}' for b in raw[:10])}")

# 3. 尝试解读第 1 个字节
first_byte = raw[0]
print(f"\n首字节: 0x{first_byte:02x} = {first_byte} (十进制)")
print(f"  → 如果按 XDeDiMEkw 格式: func_idx={first_byte-1}, len={(raw[1]<<8)|raw[2]}")
print(f"  → func_idx={first_byte-1} 超出 [0..29] 范围! ❌")

# 4. 尝试解读 raw bytes 原始数据
print(f"\n完整 raw bytes 结构分析:")
# 查一下 raw 中是否有重复模式
# 检查 'GSD' 相关模式 (在 XDeDiMEkw 中不出现，但在用户 POST 中大量出现)
gsd_count = raw.count(b'GSD')
xx_term = raw.count(b'XX')
print(f"  出现 'GSD' 模式: {gsd_count} 次")
print(f"  出现 'XX' 模式: {xx_term} 次")
print(f"  这些是 greenseer 模块特有的标记 → POST 走的不是 XDeDiMEkw 路径!")

# 5. 对比分析
print("\n" + "=" * 60)
print("对比: XDeDiMEkw vs POST")
print("=" * 60)

# XDeDiMEkw 5字段 raw bytes
FIVE_FIELD_RAW = bytes([
    0x01, 0x00, 0x0c, 0x65, 0x29, 0x2a, 0x28, 0x30, 0x5d, 0x6f,
    0x51, 0x13, 0x4b, 0x32, 0x2f, 0x02, 0x00, 0x50, 0xcf, 0xa3
])

print(f"\nXDeDiMEkw (5字段):")
print(f"  首10字节: {' '.join(f'{b:02x}' for b in FIVE_FIELD_RAW[:10])}")
print(f"  func_idx=0, len=12 → 有效 ✅")
print(f"  特征: {repr(FIVE_FIELD_RAW[:15].decode('latin-1'))}")

print(f"\nPOST Param (完整指纹):")
print(f"  首10字节: {' '.join(f'{b:02x}' for b in raw[:10])}")
print(f"  func_idx=94, len=50632 → 无效 ❌")
print(f"  特征: {repr(raw[:15])}")

print(f"\n结论:")
print(f"  POST Param 使用与 XDeDiMEkw 完全不同的编码格式。")
print(f"  POST 数据包含 greenseer 模块生成的完整设备指纹 (20+字段)，")
print(f"  可能经过额外的压缩/加密 (gzip/AES) 或不同头部格式。")
print(f"  需要单独追踪 POST 编码路径才能解码。")
