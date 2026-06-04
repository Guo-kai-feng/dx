"""
快速诊断: 分析用户 original Param 的结构
"""
import base64
from urllib.parse import unquote
import sys
sys.path.insert(0, ".")
from dingxiang_constid_decoder import decode_param, G_DECODE_FUNCTIONS, encode_param

USER_PARAM_SHORT = (
    "5646%23X8XIOhylijm4k93Rhwn0Xrm8wqFieStNcF68lOESzlLI"
    "lIeGtBK4lWp0t00vB7wKwHtHevtSzl0nl7p0AiEWxIDtM0BUe7dBt0A4"
    "KOKow0KJxosM2HHPS7eBAlqkKWASzGVjXXo%2B6r5jU%2F3qjTxxH28"
    "XiU1r7q3hpDYfqCp4Adr%2BGd2POo4QVDnrjnSPDZLZ9TClgDx%2F40u"
    "CX2VuX3Jhv8Ls44j09U%2B7py7Uo9lJL0E5w4aH4QWZqq1ChTjcaS%2Ba"
    "BK%2BkN%2F4QVuUboix3uGbOE76AGoPZTP1v6KJ7py7Uo9lJL0E5rrfXij"
    "EZJdr5%2FjCqRVc1TyOIRDCgTz47R%2FciJVMZJyb1J3bZTVC7RPxPRwr"
    "PmXSTGzpFlpoMno0UuEL55PmUXAcivI7bnK34%2FSQjeq6eROTXduzavR"
    "eQL%2F4plv8mGnToz3lx5Iq%2FkYhmXK7GhkLJGicqz%2BL7Czd%2FyF"
    "rUnnmK%2B8%2FGM2q%2FUoigT%2FcgHzHWWadWJfutMTOA5hTQ%2Bfyv"
    "1ZJ6Nq2rxAzbmceMEKdmWwqeL9Hr7xOPev8i%2BnzsfNEvQAsWsn2lkYA"
    "jdxTkOj9nlrfH%2FNTk6u9reOSChbNm617tBSjxMG7rp3rbbI1cBJVPh%2"
    "Bugwn1Zu5acX%2FRo%2B6NxCK5Zetu8Xr9rWKj4%2FeoGAb1%2BaL9PZ6"
    "39ueKLb9NGSbQI10vQpGYIKHlih3tb4JKyjYYv2KTG2BNSjAPCgh5hpgad"
    "DDIlj8F%2FJtzC1Yth6kJir8PRJK9FMhb2lsONWlt%2FRKPsniOLAJwI0"
    "cysL8BbHXPTLejSFbdgLU5OpgdRFzs1ZVIfuQf3L6wVVr%2FWkdbTM6o9"
    "lu%2B%2F8OgSnxvATRKLDX6Gb4E6vvbCGzcxgOzJ768ocecjKHdm%2B%2"
    "BqOnd01zYoewUxtwt6jXuXcrbDrZLccYfVsPNZba9a3FUhS1VD9laToO0"
    "AR0JJaZF2%2F%2BnpiCJj51NpJsKYb22KeTLyPCDgawF%2Blhv8baMgua"
    "ADEATz5%2BZp%2BM2nharmimYeqEZMbCkz4%2F8efHlt4EKzcVACAQy0L"
    "STSCAJGAfoRw7RIagFfUiij4%2B9bvurg3VzoxBNoixAtuAk3OV9kDh4W"
    "oUSEWH%2F6KlAGgr8Jm%2Fsi2qvToUn%2FF5aW%2B7St5GYjtoqkkFfdu"
    "dNuDGX9tYhDPXnazgQn4mN7S%2FsOkmvvbdAi91rAeOyfu099PAoLKcEK3"
    "WUTPHkEAGb5D1elIWpdwddh6yEC62n2osIjShZbcehCwaesSwmVBH2NNY"
    "XuR%2B3fmH2wuyLmI5eyZ690tllDQLjR6YAhqLn0BxYOs0rFbQb%2Fy03"
    "8SUguknHGNp31jiuOmsVMaVSXIgzz4Agotu1rJhtg0plscDf6CV%2FWkw"
    "PGcL%2BLR9QmSOx9FbOWnFvBbg3dYglIRsQYus8E%2BGcvtRE%2FPXgT6"
    "nFC%2BYxaSyvNsXbCo9rPzjuhiEPO7SxT1wFnp01hsxHp7%2BwE1YByy"
    "Fop0Ag%2FZweKyMLKmNoySHFflhm8b9MKua06KXXSA6ANe%2Bh1L%2Bx9"
    "Xrjow0z4IFxvIRnkOKkozozUq%2FAGsAQLliy6OluGUd0vVev858B%2Bn"
    "ijkZK9BvUGV3RAKxSJIoY3SyQrSnDzMaWyICbqyC6KzCsNMgqSY67Sr2B"
    "87hSnthKHVk%2Bg3swvjlPvOhF2DJOhBQwGCnzLSUUEas8W1emJaKwkkZ"
    "XCvbu9%2F3Of1nMAq6yQaW3Qcccl%2BH5Hqi6c1ekW1D1h1m7J7b2gKy"
    "1hzmE2rXmSz7EqARSryXmK31cpuLVEIiX14XXrTq8M8siwgnY3TJ%2FhV"
    "8Y82wuagA%2BC8UPc7JYaX0UVnZImfFvhWvX9%2FIvwbYsTSoY94wmwnR"
    "mcZjPcXMj8%2FdPmf4XdIQX9uHPcXMX8g8PubwPwVnPuZu1%2FoCs%2Fv"
    "QRmfuswWnP9oaY2XP7Izhr5p8r22X4r1kKrPmXaxe2wQR%2FBxxA6uMgj"
    "1lUNIR%2Bqpsg1ihgPcMfDPvgiSGfq1TtHYwSO37gFcwW9IklCojhLpR%"
    "2BOAvl61vSHXMhLih6cvTguIGhM02iCoshNo7gXSwrNQk1Nc7ykuCW6uM"
    "fDP2E0SLKSIG%2BOAvl61vS83ZXIqjbxHwVJ0vopGIeQtbVGH3AslXNqj"
    "gdewUeg1cK40C0OBWQI%2BxMidfQJzs7GpOG5e5EKiZ5GK4xB0OqZwypv"
    "eztGjowlwJ0b19qW0MefBnxgE02q%2B1M%2BdHoZN57IklQxRECB61G5j"
    "poxYlbQRcVJA9cKe10JPjS4UtdsLyM0trrotL9BE7yZir2%2BBscG6OMJ"
    "JTbnk9zFU42JFOC%2BJJxB0OxFzaE%2B01lWpEwl0d9JKvqnRdyeGE2sj"
    "W0WA02ssHrq1kMK6tNGDT0oAq7oh7A25Xj3f6TTO4OX%2Fbj3aTTrgXjT"
    "JGR1oDAmJWJgWxNTW8XXO3mwuCfr%2FTXXqQ2qkhC0KFqoLtVUhjSTnXu"
    "uzjYvamc%2FpIP4fDMmqIP4fDMmqa32X%2FuNIOU23LfCu51ROcj62YO8"
    "9omhW%2FXXyQHA8QZYnqZL5aXX%2BjwiNjCA%2F6XXk7MTkTj4XDXXWL4"
    "cjBVpas1XX1kjvaWD8u18X19keJBIkN1rXPVGj%2FbowBwToX381j15om"
    "28u7pfuMtDcMoD3mPXX8Rt7WHyTAaN7Wku4AaAvhWmVXjM1wAMPT3kzvy"
    "4Avrf1x3T5XjNSaPAct8uaGWucWJzChR23XO6%2F5UNcE1CV0nTyTnt5g"
    "F%2FxNiXbsiYWp%2B2CgYVoM%2FYnbsLcLJt%2FOYu8pFtOeYP2shwu8"
    "nLVpU6Z9vXraaL8csRb5HhyIXCyDjr9ejc3SPXvsHmVpiTZTU%2FouRY5"
    "AFNfMaAVGndbcXrXswqGilnl29eHklIVjXXf%2BDrQua2y3XXkCSUeQYef"
    "uXXEhZ8t4k4G7EXfXjjCqELC8U1xBESvGUXWX4MPgfI1tg98cVZVi4BJ"
    "1WyvFiX5uwdStQ2v%2BKRz%2BMlgft1kATZIEWGzeDdKBy%2FBPgEK"
    "AOSL0GO5LFvVP5RWN75JSQjHY5lwHJQsk9hxtMNyOPdGjanOQoH7IP68"
    "BjeOPmqZGcV1Hijs2aA26rzcQSJsYcC1oao23YXXiEJpPxOKeAqi%2Bl2"
    "yXYKu1mSkCf9Ij%2FwIRYrXP8X28JyI%2F%2BroXmKRO2fUsr7IIXXfmUN"
    "Im2D3ZXmYjq7LV9pwfqQFzdpLHG4REjrX8TrcXuc9dfAZT8a46RXnI%2F"
    "rgm7T4Gh92DAmJopCWsPYQGEwMsiwMIP3pqu7EqudM56sSDQGSD15ogNV"
    "oossSDAsSD6jEquGJquMoWYboGssSDAilopCWkPX0kUGSDAsSDiDoWqgps"
    "RIpquGJqu9MsPYtsqbpqu7Equ2r5JsSDwsJopCWkPX0kUGSDAsSD%2BJ0"
    "e%2BGQsbtcGPU0shGSDQGSDD3oWsn0eNGSDAsSDYjC5pCHIQqtquMoWYbo"
    "GpCJfpCHOqwwzYfWOPX0kUGSDQGSDD3oWsn0eNGSDAsSDEnEqugwiQGSD6"
    "VtGp9xsPYtsqbp7Et2gpCJflltquMoWYboGpCJfpCWxJMwet5QItGSDQG"
    "SDD3oWsn0eNGSDAsSDYjC59BLD%2B1CSJZJn%2BsSDwsJopCWkPX0kUGS"
    "DAsSD%2BJ0e%2BGQsbtcGPU0shGSDQGSDD3oWsn0eNGSDAsSDYjC59BLD%"
    "2B1CSJZJn%2BsSDwsJopCWkPX0kUGSDAsSDNJog72AP1T2sNwpquGJqu9"
    "MsPYtsqbpqu7Equ5En9BLDKZH5pCHIteJqug0e15pGhGSDAuosptMsQGSD"
    "tKoGhGpqu7EquGSDQGSDBsosFu0ePIpqu7EquNlsNw0ekYtquGJquBtGY"
    "wMkqMws6yoWsn0eNGSDAsSD%2BZH59BEqug2D3XXhTXfrf6numu9TD9uz"
    "4N51m9v438XneWqqAii8xx%2FhXXQOdMHa6fV49CH3PCIXYM4B3db4O2u"
    "rjPg%2BuXXss6ZzOYVVk6xzJ65aXXpjRItZr5fI%2BgtQqMfXm0zhmb3Z"
    "VTWXmEZo%2FGziGMrXmN2LTRMoj9fOXY0aQIhVB7eL2H0OGnlgEGAUq5E"
    "2Ck110SLxVJJ35ZhdCUH654YVCk%2BYp5ir"
)

# 诊断步骤
param = unquote(USER_PARAM_SHORT)
version, b64 = param.split("#", 1)
print(f"Version: {version}")
print(f"Base64 data length: {len(b64)}")

raw = base64.b64decode(b64)
print(f"Raw bytes length: {len(raw)}")

# 尝试解析第一个字段
offset = 0
field_count = 0
while offset < len(raw):
    if offset + 3 > len(raw):
        print(f"  Offset {offset}: not enough bytes for header")
        break
    
    func_idx = raw[offset] - 1
    data_len = (raw[offset + 1] << 8) | raw[offset + 2]
    
    if data_len > 10000 or func_idx < 0 or func_idx >= 30:
        print(f"  Offset {offset}: INVALID header func_idx={func_idx}, data_len={data_len}")
        break
    
    xored_data = raw[offset + 3:offset + 3 + data_len]
    
    try:
        decoded = G_DECODE_FUNCTIONS[func_idx](xored_data.decode("latin-1"))
        field_count += 1
        if field_count <= 10:
            print(f"  Field {field_count}: func={func_idx}, len={data_len}, decoded={repr(decoded[:60])}")
    except Exception as e:
        print(f"  Field {field_count}: func={func_idx}, len={data_len}, ERROR: {e}")
        break
    
    offset += 3 + data_len

print(f"\nTotal fields parsed: {field_count}")
print(f"Remaining bytes at offset {offset}: {len(raw) - offset}")
