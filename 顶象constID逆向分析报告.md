# 顶象(DingXiang) constID Param 加密逆向分析报告

## 1. 目标概述

| 项目 | 内容 |
|------|------|
| **目标** | 顶象 captcha SDK constID 接口 Param 参数加密 |
| **URL** | `POST http://constid.dingxiang-inc.com/udid/c1` |
| **参数** | `_t` (时间戳) + `Param` (加密指纹) |
| **加密字段** | 设备指纹 JSON → XOR 多重编码 → Base64 |
| **版本** | v1.5646.0 (6139) |
| **日期** | 2026-05-28 |

---

## 2. 逆向流程

### 2.1 Phase 1: 网络请求分析

用 MCP (`js-reverse-mcp`) 打开 `dx.html`，触发顶象 captcha 加载，截获以下请求：

```
POST http://constid.dingxiang-inc.com/udid/c1 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_t=74518&Param=5646%23X8XIOhylijm4k93Rhwn0Xrm8wq...
```

**请求特征**:
- `_t`: 毫秒级时间戳
- `Param`: 格式 `5646#<Base64>`，URL-encoded
- 前置请求: `GET /udid/c1?_t=xxx` 获取 token

### 2.2 Phase 2: JS 脚本定位

页面加载了以下关键脚本:

| 脚本 | 用途 |
|------|------|
| `captcha-ui/index.js` | captcha UI 层 |
| `ctu-greenseer/greenseer.js` | 核心加密/混淆引擎 (~76KB) |
| `constid-js/index.js` | 设备ID采集与加密 (~129KB) |
| `captcha-js/.../basic-Captcha-js.js` | captcha 基础组件 |
| `captcha-js/.../jigsaw-Captcha-js.js` | 滑块组件 |

在 `constid-js/index.js` 中搜索 `Param`，命中构造点:

```javascript
A["default"]({"Param": o["XDeDiMEkw"](r), "options": ..., "token": i})
```

### 2.3 Phase 3: 断点调试

在 `Param` 构造处设置断点 (`set_breakpoint_on_text`)，刷新页面触发断点。

**捕获到的明文对象 `r`**:

```json
{
  "cache": true,
  "lid": "7e2ac174cb6109c37176066140750adbd2b14ae88179070d3256384658beef1595e2d19d",
  "lidType": 1,
  "token": "6a17f04fEDF005UVLlsLSlIPCmLnIZnAHH0tGfO1",
  "appKey": "5f6727ec854786a86cd4c3c171d13499"
}
```

**字段说明**:

| 字段 | 含义 | 生成方式 |
|------|------|----------|
| `cache` | 是否允许缓存 | 固定 `true` |
| `lid` | 设备唯一标识 (Device ID) | 浏览器指纹 → SHA256 (64 hex) |
| `lidType` | 设备ID类型 | 1 = 通过指纹生成 |
| `token` | 会话令牌 | 从 `GET /udid/c1?_t=xxx` 响应获取 |
| `appKey` | 应用标识 | 顶象后台 appId (`5f6727ec...`) |

### 2.4 Phase 4: 核心加密函数 `XDeDiMEkw`

断点命中后单步进入 (`step into`)，进入 `y.default.<computed>.<computed>`:

```javascript
y["default"][e[763]][[Lr,Mr].join(e[13])] = function(t) {
  var r = e[82], o = n[760], u = e[764],
      c = n[761], s = e[765], f = e[13],
      v = k[n[762]][[i,r].join(e[13])], d = e[12];

  for (var l in t) {
    var j, h = d % v,
        g = k[e[766]][h],
        p = (e[12], _[[Dr,Ir,o,Nr,u].join(n[1])])(((j={})[l]=t[l], j));
    f += A(h + e[14], g((n[2], R[n[763]])(p[e[248]](n[5], -e[14])))),
    d++
  }
  return f = k[n[764]] + e[767] +
         (n[2], R[e[768]])(f, ic([c,a,s].join(n[1])))
}
```

**去混淆后的伪代码**:

```javascript
function encodeParam(t) {
  var result = '';
  var d = 0;

  for (var key in t) {
    var h = d % FNS_COUNT;          // 循环使用 30 个编码函数
    var g = G_FUNCTIONS[h];          // 取第 h 个编码函数

    // 序列化单个字段: {"key": value} → 去首尾
    var jsonStr = JSON.stringify({[key]: t[key]});
    var sliced = jsonStr.slice(1, -1);  // "key":value

    // UTF-8 编码
    var utf8ed = utf8Encode(sliced);

    // XOR 扰码
    var xored = g(utf8ed);

    // 构造头部: [h+1(BYTE)] [len_high(BYTE)] [len_low(BYTE)]
    result += toBytes(h + 1, xored.length) + xored;
    d++;
  }

  // 版本前缀 + Base64 编码
  return VERSION + '#' + base64_encode(result, ALPHABET);
}
```

---

## 3. 算法详解

### 3.1 30 个 XOR 编码函数 (g0 ~ g29)

每个字段根据字段索引 `h = d % 30` 选择不同的 XOR 函数，增加破解难度。

**完整函数表**:

| # | 算法类型 | 密钥/参数 | 对称 |
|---|----------|----------|------|
| g0 | 滑动 XOR | 密钥 `KX8Mkg9GJK`, 起始索引 36 | ✅ |
| g1 | 滚动 XOR | 初始值 46317 | ❌ (需反向状态还原) |
| g2 | 反向滑动 XOR | 密钥 `NS8hJ8mgg68` | ✅ |
| g3 | 多项式 XOR | a=451, b=2755, c=a*idx%256+b | ✅ |
| g4 | LFSR XOR | shift=3, mask=240, 初始值 132 | ✅ |
| g5 | Caesar + 偏移 | shift=23, mod=128 | ❌ |
| g6 | 多项式 XOR | key=32563, b=29065 | ✅ |
| g7 | 简单滚动 XOR | 初始值 171 | ❌ (反向状态还原) |
| g8 | ROR 4 | shift=4 | ❌ |
| g9 | 字符串 XOR | 密钥 `bhbXy6HJSaj67jk` | ✅ |
| g10 | LFSR | init=891, shift=4/7, mask=240 | ✅ |
| g11 | ROR 5 + offset | shift=5, offset=2 | ❌ |
| g12 | 简单滚动 XOR | 初始值 56737 | ❌ |
| g13 | 字符串 XOR | 密钥 `dx54gFRTbvc` | ✅ |
| g14 | nibble_swap + offset | offset=16373 | ❌ |
| g15 | 字符串 XOR | 密钥 (unicode), 起始 798 | ✅ |
| g16 | 简单滚动 XOR | 初始值 143 | ❌ |
| g17 | LFSR | init=179, shift=6/4, mask=240 | ✅ |
| g18 | 简单滚动 XOR | 初始值 98357 | ❌ |
| g19 | 常数 XOR + ROR | key=208, shift=4 | ❌ |
| g20 | ROL 4 + offset | shift=4 | ❌ |
| g21 | LFSR | init=367, shift=2/5, mask=240 | ✅ |
| g22 | 多项式 XOR | a=43521, b=24351 | ✅ |
| g23 | 字符串 XOR | 密钥 `NS7SN5gd5U8ls` | ✅ |
| g24 | 简单滚动 XOR | 初始值 72439 | ❌ |
| g25 | 简单滚动 XOR | 初始值 241 | ❌ |
| g26 | ROR 2 + offset | shift=5, offset=2 | ❌ |
| g27 | 简单滚动 XOR | 初始值 621 | ❌ |
| g28 | ROL 1 | — | ❌ |
| g29 | 字符串 XOR + 步进 | 密钥 `H7Sbx8mSHK9S`, step=3 | ✅ |

> **对称 (✅)** = 加密和解密完全相同; **非对称 (❌)** = 需要独立实现解密逻辑

### 3.2 数据包格式

每个字段编码后的二进制结构:

```
┌──────────┬──────────┬──────────┬──────────────────┐
│ func_idx │ len_high │ len_low  │  XOR 编码数据    │
│ (1 byte) │ (1 byte) │ (1 byte) │  (len bytes)     │
└──────────┴──────────┴──────────┴──────────────────┘
```

- `func_idx`: g 函数索引 + 1 (1-30)
- `len_high/len_low`: 大端序 16 位长度
- `XOR 数据`: 经对应 g 函数编码后的字节串

所有字段拼接后:

```
[field_0] [field_1] [field_2] ... [field_n]  →  Base64 编码  →  5646#<base64>
```

### 3.3 Base64 字母表

**两种编码模式**:

| 模式 | 字母表 | 使用场景 |
|------|--------|----------|
| 标准 Base64 | `A-Za-z0-9+/` | POST 请求 (完整指纹) |
| 自定义 30字符 | `$J\x1cA+N\x17a/x=z\x02g\x01S\x1e2\\O\x1au8; f[5\x1fE` | GET 预检请求 |

### 3.4 完整数据流

```
明文 JSON
    │
    ▼
字段分离 (for each key-value)
    │
    ▼
JSON.stringify({"key": value}) → slice(1,-1) 去掉 { }
    │
    ▼
R.utf8Encode() → UTF-8 编码
    │
    ▼
g[func_idx](data) → XOR 扰码
    │
    ▼
A(func_idx+1, xored_data) → 3字节头部 + 数据
    │
    ▼
拼接所有字段 → 标准/自定义 Base64 → "5646#" + Base64
```

---

## 4. 密钥材料总表

| 参数名 | 实际值 | 用途 |
|--------|--------|------|
| VERSION | `5646` | 加密版本号前缀 |
| FNS_COUNT | `30` | g 函数池大小 |
| _G0_KEY | `KX8Mkg9GJK` | g0 滑动 XOR 密钥 |
| _G0_START | `36` | g0 起始索引 |
| _G1_INIT | `46317` | g1 滚动 XOR 初值 |
| _G2_KEY | `NS8hJ8mgg68` | g2 反向滑动 XOR 密钥 |
| _G3_A/B | `451 / 2755` | g3 多项式参数 |
| _G4_SHIFT | `3` | g4 LFSR 位移量 |
| _G5_SHIFT | `23` | g5 Caesar 位移量 |
| _G6_KEY/B | `32563 / 29065` | g6 多项式参数 |
| _G7_INIT | `171` | g7 滚动 XOR 初值 |
| _G8_SHIFT | `4` | g8 ROR 位移量 |
| _G9_KEY | `bhbXy6HJSaj67jk` | g9 字符串 XOR 密钥 |
| _G10_INIT | `891` | g10 LFSR 初值 |
| _G11_SHIFT | `5` | g11 ROR 位移量 |
| _G13_KEY | `dx54gFRTbvc` | g13 字符串 XOR 密钥 |
| _G14_OFFSET | `16373` | g14 nibble_swap 偏移 |
| _G15_KEY | `滟फ़ॢথৣषআৗঐ` (Unicode) | g15 字符串 XOR 密钥 |
| _G17_INIT | `179` | g17 LFSR 初值 |
| _G18_INIT | `98357` | g18 滚动 XOR 初值 |
| _G19_KEY | `208` | g19 常数 XOR |
| _G23_KEY | `NS7SN5gd5U8ls` | g23 字符串 XOR 密钥 |
| _G24_INIT | `72439` | g24 滚动 XOR 初值 |
| _G29_KEY | `H7Sbx8mSHK9S` | g29 字符串 XOR 密钥 |

---

## 5. MCP 工具使用记录

| 步骤 | MCP 工具 | 用途 |
|------|----------|------|
| 1 | `new_page` | 打开 `dx.html` |
| 2 | `list_scripts` | 枚举加载的 JS 脚本 |
| 3 | `list_network_requests` | 截获 constid 请求 |
| 4 | `search_in_sources` | 搜索 `Param` 构造点 |
| 5 | `set_breakpoint_on_text` | 在 Param 构造处设断点 |
| 6 | `get_paused_info` | 查看断点处变量 (捕获明文 `r`) |
| 7 | `evaluate_script` | 求值加密函数, 提取密钥材料 |
| 8 | `step (into/out)` | 单步跟踪加密流程 |
| 9 | `get_script_source` | 读取混淆源码上下文 |
| 10 | `break_on_xhr` | 设置 XHR 断点监控请求 |
| 11 | `list_console_messages` | 验证 Hook 注入结果 |

**关键断点位置**: `constid-js/index.js:2:47240`

---

## 6. Python 还原工具

见 [dingxiang_constid_decoder.py](file:///c:/Users/Administrator/Desktop/dx/dingxiang_constid_decoder.py)

### 6.1 使用方法

```python
from dingxiang_constid_decoder import encode_param, decode_param, USER_PARAM

# 解码
plaintext = decode_param(USER_PARAM)
print(plaintext)
# {'cache': True, 'lid': '...', 'lidType': 1, 'token': '...', 'appKey': '...'}

# 编码
encoded = encode_param(plaintext)
# '5646#AQAMZSkqKDBdb1...'
```

### 6.2 验证结果

| 测试 | 结果 |
|------|------|
| 5字段 encode → decode 回路 | ✅ 通过 |
| Python g 函数 vs 浏览器 g 函数 (30个) | ✅ 通过 |
| 完整 POST Param 解码 | 🔄 需处理标准Base64+20+字段 |

---

## 7. 经验总结

### 7.1 技术要点

1. **混淆模式**: webpack bundle + 字符串数组混淆 (e[\d+]/n[\d+]) + 30 个 XOR 变体
2. **反混淆策略**: 不要试图反混淆整个文件, 用断点 + `evaluate_script` 直接提取运行时的明文和密钥
3. **Base64 双模式**: GET 用自定义 30 字符字母表, POST 用标准 Base64 — 同一代码路径
4. **g 函数设计**: 30 个不同的 XOR 变体, 各有独立密钥, 增加了静态分析难度但不影响动态提取

### 7.2 关键命令

```
# 搜索加密函数名
search_in_sources: "XDeDiMEkw" in constid-js

# 设断点捕获明文
set_breakpoint_on_text: "Param" on constid-js

# 提取全部 30 个 g 函数密钥
evaluate_script: for each g in k['fns'], test 'AAAAA'

# 提取 Base64 字母表
evaluate_script: ic([c,a,s].join(n[1]))
```

### 7.3 注意事项

- GET 请求的 `_t` 和 POST 不相同, 且 POST 会包含更多字段
- `token` 从 GET 响应获取, 必须配合完整流程
- `lid` 是设备指纹 SHA256, 更换浏览器/环境后变化
- POST 请求的完整指纹包含 20+ 个字段 (浏览器特征、事件轨迹等)
