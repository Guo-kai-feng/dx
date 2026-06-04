"""测试 Python g 函数 vs 浏览器输出"""
from dingxiang_constid_decoder import *

t = 'AAAAA'
print('Python g functions:')
print(f'g0: {" ".join(hex(ord(c)) for c in g0_encode(t))}')
print(f'g1: {" ".join(hex(ord(c)) for c in g1_encode(t))}')
print(f'g2: {" ".join(hex(ord(c)) for c in g2_encode(t))}')
print(f'g3: {" ".join(hex(ord(c)) for c in g3_encode(t))}')
print(f'g4: {" ".join(hex(ord(c)) for c in g4_encode(t))}')
print()
print('Browser g functions:')
print('g0: 06 0b 0a 0a 19')
print('g1: ac ed ac ed ac')
print('g2: 79 77 26 26 2c')
print('g3: 82 82 c7 8e 71')
print('g4: f1 07 39 fe 16')
print()
# Compare
browser = {
    0: [0x06, 0x0b, 0x0a, 0x0a, 0x19],
    1: [0xac, 0xed, 0xac, 0xed, 0xac],
    2: [0x79, 0x77, 0x26, 0x26, 0x2c],
    3: [0x82, 0x82, 0xc7, 0x8e, 0x71],
    4: [0xf1, 0x07, 0x39, 0xfe, 0x16],
}

funcs = [g0_encode, g1_encode, g2_encode, g3_encode, g4_encode]
for i in range(5):
    py_out = [ord(c) for c in funcs[i](t)]
    br_out = browser[i]
    match = py_out == br_out
    print(f'g{i}: {"MATCH" if match else "MISMATCH"}  py={[hex(b) for b in py_out]}  br={[hex(b) for b in br_out]}')
