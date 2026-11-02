"""生成应用图标（无第三方依赖，纯标准库）。
输出 build/icon.ico：256x256 的 PNG 载荷包在 ICO 容器里（Vista 及以上支持）。
图案：蓝紫渐变圆角方块 + 白色盾牌。
"""
import struct
import zlib
import os

S = 256


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def rounded_rect_alpha(x, y, pad, radius):
    """圆角矩形的覆盖度，返回 0..1"""
    cx = min(max(x, pad + radius), S - pad - radius)
    cy = min(max(y, pad + radius), S - pad - radius)
    dx, dy = x - cx, y - cy
    d = (dx * dx + dy * dy) ** 0.5
    if x < pad or x > S - pad or y < pad or y > S - pad:
        return 0.0
    if d <= radius:
        return 1.0
    return max(0.0, 1.0 - (d - radius))


def shield_inside(x, y):
    """盾牌形状：矩形肩部 + 底部收成尖角"""
    cx, cy = S / 2, S / 2
    w, top, bottom = 62, 48, 208
    if y < top or y > bottom:
        return False
    if y <= cy:
        return abs(x - cx) <= w
    # 下半部分按抛物线收窄
    t = (y - cy) / (bottom - cy)
    half = w * (1 - t * t * 1.02)
    return abs(x - cx) <= half


def pixel(x, y):
    a = rounded_rect_alpha(x + 0.5, y + 0.5, 8, 52)
    if a <= 0:
        return (0, 0, 0, 0)
    t = (x + y) / (2 * S)
    bg = lerp((61, 125, 255), (122, 77, 255), t)

    if shield_inside(x + 0.5, y + 0.5):
        # 盾牌内部再挖一个锁孔，做出层次
        cx, cy = S / 2, S / 2 - 10
        d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
        if d < 22 or (abs(x - cx) < 7 and cy < y < cy + 52):
            return (int(bg[0] * 0.85), int(bg[1] * 0.85), int(bg[2] * 0.85), 255)
        return (255, 255, 255, 255)

    # 四角轻微压暗
    shade = 1.0 - 0.18 * max(0.0, (abs(x - S / 2) + abs(y - S / 2)) / S - 0.55)
    return (int(bg[0] * shade), int(bg[1] * shade), int(bg[2] * shade), int(255 * a))


def build_png():
    raw = bytearray()
    for y in range(S):
        raw.append(0)  # filter type 0
        for x in range(S):
            raw.extend(pixel(x, y))

    def chunk(tag, data):
        c = struct.pack('>I', len(data)) + tag + data
        return c + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack('>IIBBBBB', S, S, 8, 6, 0, 0, 0)
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', ihdr)
            + chunk(b'IDAT', zlib.compress(bytes(raw), 9))
            + chunk(b'IEND', b''))


def main():
    png = build_png()
    header = struct.pack('<HHH', 0, 1, 1)
    entry = struct.pack('<BBBBHHII', 0, 0, 0, 0, 1, 32, len(png), 22)
    out = header + entry + png
    os.makedirs('build', exist_ok=True)
    with open(os.path.join('build', 'icon.ico'), 'wb') as f:
        f.write(out)
    print('已生成 build/icon.ico，%d 字节' % len(out))


if __name__ == '__main__':
    main()
