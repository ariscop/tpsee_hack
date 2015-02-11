#!/usr/bin/env python3

import sys
import crcmod
from struct import unpack
from collections import namedtuple

def to_hex(data):
    return ''.join('%02x' % x for x in data)

def to_str(data):
    try:
        return bytes(data).decode().strip('\x00')
    except:
        return data

crc32 = crcmod.predefined.mkPredefinedCrcFun('crc-32')

Header = namedtuple("Header", "magic crc length")
Kernel = namedtuple("Kernel", "unk1 offset length crc name")
Rootfs = namedtuple("Rootfs", "offset length name crc")

with open(sys.argv[1], "rb") as fd:
    data = memoryview(fd.read())

try:
    header = Header(*unpack("<8s2I", data[:16]))

    print("          Magic:", header.magic)
    print("Header Checksum:", hex(header.crc))
    print("    File Length:", header.length)
except:
    print("Not a topsee rom")
    exit(1)

if header.magic != b'FIRMWARE':
    print("Not a topsee rom")
    exit(1)

header_data = bytearray(data[:1556])
header_data[8:12] = b'\x00\x00\x00\x00'
header_crc = crc32(header_data)
if header.crc != header_crc:
    print("Header crc mismatch, expected: %s got %s" % (hex(header.crc), hex(header_crc)))
print()


kernel = Kernel(*unpack("<4I256s", data[16:0x120]))

print("       Kernel:", to_str(kernel.name))
print("      Unknown:", hex(kernel.unk1))
print("Kernel Offset:", kernel.offset)
print("  Kernel Size:", kernel.length)
print("     Checksum:", hex(kernel.crc))
kernel_data = data[kernel.offset:][:kernel.length]
kernel_crc = crc32(kernel_data)
if kernel_crc != kernel.crc:
    print("Kernel crc mismatch, expected: %s got %s" % (hex(kernel.crc), hex(kernel_crc)))
print()


rootfs = Rootfs(*unpack("<2I256sI", data[0x120:0x22C]))

print("       Rootfs:", to_str(rootfs.name))
print("Rootfs Offset:", rootfs.offset)
print("  Rootfs Size:", rootfs.length)
print("     Checksum:", hex(rootfs.crc))
rootfs_data = data[rootfs.offset:][:rootfs.length]
rootfs_crc = crc32(rootfs_data)
if rootfs_crc != rootfs.crc:
    print("Rootfs crc mismatch, expected: %s got %s" % (hex(rootfs.crc), hex(rootfs_crc)))
print()

exit(0)

print("Unpacking header")
with open("header.img", "wb") as fd:
    fd.write(header_data)

print("Unpacking kernel")
with open("kernel.uimage", "wb") as fd:
    fd.write(kernel_data)

print("Unpacking Rootfs")
with open("rootfs", "wb") as fd:
    fd.write(rootfs_data)
