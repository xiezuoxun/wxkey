#!/usr/bin/env python3
"""verify_key.py — 校验一把候选密钥是不是某个微信数据库真正的密钥。

原理（SQLCipher 4 公开规范，无需解密整个库）：
  加密库的第一页（4096 字节）里带了一段 HMAC 校验码。只要用候选密钥
  走一遍 SQLCipher 的密钥派生，算出同样的 HMAC，再跟文件里存的比对，
  一致就说明密钥是对的。整个过程只读数据库的第一页，速度是毫秒级。

用法：
  python verify_key.py <密钥hex> <任一.db文件>
  python verify_key.py <密钥hex> <db_storage目录>        # 自动挑库挨个试

退出码：0 = 密钥正确，1 = 不对，2 = 参数/文件问题
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import sys

PAGE_SIZE = 4096
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
HMAC_SIZE = 64
PBKDF2_ROUNDS = 256000
MAC_SALT_XOR = 0x3A


def _derive(passphrase: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """按 SQLCipher 4 的方式从口令派生出加密密钥和校验密钥。"""
    enc_key = hashlib.pbkdf2_hmac(
        "sha512", passphrase, salt, PBKDF2_ROUNDS, dklen=KEY_SIZE
    )
    mac_salt = bytes(b ^ MAC_SALT_XOR for b in salt)
    mac_key = hashlib.pbkdf2_hmac(
        "sha512", enc_key, mac_salt, 2, dklen=KEY_SIZE
    )
    return enc_key, mac_key


def verify_one(passphrase: bytes, db_path: str) -> bool:
    """用候选口令校验单个数据库文件。"""
    try:
        with open(db_path, "rb") as fh:
            page = fh.read(PAGE_SIZE)
    except OSError:
        return False
    if len(page) < PAGE_SIZE:
        return False

    salt = page[:SALT_SIZE]
    _, mac_key = _derive(passphrase, salt)

    reserve = IV_SIZE + HMAC_SIZE
    reserve = ((reserve + 15) // 16) * 16

    body_start = SALT_SIZE
    body_end = PAGE_SIZE - reserve + IV_SIZE
    mac = hmac.new(mac_key, page[body_start:body_end], hashlib.sha512)
    mac.update(struct.pack("<I", 1))

    stored_start = body_end
    stored = page[stored_start:stored_start + HMAC_SIZE]
    return hmac.compare_digest(mac.digest(), stored)


def collect_dbs(target: str) -> list[str]:
    """从单个文件或目录里收集可用于校验的数据库。"""
    if os.path.isfile(target):
        return [target]
    found = []
    for root, _dirs, files in os.walk(target):
        for name in files:
            if not name.lower().endswith(".db"):
                continue
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) >= PAGE_SIZE:
                    found.append(path)
            except OSError:
                continue
    return sorted(found, key=lambda p: (len(p), p))


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    raw = sys.argv[1].strip().lower().removeprefix("0x")
    target = sys.argv[2]

    try:
        passphrase = bytes.fromhex(raw)
    except ValueError:
        print(f"[-] 密钥不是合法的十六进制字符串：{sys.argv[1][:16]}...")
        return 2

    if len(passphrase) != KEY_SIZE:
        print(f"[-] 密钥长度不对：得到 {len(passphrase)} 字节，应为 {KEY_SIZE} 字节（64 个 hex 字符）")
        return 2

    if not os.path.exists(target):
        print(f"[-] 路径不存在：{target}")
        return 2

    dbs = collect_dbs(target)
    if not dbs:
        print(f"[-] 没找到可用的 .db 文件：{target}")
        return 2

    print(f"[*] 待校验数据库 {len(dbs)} 个")
    for db in dbs:
        ok = verify_one(passphrase, db)
        mark = "命中" if ok else "不匹配"
        print(f"    [{mark}] {os.path.basename(os.path.dirname(db))}/{os.path.basename(db)}")
        if ok:
            print(f"\n[+] 密钥正确，可用于解密该微信数据目录下所有数据库")
            return 0

    print("\n[-] 所有数据库都不匹配，这把密钥对该数据目录无效")
    return 1


if __name__ == "__main__":
    sys.exit(main())
