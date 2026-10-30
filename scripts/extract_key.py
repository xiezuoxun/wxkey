#!/usr/bin/env python3
"""extract_key.py — 从运行中的微信进程内存里提取数据库密钥（Windows / 微信 4.x）。

⚠️ 先看这句：本脚本会读取其他进程的内存，需要以**管理员身份**运行。
   拿到密钥等于拿到该微信账号全部本地聊天记录的钥匙，请只在自己的设备上对自己
   的账号使用。

原理（三步）：
  1. 微信启动、打开数据库时，会在堆上创建一个内部结构，结构里有一个指针指向
     候选密钥缓冲区。这个结构带一段固定字节特征，可以据此精确定位。
  2. 顺着指针读出 32 字节，得到一个「原始值」(raw)。
  3. 微信 4.x 还会把 raw 和一个固定的 XOR 常量异或一次，才是真正用于解密的口令
     （passphrase）。所以需要拿到这个 XOR 常量。

关于第 3 步的 XOR 常量：
  它藏在 Weixin.dll 里，属于版本相关的逆向结果，本脚本不内置任何具体值。
  用 --xor-key 传入；不传则只验证 raw 本身（部分版本不需要异或）。
  拿不到也不要紧——用 --dump 把所有候选导出来，再拿 verify_key.py 逐个试。

用法：
  # 最省事：先不重启，直接扫（微信刚启动时成功率最高）
  python extract_key.py --db "<db_storage目录>" --dump

  # 已知 XOR 常量时
  python extract_key.py --db "<db_storage目录>" --xor-key 0f1e2d3c...

  # 扫描不到时：杀掉微信重启，再扫
  python extract_key.py --db "<db_storage目录>" --restart

  # 指定主进程（多开/多账号时必须指定）
  python extract_key.py --db "<db_storage目录>" --pid 12345

退出码：0=找到并通过校验，1=扫到候选但都不对，2=环境问题
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import struct
import subprocess
import sys
import time

PAGE_SIZE = 4096
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
HMAC_SIZE = 64
PBKDF2_ROUNDS = 256000
MAC_SALT_XOR = 0x3A

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_READABLE = {0x02, 0x04, 0x20, 0x40, 0x80}
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# 内部结构特征：6 字节任意 + 10×00 + 20 + 6×00 + 2f + 6×00
# 匹配起点（第一个任意字节）就是一个 8 字节指针，指向密钥缓冲区。
# 微信版本升级后若扫不到，需要更新这段特征（用调试器看新的结构布局）。
SIG_TAIL = bytes([0x00] * 10 + [0x20] + [0x00] * 6 + [0x2F] + [0x00] * 6)
SIG_PREFIX = 6
WECHAT_EXE = "Weixin.exe"

if os.name != "nt":
    print("[-] 本脚本仅支持 Windows")
    sys.exit(2)

k32 = ctypes.windll.kernel32


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", ctypes.c_ushort),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


def read_mem(handle: int, addr: int, size: int) -> bytes | None:
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)
    )
    if ok and got.value == size:
        return buf.raw
    return None


def iter_regions(handle: int):
    """遍历进程里可读的私有内存段。"""
    addr = 0
    mbi = MBI()
    size = ctypes.sizeof(mbi)
    while addr < 0x7FFFFFFEFFFF:
        if not k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), size):
            break
        region = mbi.RegionSize
        if (
            mbi.State == MEM_COMMIT
            and mbi.Type == MEM_PRIVATE
            and (mbi.Protect & 0xFF) in PAGE_READABLE
        ):
            yield addr, region
        addr += region


def find_wechat_pids() -> list[int]:
    try:
        import psutil
    except ImportError:
        print("[-] 需要 psutil：pip install psutil")
        sys.exit(2)
    return [
        p.info["pid"]
        for p in psutil.process_iter(["pid", "name"])
        if (p.info["name"] or "").lower() == WECHAT_EXE.lower()
    ]


def pick_main_pid(pids: list[int]) -> int:
    """多个进程时，挑占用内存最大的那个（通常是主进程）。"""
    import psutil
    best, best_rss = pids[0], -1
    for pid in pids:
        try:
            rss = psutil.Process(pid).memory_info().rss
        except Exception:
            continue
        if rss > best_rss:
            best, best_rss = pid, rss
    return best


def scan_candidates(pid: int, verbose: bool = True) -> list[bytes]:
    """扫描进程内存，返回所有候选 32 字节值。"""
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        print(f"[-] 打不开进程 {pid}，请用管理员权限运行")
        return []

    pointers = []
    scanned = 0
    try:
        for base, size in iter_regions(handle):
            data = read_mem(handle, base, size)
            if not data:
                continue
            scanned += len(data)
            pos = SIG_PREFIX
            while True:
                idx = data.find(SIG_TAIL, pos)
                if idx < 0:
                    break
                start = idx - SIG_PREFIX
                if start >= 0:
                    pointers.append(struct.unpack_from("<Q", data, start)[0])
                pos = idx + 1
    finally:
        k32.CloseHandle(handle)

    if verbose:
        print(f"[*] 已扫描 {scanned / 1024 / 1024:.0f}MB 内存，特征命中 {len(pointers)} 处")

    if not pointers:
        return []

    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return []
    seen: list[bytes] = []
    try:
        for ptr in pointers:
            if not (0x10000 < ptr < 0x7FFFFFFEFFFF):
                continue
            blob = read_mem(handle, ptr, KEY_SIZE)
            if blob and blob not in seen:
                seen.append(blob)
    finally:
        k32.CloseHandle(handle)
    return seen


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def verify(passphrase: bytes, page: bytes) -> bool:
    """用 SQLCipher 4 的 HMAC 校验判断口令是否正确。"""
    import hashlib
    import hmac as _hmac

    salt = page[:SALT_SIZE]
    enc_key = hashlib.pbkdf2_hmac("sha512", passphrase, salt, PBKDF2_ROUNDS, dklen=KEY_SIZE)
    mac_salt = bytes(b ^ MAC_SALT_XOR for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SIZE)

    reserve = IV_SIZE + HMAC_SIZE
    reserve = ((reserve + 15) // 16) * 16
    body_end = PAGE_SIZE - reserve + IV_SIZE
    mac = _hmac.new(mac_key, page[SALT_SIZE:body_end], hashlib.sha512)
    mac.update(struct.pack("<I", 1))
    stored = page[body_end:body_end + HMAC_SIZE]
    return _hmac.compare_digest(mac.digest(), stored)


def collect_dbs(target: str) -> list[str]:
    if os.path.isfile(target):
        return [target]
    found = []
    for root, _dirs, files in os.walk(target):
        for name in files:
            if name.lower().endswith(".db"):
                path = os.path.join(root, name)
                try:
                    if os.path.getsize(path) >= PAGE_SIZE:
                        found.append(path)
                except OSError:
                    continue
    return sorted(found, key=lambda p: (len(p), p))


def load_pages(dbs: list[str]) -> list[tuple[str, bytes]]:
    pages = []
    for db in dbs:
        try:
            with open(db, "rb") as fh:
                page = fh.read(PAGE_SIZE)
            if len(page) == PAGE_SIZE:
                pages.append((db, page))
        except OSError:
            continue
    return pages


def restart_wechat(exe_path: str, wait: float = 4.0) -> None:
    import psutil
    killed = 0
    for p in psutil.process_iter(["pid", "name"]):
        if (p.info["name"] or "").lower() == WECHAT_EXE.lower():
            try:
                p.kill()
                killed += 1
            except Exception:
                pass
    print(f"[*] 已结束 {killed} 个微信进程，重新启动...")
    time.sleep(2)
    try:
        subprocess.Popen([exe_path], cwd=os.path.dirname(exe_path))
    except OSError as exc:
        print(f"[-] 启动失败：{exc}")
        sys.exit(2)
    print(f"[*] 等待 {wait:.0f} 秒让微信打开数据库...")
    time.sleep(wait)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="从微信进程内存提取数据库密钥（需管理员权限）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--db", required=True, help="任一 .db 文件，或 db_storage 目录")
    ap.add_argument("--pid", type=int, help="指定微信主进程 PID（多开时必须指定）")
    ap.add_argument("--xor-key", help="微信 4.x 的 XOR 常量（64 位 hex）")
    ap.add_argument("--restart", action="store_true", help="先杀掉微信再重启，提高命中率")
    ap.add_argument("--wechat-exe", default=r"C:\Program Files\Tencent\Weixin\Weixin.exe",
                    help="Weixin.exe 路径（配合 --restart 使用）")
    ap.add_argument("--dump", action="store_true", help="把所有候选 key 打印出来，便于外部验证")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"[-] --db 路径不存在：{args.db}")
        return 2

    pages = load_pages(collect_dbs(args.db))
    if not pages:
        print("[-] 没找到可用于校验的 .db（需要至少 4096 字节）")
        return 2
    print(f"[*] 校验用数据库 {len(pages)} 个")

    if args.restart:
        restart_wechat(args.wechat_exe)

    pids = find_wechat_pids()
    if not pids:
        print("[-] 没找到运行中的 Weixin.exe。请先登录并保持微信运行。")
        return 2
    pid = args.pid if args.pid else pick_main_pid(pids)
    if pid not in pids:
        print(f"[-] PID {pid} 不是运行中的微信进程，当前有：{pids}")
        return 2
    print(f"[*] 目标进程 PID = {pid}（共 {len(pids)} 个微信进程）")

    cands = scan_candidates(pid)
    if not cands:
        print("\n[-] 没有命中特征结构。常见原因：")
        print("    1. 微信已经运行很久，打开数据库时的内部结构已不存在")
        print("       -> 加 --restart 重启微信后立刻扫描")
        print("    2. 微信版本升级，特征字节变了")
        print("       -> 需要重新定位特征（见 SKILL.md 的『特征失效』章节）")
        print("    3. 没有管理员权限，读不到主进程内存")
        return 1

    print(f"[*] 得到 {len(cands)} 个候选值")

    xors: list[tuple[str, bytes]] = [("不异或", b"")]
    if args.xor_key:
        try:
            xk = bytes.fromhex(args.xor_key.strip().lower().removeprefix("0x"))
        except ValueError:
            print("[-] --xor-key 不是合法 hex")
            return 2
        if len(xk) != KEY_SIZE:
            print(f"[-] --xor-key 应为 32 字节，实际 {len(xk)} 字节")
            return 2
        xors.append(("异或后", xk))

    tries = 0
    for cidx, cand in enumerate(cands, 1):
        for label, xk in xors:
            passphrase = xor_bytes(cand, xk) if xk else cand
            tries += 1
            for _db, page in pages:
                if verify(passphrase, page):
                    print(f"\n[+] 找到了！候选 #{cidx}（{label}）")
                    print(f"    raw     = {cand.hex()}")
                    if xk:
                        print(f"    xor_key = {xk.hex()}")
                    print(f"    密钥     = {passphrase.hex()}")
                    print(f"\n    用 verify_key.py 复核：")
                    print(f'    python verify_key.py {passphrase.hex()} "{args.db}"')
                    return 0

    print(f"\n[-] {len(cands)} 个候选 × {len(xors)} 种变换 = {tries} 次尝试，均未通过校验")
    if args.dump:
        print("\n[*] 全部候选（可拿去别处验证）：")
        for i, c in enumerate(cands, 1):
            print(f"    {i:3d}. {c.hex()}")
    if not args.xor_key:
        print("\n提示：微信 4.x 通常还需要一步 XOR。用 --xor-key 传入常量后再试。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
