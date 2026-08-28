#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPv6 启动器 (ipv6_launcher.py)
===============================

背景
----
校园网登录后 IPv6 往往不会自动生效；即使手动执行 `ipconfig /renew6`
（也就是 强制获取ipv6地址.bat 里的做法），有时也会失败、拿不到 IPv6。

本脚本做的事：
  1. 自动以管理员权限运行（网络命令需要管理员）。
  2. 重启 IPv6 网络：`ipconfig /release6` + `ipconfig /renew6`；
     可加 `--reset-adapter` 顺带禁用/启用活动网卡（更彻底，会短暂断网）。
  3. 检测 IPv6 是否真正可用（三级判定）：
        a. 本机存在全局 IPv6 地址（排除 fe80 链路本地、::1、ULA、组播）；
        b. 连通性：ping -6 或 TCP 连接外部 IPv6 目标；
        c. 并发下载测速：多线程并发下载 IPv6 镜像，最高下载速度
           必须 ≥ --min-speed-mbs（默认 50 MB/s）才算 IPv6 连通。
  4. 失败自动重试，直到 IPv6 可用或达到最大尝试次数。

用法示例
--------
  python ipv6_launcher.py                      # 默认：重启 + 检测(含测速) + 重试
  python ipv6_launcher.py --once               # 只重启检测一次
  python ipv6_launcher.py --check-only         # 只检测当前状态，不重启
  python ipv6_launcher.py --reset-adapter      # 更彻底：禁用/启用活动网卡
  python ipv6_launcher.py --min-speed-mbs 50   # 测速门槛（默认 50 MB/s）
  python ipv6_launcher.py --no-speed           # 跳过测速，只查地址+连通性
  python ipv6_launcher.py --self-test          # 形式化自检（单测+本地测速）
  python ipv6_launcher.py --no-pause           # 结束后不等待回车（自动化用）
  python ipv6_launcher.py --speed-url <url>    # 自定义测速源（可多次指定）

退出码：0 = IPv6 可用；1 = 未成功。
交互式运行时结束后会等待按回车（避免双击运行时窗口闪退），
自动化/管道调用时自动跳过等待。
"""

import argparse
import ctypes
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer

# 连通性测试目标（可被 --target 覆盖；按实测可达性排序）
PING_TARGETS = [
    "2400:3200::1",            # 阿里 AliDNS IPv6（实测可达）
    "2001:4860:4860::8888",    # Google Public DNS IPv6（实测可达）
    "2001:da8::6666",          # CERNET IPv6 DNS
    "240c::6666",              # CNNIC IPv6 DNS
]
TCP_TARGETS = [
    ("2400:3200::1", 53),          # AliDNS IPv6（实测可达）
    ("2001:4860:4860::8888", 53),  # Google DNS IPv6（实测可达）
    ("2606:4700:4700::1111", 443), # Cloudflare IPv6
]
# 并发测速源（按实测可达性排序；可被 --speed-url 覆盖）
SPEED_URLS = [
    "https://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.4-desktop-amd64.iso",
    "https://mirrors.ustc.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.4-desktop-amd64.iso",
]
DEFAULT_MIN_SPEED_MBS = 50.0

HAS_WINDOWS = sys.platform.startswith("win")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def pause_if_interactive():
    """交互式（双击运行/有控制台输入）时按回车再退出，避免窗口闪退。

    仅在 stdin 是终端时等待；被管道/自动化调用（stdin 非 tty）时直接返回。
    """
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            input("\n按回车键退出...")
    except (EOFError, KeyboardInterrupt):
        pass


def _finish(code, pause):
    """统一退出点：可选等待回车后退出。"""
    if pause:
        pause_if_interactive()
    sys.exit(code)


def run(cmd, timeout=30):
    """运行命令，返回 (returncode, stdout, stderr)。"""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if HAS_WINDOWS else 0,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


# ---------------------------------------------------------------- 提权
def is_admin() -> bool:
    if not HAS_WINDOWS:
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def elevate() -> None:
    if is_admin():
        return
    log("需要管理员权限，正在请求提权（UAC）...")
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            subprocess.list2cmdline(sys.argv), None, 1,
        )
    except Exception as e:  # noqa: BLE001
        log(f"提权失败：{e}")
        sys.exit(1)
    if ret <= 32:
        log(f"提权请求被拒绝或失败（代码 {ret}）。请右键“以管理员身份运行”。")
        sys.exit(1)
    sys.exit(0)


# ---------------------------------------------------------------- 地址检测
def _filter_global(addrs):
    """只保留全局单播 IPv6 地址。"""
    result = []
    for a in addrs:
        a = a.strip().lower()
        if (
            a and a != "::1"
            and not a.startswith("fe80")  # 链路本地
            and not a.startswith("fc")    # ULA
            and not a.startswith("fd")    # ULA
            and not a.startswith("ff")    # 组播
        ):
            result.append(a)
    return sorted(set(result))


def _parse_netsh_addresses(text):
    """从 `netsh interface ipv6 show address` 输出中提取 IPv6 地址 token。

    地址本身是 ASCII（十六进制+冒号），与系统语言无关；%zone 后缀会被去掉。
    """
    addrs = set()
    for line in text.splitlines():
        for tok in line.split():
            if ":" in tok and tok.count(":") >= 2:
                addrs.add(tok.split("%")[0].lower())
    return sorted(addrs)


def get_global_ipv6_addresses():
    """返回本机全局 IPv6 地址列表（排除链路本地/回环/ULA/组播）。

    用 `netsh interface ipv6 show address` 解析（不依赖 PowerShell/CIM，
    任何环境都可用）。
    """
    if not HAS_WINDOWS:
        # 非 Windows：用 socket 探测（尽力而为）
        addrs = set()
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
                addrs.add(info[4][0])
        except socket.gaierror:
            pass
        return _filter_global(addrs)
    rc, out, _ = run(["netsh", "interface", "ipv6", "show", "address"], timeout=30)
    if rc != 0:
        return []
    return _filter_global(_parse_netsh_addresses(out))


# ---------------------------------------------------------------- 连通性
def test_ping(targets):
    for t in targets:
        rc, _, _ = run(["ping", "-6", "-n", "1", "-w", "3000", t], timeout=10)
        if rc == 0:
            log(f"  ping6 {t} -> 通")
            return True
        log(f"  ping6 {t} -> 不通")
    return False


def test_tcp(targets):
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=3):
                log(f"  tcp {host}:{port} -> 通")
                return True
        except Exception:  # noqa: BLE001
            log(f"  tcp {host}:{port} -> 不通")
    return False


# ---------------------------------------------------------------- 并发测速
def _opener():
    """返回禁用代理的 opener（保证走直连 IPv6，不被系统代理干扰）。"""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _speed_test_one(url, concurrency, duration, timeout):
    """对单个 URL 做并发下载测速。返回 (MB/s, 总字节)。"""
    opener = _opener()
    # 先 HEAD 拿文件总长，用于切分 Range
    req = urllib.request.Request(url, method="HEAD")
    with opener.open(req, timeout=timeout) as r:
        total_size = int(r.headers.get("Content-Length") or 0)
    if total_size <= 0:
        total_size = 256 * 1024 * 1024  # 未知则按 256MB 预算
    budget = max(total_size // concurrency, 16 * 1024 * 1024)
    deadline = time.time() + duration

    def worker(i):
        start = i * budget
        if start >= total_size:
            return 0
        end = min(start + budget - 1, total_size - 1)
        req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
        total = 0
        with opener.open(req, timeout=timeout) as r:
            while time.time() < deadline:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
        return total

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(worker, i) for i in range(concurrency)]
        totals = []
        for f in futs:
            try:
                totals.append(f.result())
            except Exception:  # noqa: BLE001
                totals.append(0)  # 单个 worker 失败不影响整体测量
    elapsed = time.time() - t0
    total = sum(totals)
    mbs = total / 1e6 / elapsed if elapsed > 0 else 0.0
    return mbs, total


def speed_test(urls, concurrency=8, duration=6.0, timeout=20):
    """并发下载测速。逐个 URL 尝试直到成功。返回 (MB/s, 总字节, 使用的URL)。"""
    for url in urls:
        try:
            mbs, total = _speed_test_one(url, concurrency, duration, timeout)
            if mbs > 0:
                return mbs, total, url
        except Exception as e:  # noqa: BLE001
            log(f"  测速源 {url} 失败: {e}")
    return 0.0, 0, ""


# ---------------------------------------------------------------- 检测汇总
def check_ipv6(use_ping=True, use_tcp=True, run_speed=True,
               min_speed_mbs=DEFAULT_MIN_SPEED_MBS,
               speed_concurrency=8, speed_duration=6.0):
    addrs = get_global_ipv6_addresses()
    log(f"全局 IPv6 地址: {addrs if addrs else '无'}")
    if not addrs:
        return False, {"addresses": [], "ping": False, "tcp": False,
                       "speed_mbs": 0.0, "speed_ok": False}

    ping_ok = test_ping(PING_TARGETS) if use_ping else False
    tcp_ok = test_tcp(TCP_TARGETS) if use_tcp else False
    conn_ok = (ping_ok or tcp_ok) if (use_ping or use_tcp) else True

    speed_mbs, speed_ok = 0.0, False
    if run_speed:
        if conn_ok or not (use_ping or use_tcp):
            log(f"并发测速中（{speed_concurrency} 线程 × {speed_duration}s，"
                f"要求 ≥ {min_speed_mbs} MB/s）...")
            speed_mbs, _total, _url = speed_test(SPEED_URLS, speed_concurrency,
                                                 speed_duration)
            log(f"  并发下载速度: {speed_mbs:.1f} MB/s ({speed_mbs * 8:.0f} Mbps)"
                f" {'✅' if speed_mbs >= min_speed_mbs else '❌'}")
            speed_ok = speed_mbs >= min_speed_mbs
        else:
            log("  连通性未通过，跳过测速")

    ok = speed_ok if run_speed else conn_ok
    return ok, {"addresses": addrs, "ping": ping_ok, "tcp": tcp_ok,
                "speed_mbs": speed_mbs, "speed_ok": speed_ok}


# ---------------------------------------------------------------- 重启
def restart_ipv6(reset_adapter=False):
    log("释放 IPv6 地址 (ipconfig /release6) ...")
    run(["ipconfig", "/release6"], timeout=30)
    if reset_adapter:
        # 先重置网卡再 renew，避免 renew 的地址被禁用/启用冲掉
        reset_active_adapter()
    log("重新获取 IPv6 地址 (ipconfig /renew6) ...")
    rc, out, err = run(["ipconfig", "/renew6"], timeout=60)
    if rc != 0:
        log(f"renew6 非零返回码 {rc}: {(err or out).strip()}")


def reset_active_adapter():
    log("禁用/启用活动网卡（会短暂断网）...")
    ps = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue"
        " | Sort-Object RouteMetric | Select-Object -First 1;"
        "$a = $null;"
        "if ($r) { $a = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue };"
        "if (-not $a) { $a = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 };"
        "if ($a) {"
        "  Disable-NetAdapter -Name $a.Name -Confirm:$false;"
        "  Start-Sleep -Seconds 3;"
        "  Enable-NetAdapter -Name $a.Name -Confirm:$false;"
        "  'RESET_OK:' + $a.Name"
        "} else { 'NO_ADAPTER' }"
    )
    rc, out, err = run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        timeout=90,
    )
    msg = (out or err).strip()
    log(f"网卡重置结果: {msg or rc}")


# ---------------------------------------------------------------- 自检
class _RangeHandler(BaseHTTPRequestHandler):
    """本地测速用：支持 Range 的静态文件服务。"""
    data = b""

    def do_HEAD(self):
        self._serve()

    def do_GET(self):
        self._serve()

    def _serve(self):
        body = self.data
        rng = self.headers.get("Range", "")
        if rng.startswith("bytes="):
            start_s, _, end_s = rng[len("bytes="):].partition("-")
            start = int(start_s)
            end = int(end_s) if end_s else len(body) - 1
            end = min(end, len(body) - 1)
            body = body[start:end + 1]
            self.send_response(206)
            self.send_header("Content-Range",
                             f"bytes {start}-{end}/{len(self.data)}")
        else:
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:  # noqa: BLE001
            pass

    def log_message(self, *args):
        pass


def _local_speed_server(blob):
    _RangeHandler.data = blob
    srv = HTTPServer(("127.0.0.1", 0), _RangeHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/test.bin"


def self_test():
    """形式化自检：纯函数单测 + 本地并发测速。全部通过返回 True。"""
    results = []

    # 1. 地址过滤
    samples = ["fe80::1", "::1", "fd00::1", "fc00::1", "ff02::1",
               "2400:3200::1", "2403:ac00:238f:0:1e83:41ff:fed2:f43b"]
    got = _filter_global(samples)
    expect = ["2400:3200::1", "2403:ac00:238f:0:1e83:41ff:fed2:f43b"]
    results.append(("地址过滤", got == expect, f"got={got}"))

    # 2. netsh 输出解析（中英文混合输出）
    sample = (
        "Interface 8: 以太网\n"
        "Addr Type  DAD State   Valid Life Pref. Life Address\n"
        "---------  ----------- ---------- ---------- ------------------------\n"
        "Dhcp      Preferred  29d23h49m39s 6d23h49m39s "
        "2403:ac00:238f:0:1e83:41ff:fed2:f43b\n"
        "Other     Preferred     infinite   infinite fe80::a3b8:8357:f168:9702%8\n"
    )
    parsed = _parse_netsh_addresses(sample)
    results.append(("netsh解析(原始)", parsed == [
        "2403:ac00:238f:0:1e83:41ff:fed2:f43b",
        "fe80::a3b8:8357:f168:9702",
    ], f"got={parsed}"))
    filtered = _filter_global(parsed)
    results.append(("netsh解析+全局过滤", filtered == [
        "2403:ac00:238f:0:1e83:41ff:fed2:f43b",
    ], f"got={filtered}"))

    # 3. 本地并发测速（验证并发聚合逻辑）
    blob = os.urandom(32 * 1024 * 1024)  # 32MB
    srv, url = _local_speed_server(blob)
    try:
        mbs, total = _speed_test_one(url, concurrency=4, duration=2.0, timeout=10)
        results.append(("本地并发测速", mbs > 0 and total > 0,
                        f"{mbs:.1f} MB/s, {total} bytes"))
    finally:
        srv.shutdown()

    # 4. 坏 URL 容错
    mbs, total, used = speed_test(["http://127.0.0.1:1/nope"], concurrency=2,
                                  duration=1.0, timeout=3)
    results.append(("坏源容错", mbs == 0 and total == 0 and used == "",
                    f"mbs={mbs}, used={used!r}"))

    all_ok = True
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")
        all_ok = all_ok and ok
    return all_ok


# ---------------------------------------------------------------- main
def build_parser():
    """构造命令行参数解析器（独立成函数，便于测试）。"""
    ap = argparse.ArgumentParser(
        description="重启 IPv6 网络并检测可用性（含并发测速 ≥50MB/s），直到 IPv6 可用",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--once", action="store_true", help="只重启+检测一次，不循环")
    ap.add_argument("--check-only", action="store_true", help="只检测当前 IPv6 可用性，不重启")
    ap.add_argument("--reset-adapter", action="store_true",
                    help="重启时禁用/启用活动网卡（更彻底，会短暂断网）")
    ap.add_argument("--max-attempts", type=int, default=10, help="最大尝试次数（默认 10）")
    ap.add_argument("--interval", type=float, default=5.0, help="失败后重试间隔秒数（默认 5）")
    ap.add_argument("--settle", type=float, default=3.0, help="renew6 后等待秒数再检测（默认 3）")
    ap.add_argument("--target", action="append", default=[], help="额外 ping 目标（可多次指定）")
    ap.add_argument("--no-ping", action="store_true", help="不做 ping 测试")
    ap.add_argument("--no-tcp", action="store_true", help="不做 TCP 测试")
    ap.add_argument("--min-speed-mbs", type=float, default=DEFAULT_MIN_SPEED_MBS,
                    help=f"测速门槛 MB/s（默认 {DEFAULT_MIN_SPEED_MBS}）")
    ap.add_argument("--speed-concurrency", type=int, default=8, help="测速并发线程数（默认 8）")
    ap.add_argument("--speed-duration", type=float, default=6.0, help="测速时长秒（默认 6）")
    ap.add_argument("--speed-url", action="append", default=[], help="自定义测速源（可多次指定）")
    ap.add_argument("--no-speed", action="store_true", help="跳过测速，只查地址+连通性")
    ap.add_argument("--self-test", action="store_true", help="运行形式化自检后退出")
    ap.add_argument("--no-pause", action="store_true",
                    help="结束后不等待回车（用于脚本/自动化调用）")
    return ap


def main():
    ap = build_parser()
    args = ap.parse_args()
    pause = not args.no_pause

    if args.self_test:
        print("===== 形式化自检 =====")
        ok = self_test()
        print("自检结果:", "全部通过 ✅" if ok else "存在失败 ❌")
        _finish(0 if ok else 1, pause)

    if args.target:
        PING_TARGETS[:] = args.target
    if args.speed_url:
        SPEED_URLS[:] = args.speed_url

    if not args.check_only:
        elevate()

    log("=" * 60)
    log("IPv6 启动器：重启 + 可用性检测(含并发测速) + 自动重试")
    log(f"测速门槛: ≥ {args.min_speed_mbs} MB/s，并发 {args.speed_concurrency}，"
        f"时长 {args.speed_duration}s")
    log("=" * 60)

    if args.check_only:
        ok, info = check_ipv6(
            use_ping=not args.no_ping, use_tcp=not args.no_tcp,
            run_speed=not args.no_speed, min_speed_mbs=args.min_speed_mbs,
            speed_concurrency=args.speed_concurrency,
            speed_duration=args.speed_duration,
        )
        log(f"检测结果: {'IPv6 连通 ✅' if ok else 'IPv6 未连通 ❌'}")
        _finish(0 if ok else 1, pause)

    max_attempts = 1 if args.once else args.max_attempts

    for attempt in range(1, max_attempts + 1):
        log(f"---- 第 {attempt}/{max_attempts} 次尝试 ----")
        restart_ipv6(reset_adapter=args.reset_adapter)
        if args.settle > 0:
            log(f"等待 {args.settle}s 让地址生效...")
            time.sleep(args.settle)

        ok, info = check_ipv6(
            use_ping=not args.no_ping, use_tcp=not args.no_tcp,
            run_speed=not args.no_speed, min_speed_mbs=args.min_speed_mbs,
            speed_concurrency=args.speed_concurrency,
            speed_duration=args.speed_duration,
        )
        if ok:
            log("✅ IPv6 连通！")
            log(f"   全局地址: {', '.join(info['addresses'])}")
            if info["speed_mbs"]:
                log(f"   并发下载: {info['speed_mbs']:.1f} MB/s ({info['speed_mbs'] * 8:.0f} Mbps)")
            _finish(0, pause)

        if attempt < max_attempts:
            log(f"❌ 本次未成功，{args.interval}s 后重试...")
            if attempt >= 3 and not args.reset_adapter:
                log("提示: 多次 renew6 失败时，可加 --reset-adapter 禁用/启用网卡更彻底")
            time.sleep(args.interval)

    log("❌ 达到最大尝试次数，IPv6 仍未连通。")
    log("建议: 尝试 python ipv6_launcher.py --reset-adapter --max-attempts 15")
    _finish(1, pause)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
    input()
