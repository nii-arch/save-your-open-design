# -*- coding: utf-8 -*-
"""cf_hunt.py —— 自己扫 Cloudflare 优选 IP。

原理：Cloudflare 是 anycast，同一个域名可以从任意一个边缘 IP 进入（只要 SNI 和
Host 头对得上，证书就有效）。挑一个对自己本地线路最快最稳的 IP 写进 hosts，
就能绕开 DNS 分到的那条烂路。

测量方式：低并发、宽超时、分层筛选、串行多采样。
单次探测不能作为决策依据——只有多次采样算出的丢包率才算数。

子命令：
  pool    生成候选 IP 池（CF 官方 15 段，每 /24 取 1 个，随机采样）
  screen  TCP 握手粗筛
  probe   TLS + 完整 HTTPS 请求复筛（带 colo 识别）
  verify  终选：多次采样，出 p50/p95/丢包

默认目标域名是 open-design.ai（本项目最初的来源场景），用 --domains 换成你自己的。

只用标准库。
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import socket
import ssl
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "cf_hunt")

# Cloudflare 官方公布的回源/边缘 IPv4 段 https://www.cloudflare.com/ips-v4
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

# 默认目标域名。换成你自己的站点，或者用 --domains 传参。
# 前提条件：该域名必须由 Cloudflare 托管（NS 指向 CF），否则任意 CF 边缘 IP
# 都不会为它提供有效证书。
DOMAINS = ["open-design.ai", "www.open-design.ai"]
PRIMARY = DOMAINS[0]
PORT = 443


def _ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


# --------------------------------------------------------------------------- pool
def cmd_pool(args):
    ips = []
    for r in CF_RANGES:
        net = ipaddress.ip_network(r)
        for sub in net.subnets(new_prefix=24):
            ips.append(str(sub.network_address + 1))
    random.Random(args.seed).shuffle(ips)
    if args.limit and args.limit < len(ips):
        ips = ips[:args.limit]
    path = os.path.join(OUT, "pool.txt")
    os.makedirs(OUT, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(ips) + "\n")
    print(f"[pool] {len(ips)} 个候选（CF 全部段每 /24 取 1 个，随机采样）-> {path}")


# ------------------------------------------------------------------------- screen
def tcp_rtt(ip, timeout=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.connect((ip, PORT))
        return (time.perf_counter() - t0) * 1000.0
    except OSError:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def cmd_screen(args):
    with open(args.pool, encoding="utf-8") as f:
        ips = [ln.strip() for ln in f if ln.strip()]
    print(f"[screen] TCP 粗筛 {len(ips)} 个 IP，并发 {args.concurrency}，超时 {args.timeout}s …")
    t_start = time.time()
    hits = []
    done = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = {ex.submit(tcp_rtt, ip, args.timeout): ip for ip in ips}
        for fut in as_completed(futs):
            done += 1
            ip = futs[fut]
            try:
                rtt = fut.result()
            except Exception:
                rtt = None
            if rtt is not None:
                hits.append({"ip": ip, "rtt": round(rtt, 1)})
            if done % 500 == 0:
                print(f"    {done}/{len(ips)} … 命中 {len(hits)}，{time.time()-t_start:.0f}s")
    hits.sort(key=lambda x: x["rtt"])
    path = os.path.join(OUT, "screen.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(hits, f, ensure_ascii=False, indent=1)
    print(f"[screen] 完成 {time.time()-t_start:.0f}s：{len(hits)} 个可连通，"
          f"最快 {hits[0]['rtt'] if hits else '-'}ms -> {path}")
    if hits:
        for h in hits[:10]:
            print(f"    {h['ip']:<16} {h['rtt']:>7.1f}ms")


# -------------------------------------------------------------------------- probe
def https_probe(ip, domain, timeout):
    """返回 dict(conn_ms, tls_ms, total_ms, colo) 或 None。"""
    t0 = time.perf_counter()
    try:
        raw = socket.create_connection((ip, PORT), timeout=timeout)
    except OSError:
        return None
    conn_ms = (time.perf_counter() - t0) * 1000.0
    s = None
    try:
        raw.settimeout(timeout)
        s = _ctx().wrap_socket(raw, server_hostname=domain)
        tls_ms = (time.perf_counter() - t0) * 1000.0
        req = (f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {domain}\r\n"
               "User-Agent: Mozilla/5.0 cf-hunt\r\nAccept: */*\r\n"
               "Connection: close\r\n\r\n").encode()
        s.settimeout(timeout)
        s.sendall(req)
        buf = b""
        deadline = time.perf_counter() + timeout
        while b"\r\n\r\n" not in buf and time.perf_counter() < deadline:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        total_ms = (time.perf_counter() - t0) * 1000.0
        if not buf:
            return None
        head, _, body = buf.partition(b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if " 200" not in first and " 301" not in first and " 302" not in first:
            return None
        colo = ""
        for line in body.decode("utf-8", "replace").splitlines():
            if line.startswith("colo="):
                colo = line[5:].strip()
                break
        return {"conn_ms": round(conn_ms, 1), "tls_ms": round(tls_ms, 1),
                "total_ms": round(total_ms, 1), "colo": colo}
    except (OSError, ssl.SSLError, ValueError):
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
        else:
            try:
                raw.close()
            except OSError:
                pass


def cmd_probe(args):
    if args.ips:
        cand = [x.strip() for x in args.ips.split(",") if x.strip()][:args.top]
    elif args.screen and os.path.exists(args.screen):
        with open(args.screen, encoding="utf-8") as f:
            src = json.load(f)
        cand = [x["ip"] for x in src if x["rtt"] <= args.max_rtt][:args.top]
    else:
        with open(args.pool, encoding="utf-8") as f:
            cand = [ln.strip() for ln in f if ln.strip()][:args.top]

    domains = [d.strip() for d in args.domains.split(",") if d.strip()] if args.domains else DOMAINS
    primary = domains[0]
    print(f"[probe] 复筛 {len(cand)} 个 IP × {len(domains)} 域名，"
          f"并发 {args.concurrency}，超时 {args.timeout}s …")
    t_start = time.time()
    rows = []

    def work(ip):
        out = {"ip": ip, "domains": {}}
        ok = 0
        for d in domains:
            r = https_probe(ip, d, args.timeout)
            out["domains"][d] = r
            if r:
                ok += 1
        out["ok"] = ok
        return out

    done = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(work, ip) for ip in cand]
        for fut in as_completed(futs):
            done += 1
            try:
                rows.append(fut.result())
            except Exception:
                pass
            if done % 20 == 0:
                print(f"    {done}/{len(cand)} … {time.time()-t_start:.0f}s")

    for r in rows:
        prim = r["domains"].get(primary)
        r["primary"] = prim
        r["colo"] = prim["colo"] if prim else ""
        r["total"] = prim["total_ms"] if prim else 10 ** 6
        r["tls"] = prim["tls_ms"] if prim else 10 ** 6
    rows.sort(key=lambda x: (-x["ok"], x["total"]))
    path = os.path.join(OUT, "probe.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)

    good = [r for r in rows if r["primary"]]
    print(f"[probe] 完成 {time.time()-t_start:.0f}s：{len(good)}/{len(rows)} 个能正常返回 {primary}")
    print(f"    {'IP':<16}{'机房':<6}{'TCP':>8}{'TLS':>8}{'总耗时':>9}  域名通过")
    for r in rows[:args.show]:
        p = r["primary"]
        if p:
            print(f"    {r['ip']:<16}{r['colo']:<6}{p['conn_ms']:>7.1f}ms"
                  f"{p['tls_ms']:>7.1f}ms{p['total_ms']:>8.1f}ms  {r['ok']}/{len(domains)}")
        else:
            print(f"    {r['ip']:<16}{'-':<6}{'-':>8}{'-':>8}{'-':>9}  {r['ok']}/{len(domains)}")


# ------------------------------------------------------------------------- verify
def cmd_verify(args):
    with open(args.probe, encoding="utf-8") as f:
        rows = json.load(f)
    cand = [r["ip"] for r in rows if r["primary"]][:args.top]
    if not cand:
        print("[verify] 没有候选，先跑 probe")
        return 1
    domain = args.domain or PRIMARY
    print(f"[verify] 终选 {len(cand)} 个 IP × {args.n} 次请求（串行，间隔 {args.gap}s），"
          f"域名 {domain} …")
    results = []
    for ip in cand:
        samples, fails, colo = [], 0, ""
        for i in range(args.n):
            r = https_probe(ip, domain, args.timeout)
            if r:
                samples.append(r["total_ms"])
                colo = r["colo"] or colo
            else:
                fails += 1
            time.sleep(args.gap)
        ok = len(samples)
        if ok:
            samples_sorted = sorted(samples)
            p50 = statistics.median(samples_sorted)
            idx = min(len(samples_sorted) - 1, int(round(0.95 * (len(samples_sorted) - 1))))
            p95 = samples_sorted[idx]
        else:
            p50 = p95 = None
        results.append({"ip": ip, "colo": colo, "n": args.n, "ok": ok, "fail": fails,
                        "loss": round(fails / args.n * 100, 1),
                        "p50": round(p50, 1) if p50 else None,
                        "p95": round(p95, 1) if p95 else None})
        print(f"    {ip:<16}{colo:<6} 成功 {ok}/{args.n} 丢包 {fails/args.n*100:>5.1f}% "
              f"p50={p50 if p50 else '-':>8} p95={p95 if p95 else '-':>8}")

    def score(r):
        if not r["ok"]:
            return (1, 10 ** 6)
        return (0, (r["loss"] or 0) * 20 + (r["p95"] or 10 ** 6))

    results.sort(key=score)
    path = os.path.join(OUT, "verify.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    print(f"\n[verify] 推荐顺序（丢包优先，其次 p95）：-> {path}")
    for r in results[:args.show]:
        print(f"    {r['ip']:<16}{r['colo']:<6} 丢包 {r['loss']:>5.1f}%  "
              f"p50={r['p50']}  p95={r['p95']}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pool")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--seed", type=int, default=1)
    p.set_defaults(func=cmd_pool)

    p = sub.add_parser("screen")
    p.add_argument("--pool", default=os.path.join(OUT, "pool.txt"))
    p.add_argument("--concurrency", type=int, default=24)
    p.add_argument("--timeout", type=float, default=1.5)
    p.set_defaults(func=cmd_screen)

    p = sub.add_parser("probe")
    p.add_argument("--ips", default="")
    p.add_argument("--screen", default=os.path.join(OUT, "screen.json"))
    p.add_argument("--pool", default=os.path.join(OUT, "pool.txt"))
    p.add_argument("--top", type=int, default=60)
    p.add_argument("--max-rtt", type=float, default=400.0)
    p.add_argument("--domains", default="")
    p.add_argument("--concurrency", type=int, default=6)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--show", type=int, default=25)
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("verify")
    p.add_argument("--probe", default=os.path.join(OUT, "probe.json"))
    p.add_argument("--top", type=int, default=12)
    p.add_argument("--n", type=int, default=8)
    p.add_argument("--gap", type=float, default=0.3)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--domain", default="")
    p.add_argument("--show", type=int, default=12)
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
