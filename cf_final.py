# -*- coding: utf-8 -*-
"""cf_final.py —— 决赛复核：候选 IP vs 当前 DNS 默认路径，同口径对比。

用法：
  python cf_final.py <ip1,ip2,...> [--n 10] [--domains a,b,c]
"""
from __future__ import annotations

import argparse
import os
import socket
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cf_hunt import https_probe, DOMAINS, PRIMARY  # noqa: E402


def summarize(samples, n):
    if not samples:
        return None, None
    s = sorted(samples)
    p50 = statistics.median(s)
    idx = min(len(s) - 1, int(round(0.95 * (len(s) - 1))))
    return round(p50, 1), round(s[idx], 1)


def run_one(target, domain, n, timeout=6.0):
    samples, fails = [], 0
    colo = ""
    for _ in range(n):
        ip = target
        if ip is None:
            try:
                ip = socket.getaddrinfo(domain, 443, socket.AF_INET,
                                        socket.SOCK_STREAM)[0][4][0]
            except OSError:
                fails += 1
                time.sleep(0.2)
                continue
        r = https_probe(ip, domain, timeout)
        if r:
            samples.append(r["total_ms"])
            colo = r["colo"] or colo
        else:
            fails += 1
        time.sleep(0.25)
    p50, p95 = summarize(samples, n)
    return {"target": target or "DNS", "domain": domain, "n": n,
            "ok": len(samples), "loss": round(fails / n * 100, 1),
            "p50": p50, "p95": p95, "colo": colo}


def fmt(r):
    p50 = f"{r['p50']:>8.1f}" if r["p50"] else "       -"
    p95 = f"{r['p95']:>8.1f}" if r["p95"] else "       -"
    return (f"    {r['target']:<16}{r['colo'] or '-':<5}{r['domain']:<28}"
            f"{r['ok']:>3}/{r['n']:<3}{r['loss']:>6.1f}%{p50}{p95}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ips", help="逗号分隔的候选 IP；用 DNS 表示走默认解析")
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--domains", default="")
    ap.add_argument("--timeout", type=float, default=6.0)
    a = ap.parse_args()

    domains = [d.strip() for d in a.domains.split(",") if d.strip()] if a.domains else DOMAINS
    primary = domains[0]
    targets = [x.strip() for x in a.ips.split(",") if x.strip()]

    hdr = f"    {'目标':<16}{'机房':<5}{'域名':<28}{'成功':>7}{'丢包':>8}{'p50':>9}{'p95':>9}"
    rows = []

    print("\n=== 当前 DNS 默认路径（基线） ===")
    print(hdr)
    for d in domains:
        r = run_one(None, d, a.n, a.timeout)
        rows.append(r)
        print(fmt(r))

    for ip in targets:
        print(f"\n=== 候选 IP {ip} ===")
        print(hdr)
        for d in domains:
            r = run_one(ip, d, a.n, a.timeout)
            rows.append(r)
            print(fmt(r))

    print("\n=== 汇总（主域名 %s）===" % primary)
    for r in rows:
        if r["domain"] == primary:
            print(fmt(r))


if __name__ == "__main__":
    main()
