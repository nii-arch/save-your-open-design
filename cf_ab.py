# -*- coding: utf-8 -*-
"""cf_ab.py —— 交错 A/B 对照，排除「测量时刻的链路抖动」造成的假象。

同一时间窗口内轮流打两个 IP：如果 A 一直好、B 一直差，说明是路由差异；
如果两者一起变差，说明是链路瞬时拥塞，之前的排序不可信。

用法： python cf_ab.py 104.18.55.1 104.24.156.1 --n 15
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cf_hunt import https_probe, PRIMARY  # noqa: E402


def stat(samples, n):
    if not samples:
        return None, None
    s = sorted(samples)
    idx = min(len(s) - 1, int(round(0.95 * (len(s) - 1))))
    return round(statistics.median(s), 1), round(s[idx], 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ips", nargs="+")
    ap.add_argument("--n", type=int, default=15)
    ap.add_argument("--domain", default=PRIMARY)
    ap.add_argument("--timeout", type=float, default=6.0)
    a = ap.parse_args()

    data = {ip: {"ok": [], "fail": 0} for ip in a.ips}
    print(f"交错测试 {len(a.ips)} 个 IP × {a.n} 轮，域名 {a.domain}\n")
    print(f"    {'轮次':<6}" + "".join(f"{ip:>18}" for ip in a.ips))
    for i in range(a.n):
        line = f"    {i + 1:<6}"
        for ip in a.ips:
            r = https_probe(ip, a.domain, a.timeout)
            if r:
                data[ip]["ok"].append(r["total_ms"])
                line += f"{r['total_ms']:>15.0f}ms "
            else:
                data[ip]["fail"] += 1
                line += f"{'超时':>17} "
        print(line)
        time.sleep(0.2)

    print(f"\n    {'汇总':<6}" + "".join(f"{ip:>18}" for ip in a.ips))
    print(f"    {'成功':<6}" + "".join(
        f"{len(data[ip]['ok'])}/{a.n:<16}" for ip in a.ips))
    print(f"    {'丢包':<6}" + "".join(
        f"{data[ip]['fail'] / a.n * 100:>15.1f}%  " for ip in a.ips))
    for label, idx in (("p50", 0), ("p95", 1)):
        cells = ""
        for ip in a.ips:
            v = stat(data[ip]["ok"], a.n)[idx]
            cells += f"{v:>15.1f}ms  " if v else f"{'-':>17}  "
        print(f"    {label:<6}{cells}")


if __name__ == "__main__":
    main()
