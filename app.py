# -*- coding: utf-8 -*-
"""app.py —— 交互式入口：扫描 Cloudflare 优选 IP 并写入 hosts。

两种用法：
  双击运行           → 交互菜单
  命令行带子命令     → app.py scan / apply / status / revert / manual

设计原则：
  * 扫描逻辑复用 cf_hunt.py，不重复实现
  * 改 hosts 前先备份，失败不硬来，改为打印手动步骤
  * 权限不足时提示提权方式，绝不静默失败
"""
from __future__ import annotations

import argparse
import random
import sys
import time

import cf_hunt
import hosts_tool
from cf_hunt import CF_RANGES, DOMAINS, PORT, https_probe, tcp_rtt

APP_NAME = "Cloudflare 优选 IP 工具"
VERSION = "1.0.0"

# 快速扫描默认规模：普通用户等不了十几分钟
QUICK_POOL = 320            # 兼容旧参数，实际以分层池为准
QUICK_SCREEN_CONC = 24
QUICK_PROBE_TOP = 40
QUICK_PROBE_CONC = 6
QUICK_VERIFY_TOP = 6
QUICK_VERIFY_N = 6
DRILL_PER_PREFIX = 96       # 钻进最优 /20 时，每个前缀细扫多少个 IP


# --------------------------------------------------------------------- 控制台
def setup_console():
    """尽量把控制台切到 UTF-8，避免中文变乱码。"""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                        # noqa: BLE001
        pass
    if hosts_tool.is_windows():
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:                                    # noqa: BLE001
            pass


def hr(char="─", width=64):
    print(char * width)


def pause():
    try:
        input("\n按回车继续…")
    except (EOFError, KeyboardInterrupt):
        pass


# --------------------------------------------------------------------- 扫描
def build_pool(limit):
    """CF 官方段，每 /24 取 1 个，随机打散后截取。"""
    ips = []
    for r in CF_RANGES:
        import ipaddress
        net = ipaddress.ip_network(r)
        for sub in net.subnets(new_prefix=24):
            ips.append(str(sub.network_address + 1))
    random.shuffle(ips)
    return ips[:limit] if limit and limit < len(ips) else ips


def build_layered_pool(per20=1):
    """分层候选池：每个 /20 前缀取一个样本点。

    为什么不用随机抽样：路由质量是按前缀聚集的。我们实测发现整个
    104.18.48.0/20 都好用，而它在随机池里的占比只有 0.27% —— 随机抽
    100 个期望命中 0.27 个，基本靠运气。

    改成每个 /20 抽 1 个点，用约 370 个样本覆盖全部 5952 个 /24，
    哪个前缀好一眼就能看出来。

    注意：CF 有些段本身比 /20 小（如 103.21.244.0/22），这种情况取它的
    父 /20 作为分组键，样本点仍落在原段内。
    """
    import ipaddress
    groups = {}
    for r in CF_RANGES:
        net = ipaddress.ip_network(r)
        if net.prefixlen >= 20:
            # 比 /20 小（或正好 /20）的段：按父 /20 分组，自身贡献若干点
            parent = net.supernet(new_prefix=20) if net.prefixlen > 20 else net
            groups.setdefault(parent, []).append(net)
        else:
            # 比 /20 大的段（如 /13、/15）：拆成多个 /20
            for sub in net.subnets(new_prefix=20):
                groups.setdefault(sub, []).append(sub)

    ips = []
    for parent, members in groups.items():
        # 在成员段里均匀取点
        first = min(members, key=lambda n: int(n.network_address))
        base = int(first.network_address)
        for k in range(per20):
            ip = ipaddress.IPv4Address(base + 1 + k)
            if ip in first:
                ips.append(str(ip))
    random.shuffle(ips)
    return ips


def screen_ips(ips, verbose=True, label=""):
    """TCP 粗筛，返回按 RTT 排序的 [(rtt, ip)]。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    alive = []
    with ThreadPoolExecutor(max_workers=QUICK_SCREEN_CONC) as ex:
        futs = {ex.submit(tcp_rtt, ip, 1.5): ip for ip in ips}
        done = 0
        for fut in as_completed(futs):
            done += 1
            try:
                rtt = fut.result()
            except Exception:                                # noqa: BLE001
                rtt = None
            if rtt is not None:
                alive.append((rtt, futs[fut]))
            if verbose and done % 80 == 0:
                pct = done / len(ips) * 100
                print(f"      {label}{done}/{len(ips)} ({pct:.0f}%)  可连通 {len(alive)}",
                      end="\r")
    alive.sort()
    if verbose:
        print(" " * 70, end="\r")
    return alive


def probe_ips(ips, domains, verbose=True):
    """HTTPS 复筛，返回 [{ip, ok, total}]。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def probe_one(ip):
        ok, total, colo = 0, None, ""
        for d in domains:
            r = https_probe(ip, d, 5.0)
            if r:
                ok += 1
                colo = r["colo"] or colo
                if total is None or r["total_ms"] < total:
                    total = r["total_ms"]
        return {"ip": ip, "ok": ok, "colo": colo,
                "total": total if total else 10 ** 6}

    out = []
    with ThreadPoolExecutor(max_workers=QUICK_PROBE_CONC) as ex:
        for fut in as_completed([ex.submit(probe_one, ip) for ip in ips]):
            try:
                out.append(fut.result())
            except Exception:                                # noqa: BLE001
                pass
    out.sort(key=lambda x: (-x["ok"], x["total"]))
    return out


def verify_ips(ips, primary, n=QUICK_VERIFY_N, verbose=True):
    """串行多采样，算丢包率 + p50/p95。"""
    results = []
    total = len(ips)
    for idx, ip in enumerate(ips, 1):
        if verbose and total > 3:
            print(f"      {idx}/{total}  {ip}", end="\r")
        samples, fails, colo = [], 0, ""
        for _ in range(n):
            r = https_probe(ip, primary, 6.0)
            if r:
                samples.append(r["total_ms"])
                colo = r["colo"] or colo
            else:
                fails += 1
            time.sleep(0.2)
        ok = len(samples)
        if ok:
            s = sorted(samples)
            p50 = s[len(s) // 2]
            p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]
        else:
            p50 = p95 = None
        results.append({
            "ip": ip, "colo": colo, "ok": ok, "n": n,
            "loss": fails / n * 100,
            "p50": p50, "p95": p95,
        })
    if verbose and total > 3:
        print(" " * 70, end="\r")
    results.sort(key=lambda r: (r["loss"], r["p95"] if r["p95"] else 10 ** 6))
    return results


def print_results(results):
    print(f"\n    {'IP':<16}{'机房':<6}{'成功':>8}{'丢包':>8}{'p50':>9}{'p95':>9}")
    for r in results:
        p50 = f"{r['p50']:.0f}ms" if r["p50"] else "-"
        p95 = f"{r['p95']:.0f}ms" if r["p95"] else "-"
        print(f"    {r['ip']:<16}{r['colo'] or '-':<6}"
              f"{r['ok']:>4}/{r['n']:<3}{r['loss']:>7.1f}%{p50:>9}{p95:>9}")


def scan(domains=None, limit=0, verbose=True, deep=True):
    """分层扫描。

    第 1 段：每个 /20 抽 1 个点，覆盖全部 CIDR（约 372 个）
    第 2 段：挑出表现最好的 /20，钻进这个前缀细扫
    第 3 段：对候选做串行多采样终选
    """
    import ipaddress
    domains = domains or DOMAINS
    primary = domains[0]
    t0 = time.time()

    # --- 第 1 段：/20 级扫底 ----------------------------------------------
    pool = build_layered_pool(1)
    if limit and limit < len(pool):
        pool = pool[:limit]
    if verbose:
        print(f"\n[1/4] 分层扫描：{len(pool)} 个 /20 样本点（覆盖 CF 全部 CIDR）")
        print(f"      TCP 粗筛中…")

    alive = screen_ips(pool, verbose)
    if verbose:
        print(f"      /20 级可连通 {len(alive)}/{len(pool)}"
              + (f"，最快 {alive[0][0]:.0f}ms" if alive else ""))
    if not alive:
        return []

    cand = [ip for _, ip in alive[:QUICK_PROBE_TOP]]
    if verbose:
        print(f"\n[2/4] HTTPS 复筛 {len(cand)} 个前缀代表 × {len(domains)} 域名…")
    probed = probe_ips(cand, domains, verbose)
    usable = [p for p in probed if p["ok"] == len(domains)]
    if verbose:
        print(f"      {len(usable)}/{len(probed)} 个能正常服务所有域名")
    if not usable:
        return []

    # --- 第 2 段：钻进最好的 /20 -------------------------------------------
    final_pool = usable[:QUICK_VERIFY_TOP]
    if deep and usable:
        best_ips = [p["ip"] for p in usable[:3]]
        prefixes = []
        for ip in best_ips:
            try:
                net = ipaddress.ip_network(ip + "/20", strict=False)
            except ValueError:
                continue
            if net not in prefixes:
                prefixes.append(net)
        if prefixes:
            drill = []
            for net in prefixes[:2]:
                for h in net.hosts():
                    drill.append(str(h))
                    if len(drill) >= DRILL_PER_PREFIX:
                        break
            if verbose:
                print(f"\n[3/4] 钻进 {len(prefixes[:2])} 个最优 /20 细扫 "
                      f"{len(drill)} 个 IP…")
            drill_alive = screen_ips(drill, verbose)
            pick = [ip for _, ip in drill_alive[:QUICK_PROBE_TOP]]
            if pick:
                drill_probed = probe_ips(pick, domains, verbose)
                drill_ok = [p for p in drill_probed if p["ok"] == len(domains)]
                if verbose:
                    print(f"      /20 内 {len(drill_ok)}/{len(drill_probed)} 个可用")
                merged = {p["ip"]: p for p in usable}
                for p in drill_ok:
                    merged[p["ip"]] = p
                final_pool = sorted(merged.values(),
                                    key=lambda x: (-x["ok"], x["total"]))[:QUICK_VERIFY_TOP]

    if verbose:
        print(f"\n[4/4] 终选：{len(final_pool)} 个 IP × {QUICK_VERIFY_N} 次串行采样…")
    results = verify_ips([p["ip"] for p in final_pool], primary, verbose=verbose)
    if verbose:
        print(f"\n      完成，用时 {time.time() - t0:.0f} 秒")
        print_results(results)
    return results



def pick_ips(results, want=2):
    """挑可以写进 hosts 的 IP：只接受完全没丢包的。"""
    clean = [r for r in results if r["loss"] == 0.0 and r["ok"] == r["n"]]
    if not clean:
        return []
    return [r["ip"] for r in clean[:want]]


# --------------------------------------------------------------------- 动作
def do_status(domains=None):
    domains = domains or DOMAINS
    hr()
    print(f"  {APP_NAME} v{VERSION}")
    hr()
    print(f"  系统平台  : {hosts_tool.platform_name()}")
    print(f"  hosts 路径: {hosts_tool.hosts_path()}")
    print(f"  管理员权限: {'是' if hosts_tool.is_admin() else '否'}")

    try:
        text = hosts_tool.read_hosts()
    except OSError as exc:
        print(f"\n  [X] 读不到 hosts：{exc}")
        return 1

    st = hosts_tool.detect_state(text, domains)
    print()
    print(f"  检测结果（关注域名：{', '.join(domains)}）：")
    print(f"    本工具的托管段      : "
          f"{('有，' + str(len(st['mine'])) + ' 条') if st['mine'] else '无'}")
    print(f"    其他工具的托管段    : "
          f"{('有，' + str(len(st['foreign'])) + ' 个') if st['foreign'] else '无'}")
    print(f"    手工写的裸条目      : "
          f"{('有，' + str(len(st['bare'])) + ' 条') if st['bare'] else '无'}")
    print(f"    与本工具无关的规则  : {st['other_count']} 条（不会被改动）")

    if st["mine"]:
        print("\n  当前生效的优选：")
        ips, doms = [], []
        for r in st["mine"]:
            if r["ip"] not in ips:
                ips.append(r["ip"])
            if r["host"] not in doms:
                doms.append(r["host"])
        print(f"    IP    : {', '.join(ips)}")
        print(f"    域名  : {', '.join(doms)}")
        print("    → 再次运行 apply 会原地更新这一段，不会新增重复条目。")
    elif st["foreign"]:
        print("\n  发现其他工具（如 cf_pin.py）写入的配置：")
        for f in st["foreign"]:
            if f["rows"]:
                print(f"    第 {f['line']} 行：{f['marker']}")
                for r in f["rows"]:
                    print(f"      {r['ip']} {r['host']}")
        print("    → 再次运行 apply 会原地改这些行的 IP，保留它的标记。")
    elif st["bare"]:
        print("\n  发现手工添加的条目：")
        for b in st["bare"]:
            print(f"    第 {b['line']} 行：{b['raw'].strip()}")
        print("    → 再次运行 apply 会原地改这些行的 IP，保留行尾注释。")
    else:
        print("\n  未发现任何与这些域名相关的配置。")
        print("    → 运行 apply 会在文件末尾新增一段，不影响已有规则。")

    if st["warnings"]:
        print("\n  [!] 注意：")
        for w in st["warnings"]:
            print(f"      {w}")
    return 0


def do_apply_fixed(ips, domains):
    """跳过扫描，直接用给定 IP 写入（--ip 参数用）。"""
    if not hosts_tool.is_admin():
        print("\n  [!] 当前没有管理员权限，无法写 hosts。")
        if hosts_tool.is_windows():
            print("      正在尝试以管理员身份重新启动…\n")
            if hosts_tool.elevate_windows():
                print("      已弹出 UAC，请在弹窗里点「是」。本窗口可以关掉了。")
                return 0
            print("      [X] 提权失败。请右键程序 → 以管理员身份运行。\n")
        else:
            print(f"      请用 sudo 重新运行：sudo python3 {sys.argv[0]}\n")
        return 2

    try:
        text = hosts_tool.read_hosts()
        st = hosts_tool.detect_state(text, domains)
        for w in st["warnings"]:
            print(f"  [!] {w}")
    except OSError:
        pass

    print(f"\n  准备写入：{', '.join(ips)}")
    print(f"  生效域名：{', '.join(domains)}")
    try:
        input("\n  回车确认写入，Ctrl+C 取消…")
    except (EOFError, KeyboardInterrupt):
        print("\n  已取消。")
        return 0

    try:
        mode, backup, actions = hosts_tool.write_hosts(ips, domains)
    except (PermissionError, OSError) as exc:
        reason, tips = hosts_tool.explain_write_failure()
        if isinstance(exc, OSError) and not isinstance(exc, PermissionError):
            reason = f"写入失败：{exc}"
        show_manual(ips, domains, reason=reason, extra_tips=tips)
        return 2

    print(f"\n  [OK] 已写入 {hosts_tool.hosts_path()}（{mode}）")
    for act in actions:
        print(f"       {act}")
    if backup:
        print(f"       原文件备份：{backup}")
    ok, how = hosts_tool.flush_dns()
    print(f"       DNS 缓存：{'已刷新' if ok else '未刷新'}（{how}）")
    print("\n  完成。请重新打开浏览器访问。")
    return 0


def do_apply(domains=None, limit=QUICK_POOL, want=2):
    domains = domains or DOMAINS
    if not hosts_tool.is_admin():
        print("\n  [!] 当前没有管理员权限，无法写 hosts。")
        if hosts_tool.is_windows():
            print("      正在尝试以管理员身份重新启动…\n")
            if hosts_tool.elevate_windows():
                print("      已弹出 UAC，请在弹窗里点「是」。本窗口可以关掉了。")
                return 0
            print("      [X] 提权失败。请右键程序 → 以管理员身份运行。\n")
        else:
            print("      请用 sudo 重新运行：")
            print(f"      sudo python3 {sys.argv[0]}\n")
        return 2

    # 先看 hosts 现状，让用户知道这次会怎么改
    existing = []
    try:
        text = hosts_tool.read_hosts()
        st = hosts_tool.detect_state(text, domains)
        if st["mine"]:
            print("\n  检测到本工具之前写入的配置，本次将原地更新。")
            existing = [r["ip"] for r in st["mine"]]
        elif st["foreign"]:
            print("\n  检测到其他工具写入的配置，本次将原地更新其中的 IP。")
        elif st["bare"]:
            print("\n  检测到手工添加的条目，本次将原地更新其 IP。")
        else:
            print("\n  未检测到相关配置，本次将在 hosts 末尾新增一段。")
        for w in st["warnings"]:
            print(f"  [!] {w}")
        print("  （文件中与本工具域名无关的规则不会被动到）")
    except OSError as exc:
        print(f"\n  [!] 读 hosts 失败：{exc}")

    results = scan(domains, limit)
    ips = pick_ips(results, want)
    if not ips:
        print("\n  [X] 没扫到零丢包的 IP，放弃写入。")
        print("      （宁可不改，也不要把有丢包的 IP 写进去）")
        if existing:
            print(f"      当前 hosts 里已有的配置保持不变：{', '.join(existing)}")
        return 1

    print(f"\n  准备写入：{', '.join(ips)}")
    print(f"  生效域名：{', '.join(domains)}")
    try:
        input("\n  回车确认写入，Ctrl+C 取消…")
    except (EOFError, KeyboardInterrupt):
        print("\n  已取消。")
        return 0

    try:
        mode, backup, actions = hosts_tool.write_hosts(ips, domains)
    except (PermissionError, OSError) as exc:
        reason, tips = hosts_tool.explain_write_failure()
        if isinstance(exc, OSError) and not isinstance(exc, PermissionError):
            reason = f"写入失败：{exc}"
        show_manual(ips, domains, reason=reason, extra_tips=tips)
        return 2

    print(f"\n  [OK] 已写入 {hosts_tool.hosts_path()}（{mode}）")
    for a in actions:
        print(f"       {a}")
    if backup:
        print(f"       原文件备份：{backup}")
    ok, how = hosts_tool.flush_dns()
    print(f"       DNS 缓存：{'已刷新' if ok else '未刷新'}（{how}）")
    print("\n  完成。请重新打开浏览器访问。")
    print("  如果没效果，检查浏览器是否开了「安全 DNS / DoH」——它会绕过 hosts。")
    return 0


def do_revert():
    if not hosts_tool.is_admin():
        print("\n  [!] 需要管理员权限才能还原 hosts。")
        if hosts_tool.is_windows():
            if hosts_tool.elevate_windows():
                print("      已弹出 UAC，请点「是」。")
                return 0
            print("      请右键程序 → 以管理员身份运行。")
        else:
            print(f"      请用 sudo 重新运行：sudo python3 {sys.argv[0]}")
        return 2
    try:
        changed, backup, msg = hosts_tool.revert_hosts()
    except OSError as exc:
        print(f"\n  [X] 还原失败：{exc}")
        return 1
    if not changed:
        print(f"\n  {msg}，无需还原。")
        return 0
    print(f"\n  [OK] {msg}")
    if backup:
        print(f"       改动前备份：{backup}")
    ok, how = hosts_tool.flush_dns()
    print(f"       DNS 缓存：{'已刷新' if ok else '未刷新'}（{how}）")
    return 0


def show_manual(ips, domains, reason="", path=None, extra_tips=None):
    info = hosts_tool.manual_instructions(ips, domains, path)
    print()
    hr("=")
    print("  手动修改说明")
    hr("=")
    if reason:
        print(f"  原因：{reason}\n")
    if extra_tips:
        for t in extra_tips:
            print(f"  · {t}")
        print()
    print(f"  文件位置：{info['path']}\n")
    print("  需要加入的内容（整段复制，包括首尾两行标记）：\n")
    hr("-")
    for line in info["block"].rstrip().splitlines():
        print(f"  {line}")
    hr("-")
    print("\n  操作步骤：")
    for s in info["steps"]:
        print(f"  {s}")
    print(f"\n  {info['note']}")
    print("\n  还原方法：把上面那整段（含标记）删掉即可。")


def do_manual(domains=None):
    """不需要扫描，直接给一份手写模板（会先看现状，给出对应的改法）。"""
    domains = domains or DOMAINS
    text = ""
    try:
        text = hosts_tool.read_hosts()
    except OSError:
        pass
    st = hosts_tool.detect_state(text, domains) if text else \
        {"mine": [], "foreign": [], "bare": [], "warnings": []}

    if st["mine"]:
        ips = []
        for r in st["mine"]:
            if r["ip"] not in ips:
                ips.append(r["ip"])
        print("\n  hosts 里已有本工具写入的配置（见「查看状态」）。")
        print("  如果要换 IP，直接改那一段里的 IP；否则无需操作。")
        show_manual(ips, domains, reason="手动修改模式（已有托管段）")
    elif st["foreign"] or st["bare"]:
        print("\n  检测到已有配置（其他工具或手工添加）。")
        print("  建议：只把那些行的 IP 改掉，不要新增重复条目。")
        cur = []
        for f in st["foreign"]:
            for r in f["rows"]:
                cur.append(r["ip"])
        for b in st["bare"]:
            cur.append(b["ip"])
        ips = list(dict.fromkeys(cur)) or ["<在这里填 IP>"]
        show_manual(ips, domains, reason="手动修改模式（已有条目，改 IP 即可）")
    else:
        show_manual(["<在这里填 IP>"], domains,
                    reason="手动修改模式（当前无相关配置，末尾追加）")
    return 0


# --------------------------------------------------------------------- 菜单
def menu():
    while True:
        print()
        hr()
        print(f"  {APP_NAME} v{VERSION}")
        print(f"  平台 {hosts_tool.platform_name()}   "
              f"权限 {'管理员' if hosts_tool.is_admin() else '普通用户'}")
        hr()
        print("  1. 扫描优选 IP 并写入 hosts（推荐）")
        print("  2. 只扫描，不修改系统")
        print("  3. 查看当前状态（会先检测已有配置）")
        print("  4. 还原 hosts（只移除本工具写入的部分）")
        print("  5. 手动修改说明（不想让程序动系统时用）")
        print("  0. 退出")
        hr()
        try:
            choice = input("  请选择 [0-5]：").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice == "0":
            return 0
        if choice == "1":
            do_apply()
            pause()
        elif choice == "2":
            scan()
            pause()
        elif choice == "3":
            do_status()
            pause()
        elif choice == "4":
            do_revert()
            pause()
        elif choice == "5":
            do_manual()
            pause()
        else:
            print("  请输入 0-5 之间的数字。")


# --------------------------------------------------------------------- main
def main():
    setup_console()
    ap = argparse.ArgumentParser(
        prog="cf-hunt", description=f"{APP_NAME} v{VERSION}")
    ap.add_argument("action", nargs="?",
                    choices=["scan", "apply", "status", "revert", "manual"],
                    help="带子命令则不进菜单")
    ap.add_argument("--domains", default="",
                    help=f"逗号分隔的域名，默认 {','.join(DOMAINS)}")
    ap.add_argument("--limit", type=int, default=QUICK_POOL,
                    help=f"候选池大小，默认 {QUICK_POOL}")
    ap.add_argument("--want", type=int, default=2,
                    help="写入几个 IP，默认 2")
    ap.add_argument("--ip", default="",
                    help="跳过扫描，直接用这些 IP 写入（逗号分隔，供测试/复用）")
    a = ap.parse_args()

    domains = [d.strip() for d in a.domains.split(",") if d.strip()] if a.domains else DOMAINS
    fixed_ips = [x.strip() for x in a.ip.split(",") if x.strip()]

    if a.action == "scan":
        scan(domains, a.limit)
        return 0
    if a.action == "apply":
        if fixed_ips:
            return do_apply_fixed(fixed_ips, domains)
        return do_apply(domains, a.limit, a.want)
    if a.action == "status":
        return do_status()
    if a.action == "revert":
        return do_revert()
    if a.action == "manual":
        return do_manual()
    return menu()


if __name__ == "__main__":
    sys.exit(main() or 0)
