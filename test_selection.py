# -*- coding: utf-8 -*-
"""test_selection.py —— 选路逻辑测试（纯离线，不联网、不碰真实 hosts）。

覆盖 v1.0.1 修的「扫描选 IP 不稳定 / 会选到更慢的 IP」：

1. build_drill：下钻计数必须按前缀各自算
   （旧代码用全局累计，第一个 /20 填满后第二个只进 1 个 → 只扫了一个 /20）
2. rank_key：终选主指标是 p50，不是 p95
3. current_ips_from_state：当前 IP 在别人托管段里时也要能读到
4. merge_keep：当前 IP 要并入终选池一起 A/B
5. choose_ips：新 IP 没明显更快就保持现状（防回退）

跑法：python test_selection.py
"""
from __future__ import annotations

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app
import hosts_tool

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")
        if detail:
            print(f"         {detail}")


def res(ip, p50, loss=0.0, n=8):
    """造一条 verify_ips() 风格的终选结果。"""
    ok = n if loss == 0.0 else n - max(1, round(loss * n / 100.0))
    return {"ip": ip, "colo": "FRA", "ok": ok, "n": n,
            "loss": loss, "p50": p50, "p95": p50 * 1.3}


# ---------------------------------------------------------------- 1. build_drill
def test_build_drill():
    print("\n--- 场景1：下钻计数按前缀各自算（旧代码 96+1 的 bug） ---")
    nets = [ipaddress.ip_network("104.17.144.0/20"),
            ipaddress.ip_network("162.159.0.0/20")]
    out = app.build_drill(nets, 96)

    check("2 个前缀各钻 96 个 → 192 个（旧代码只有 97 个）",
          len(out) == 192, f"实际 {len(out)}")
    check("前 96 个都在第一个 /20 里",
          all(ipaddress.ip_address(x) in nets[0] for x in out[:96]))
    check("后 96 个都在第二个 /20 里（旧代码这里只有 1 个）",
          all(ipaddress.ip_address(x) in nets[1] for x in out[96:]))
    check("192 个 IP 没有重复", len(set(out)) == 192)

    one = app.build_drill(nets[:1], 64)
    check("单前缀 × 64 → 64 个", len(one) == 64)
    check("per_prefix=0 时退化为不产出", app.build_drill(nets, 0) == [])

    check("DRILL_PREFIXES 默认钻 2 个 /20", app.DRILL_PREFIXES == 2)


# ------------------------------------------------------------------ 2. rank_key
def test_rank_key():
    print("\n--- 场景2：终选排序主指标是 p50（不是 p95） ---")
    # p95 一样、p50 不同
    a = res("1.1.1.1", 700)
    b = res("2.2.2.2", 900)
    b["p95"] = 910
    a["p95"] = 1400          # 抖动大的那个 p95 更差
    order = sorted([a, b], key=app.rank_key)
    check("p50 小的排前面（尽管它的 p95 更差）",
          order[0]["ip"] == "1.1.1.1",
          f"实际 {[r['ip'] for r in order]}")

    # 丢包优先于延迟
    lossy = res("3.3.3.3", 300, loss=12.5)
    slow_clean = res("4.4.4.4", 2000)
    order = sorted([lossy, slow_clean], key=app.rank_key)
    check("零丢包优先于低延迟（有丢包的排后面）",
          order[0]["ip"] == "4.4.4.4")

    # 全失败（p50 为 None）排最后
    dead = res("5.5.5.5", 0, loss=100.0)
    dead["p50"] = dead["p95"] = None
    order = sorted([dead, res("6.6.6.6", 5000)], key=app.rank_key)
    check("全失败的 IP 排最后", order[-1]["ip"] == "5.5.5.5")


# ------------------------------------------------------ 3. current_ips_from_state
CF_PIN_HOSTS = """# 与项目无关的用户规则
0.0.0.0 vip.xunlei.com

# >>> CLOUDFLARE-PIN BEGIN (managed by cf_pin.py) >>>
104.18.57.1 cloudflare.com
104.18.56.1 cloudflare.com
162.159.160.1 open-design.ai
162.159.160.86 www.open-design.ai
162.159.160.1 amr-link.open-design.ai
# <<< CLOUDFLARE-PIN END <<<
"""

BARE_HOSTS = """# 手工条目
104.17.144.49 open-design.ai
104.17.144.32 www.open-design.ai
"""

MINE_HOSTS = """# >>> CF-HUNT BEGIN (managed by save-your-open-design) >>>
104.17.144.49 open-design.ai
104.17.144.32 open-design.ai
# <<< CF-HUNT END <<<
"""


def test_current_ips_from_state():
    print("\n--- 场景3：当前生效 IP 要从三种来源都能读到 ---")
    st = hosts_tool.detect_state(CF_PIN_HOSTS, app.DOMAINS)
    ips = app.current_ips_from_state(st)
    check("别人托管段（cf_pin.py）里的 IP 能读到",
          ips == ["162.159.160.1", "162.159.160.86"], f"实际 {ips}")
    check("不会把 cloudflare.com 的 IP 误当成本项目 IP",
          "104.18.57.1" not in ips and "104.18.56.1" not in ips)

    st = hosts_tool.detect_state(MINE_HOSTS, app.DOMAINS)
    check("本工具托管段里的 IP 能读到",
          app.current_ips_from_state(st) == ["104.17.144.49", "104.17.144.32"])

    st = hosts_tool.detect_state(BARE_HOSTS, app.DOMAINS)
    check("手工裸条目里的 IP 能读到",
          app.current_ips_from_state(st) == ["104.17.144.49", "104.17.144.32"])

    empty = {"mine": [], "foreign": [], "bare": []}
    check("空状态 → 空列表", app.current_ips_from_state(empty) == [])
    check("字段缺失也不炸", app.current_ips_from_state({}) == [])


# ------------------------------------------------------------------ 4. merge_keep
def test_merge_keep():
    print("\n--- 场景4：当前 IP 必须并入终选池做 A/B ---")
    cands = [{"ip": "9.9.9.1", "ok": 3, "total": 500, "colo": ""},
             {"ip": "9.9.9.2", "ok": 3, "total": 600, "colo": ""}]
    merged = app.merge_keep(cands, ["162.159.160.1", "162.159.160.86"])

    check("新候选一个不少", len(merged) == 4, f"实际 {len(merged)}")
    check("当前 IP 被追加到末尾",
          [p["ip"] for p in merged][2:] == ["162.159.160.1", "162.159.160.86"])
    check("不修改传入的候选列表", len(cands) == 2)

    dup = app.merge_keep(cands, ["9.9.9.1", "162.159.160.1"])
    check("已经在候选里的 IP 不重复追加",
          [p["ip"] for p in dup] == ["9.9.9.1", "9.9.9.2", "162.159.160.1"])

    check("keep_ips 为空时原样返回", len(app.merge_keep(cands, [])) == 2)
    check("空 keep_ips 里的空串被忽略", len(app.merge_keep(cands, ["", None])) == 2)


# ------------------------------------------------------------------ 5. choose_ips
def test_choose_ips():
    print("\n--- 场景5：新 IP 没明显更快就保持现状（防回退） ---")
    margin = app.SWITCH_MARGIN
    check("阈值 SWITCH_MARGIN 在 5%~30% 之间", 0.05 <= margin <= 0.30,
          f"实际 {margin}")

    # 5.1 没有当前配置 → 取最快的 want 个
    results = [res("1.1.1.1", 800), res("2.2.2.2", 700), res("3.3.3.3", 900)]
    got = app.choose_ips(results, current=[], want=2, verbose=False)
    check("无当前配置 → 取最快的两个",
          got == ["2.2.2.2", "1.1.1.1"], f"实际 {got}")

    # 5.2 当前 IP 更快 → 保持
    results = [res("new", 1200), res("cur", 700)]
    got = app.choose_ips(results, current=["cur"], want=1, verbose=False)
    check("当前 IP 更快 → 保持当前", got == ["cur"], f"实际 {got}")

    # 5.3 新 IP 只快一点点（不足 margin）→ 保持（核心防回退）
    cur_p50 = 1000.0
    slight = cur_p50 * (1 - margin / 2)          # 只快 6%，低于 12% 门槛
    results = [res("new", slight), res("cur", cur_p50)]
    got = app.choose_ips(results, current=["cur"], want=1, verbose=False)
    check(f"新 IP 只快 {margin * 100 / 2:.0f}%（< {margin * 100:.0f}%）→ 不切换",
          got == ["cur"], f"实际 {got}")

    # 5.4 新 IP 明显更快（超过 margin）→ 切换
    clear = cur_p50 * (1 - margin * 2)           # 快 24%
    results = [res("new", clear), res("cur", cur_p50)]
    got = app.choose_ips(results, current=["cur"], want=1, verbose=False)
    check(f"新 IP 快 {margin * 200:.0f}%（> {margin * 100:.0f}%）→ 切换",
          got == ["new"], f"实际 {got}")

    # 5.5 当前 IP 有丢包 → 不保护，直接换
    results = [res("new", 1500), res("cur", 600, loss=25.0)]
    got = app.choose_ips(results, current=["cur"], want=1, verbose=False)
    check("当前 IP 有丢包 → 换掉", got == ["new"], f"实际 {got}")

    # 5.6 当前 IP 这次没测到（不在 results 里）→ 换
    results = [res("new", 1500)]
    got = app.choose_ips(results, current=["gone"], want=1, verbose=False)
    check("当前 IP 没测到 → 换掉", got == ["new"], f"实际 {got}")

    # 5.7 want=2，当前只有 1 个可用 → 保留它 + 补一个最快的新 IP
    results = [res("new1", 900), res("new2", 950), res("cur", 1000)]
    got = app.choose_ips(results, current=["cur"], want=2, verbose=False)
    check("want=2 且当前只有 1 个 → 保留当前 + 补 1 个新的",
          got == ["cur", "new1"], f"实际 {got}")

    # 5.8 want=2，当前两个都还快 → 都保留
    results = [res("new1", 900), res("c1", 700), res("c2", 720)]
    got = app.choose_ips(results, current=["c1", "c2"], want=2, verbose=False)
    check("当前两个都更快 → 两个都保留", got == ["c1", "c2"], f"实际 {got}")

    # 5.9 全部有丢包 → 空（宁可不改）
    results = [res("a", 500, loss=12.5), res("b", 600, loss=50.0)]
    check("全部有丢包 → 返回空（放弃写入）",
          app.choose_ips(results, current=[], want=2, verbose=False) == [])

    # 5.10 结果为空 → 空
    check("空结果 → 空", app.choose_ips([], current=[], want=2, verbose=False) == [])


# --------------------------------------------------- 6. 端到端：池子里必须有基线
def test_pool_includes_baseline():
    print("\n--- 场景6：端到端串起来，终选池里必须有当前 IP ---")
    st = hosts_tool.detect_state(CF_PIN_HOSTS, app.DOMAINS)
    current = app.current_ips_from_state(st)
    check("从 cf_pin.py 段拿到基线", current == ["162.159.160.1", "162.159.160.86"])

    cands = [{"ip": f"104.17.144.{i}", "ok": 3, "total": 700 + i, "colo": ""}
             for i in (10, 20, 30, 40, 50, 60)]
    pool = app.merge_keep(cands[:app.QUICK_VERIFY_TOP], current)
    pool_ips = [p["ip"] for p in pool]
    check("终选池里同时有新候选和当前 IP",
          len(pool_ips) == app.QUICK_VERIFY_TOP + 2, f"实际 {pool_ips}")
    check("两个当前 IP 都在终选池里",
          all(ip in pool_ips for ip in current))


def main():
    print("=" * 60)
    print("  选路逻辑测试（v%s）" % app.VERSION)
    print("=" * 60)
    test_build_drill()
    test_rank_key()
    test_current_ips_from_state()
    test_merge_keep()
    test_choose_ips()
    test_pool_includes_baseline()

    print("\n" + "=" * 60)
    print(f"  通过 {PASS} 项，失败 {FAIL} 项")
    print("=" * 60)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
