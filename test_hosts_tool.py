# -*- coding: utf-8 -*-
"""test_hosts_tool.py —— 验证 hosts 改写不会伤及别人的规则。

这是本项目最关键的安全测试。每个用例都模拟一种真实会遇到的情况，
断言「与本工具无关的内容必须逐字节保留」。

    python test_hosts_tool.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hosts_tool as H

DOMAINS = ["open-design.ai", "www.open-design.ai"]
IPS = ["104.18.57.1", "104.18.56.1"]

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
            for line in str(detail).splitlines():
                print(f"         {line}")


def run_case(title, original, expect_other_preserved=True):
    """跑一个用例，返回 (new_text, actions, state)。"""
    print(f"\n--- {title} ---")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "hosts")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(original)

        text = H.read_hosts(path)
        state = H.detect_state(text, DOMAINS)
        new_text, actions = H.plan_write(text, IPS, DOMAINS)

        # 断言 1：其他规则一条不少
        if expect_other_preserved:
            for line in original.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                ip, hosts = H._parse_entry(line)
                if ip and any(h.lower() in {d.lower() for d in DOMAINS}
                              for h in hosts):
                    continue        # 这些行本来就该被改写
                check(f"保留原有规则：{s}", s in new_text,
                      f"丢失了：{s}")

        # 断言 2：不重复追加
        n_begin = new_text.count(H.BEGIN_MARK)
        check(f"托管段数量 = {n_begin}（不应重复）", n_begin <= 1,
              f"实际 {n_begin} 个")

        # 断言 3：新 IP 确实写入
        for ip in IPS:
            check(f"新 IP {ip} 已写入", ip in new_text)

        # 断言 4：写盘后能还原
        mode, backup, acts = H.write_hosts(IPS, DOMAINS, path)
        after = H.read_hosts(path)
        check("实际写入后新 IP 存在", IPS[0] in after)

        # 断言 5：detect_state 能认出写入结果
        #   - 本工具自己写的段 → mine 非空
        #   - 改的是别人的段/手工条目 → mine 为空，但 new_text 里必须有新 IP
        st2 = H.detect_state(after, DOMAINS)
        if n_begin == 1:
            check("能识别自己写入的托管段", len(st2["mine"]) > 0,
                  f"mine={len(st2['mine'])}")
        else:
            check("未新增自己的段（原地改写了已有配置）",
                  len(st2["mine"]) == 0,
                  f"mine={len(st2['mine'])}")

        print(f"  变更说明：{'; '.join(actions)}")
        return new_text, actions, state


def check_idempotent(title, original, rounds=4):
    """回归测试：反复写入，条目数必须稳定，不能累加。

    缘起：早期版本在外层托管段有多行同域名时，每行都展开成 N 个 IP，
    导致重复条目指数膨胀（10 → 18 → 34 → 66 行）。
    """
    print(f"\n--- {title} ---")
    text = original
    counts = []
    for _ in range(rounds):
        text, _actions = H.plan_write(text, IPS, DOMAINS)
        counts.append(len([ln for ln in text.splitlines()
                           if any(d in ln.lower() for d in DOMAINS)]))
    check(f"第 1 轮条目数 = {counts[0]}", counts[0] >= len(IPS) * len(DOMAINS),
          f"实际 {counts[0]}，至少应为 {len(IPS) * len(DOMAINS)}")
    check(f"反复写入不膨胀（{counts}）", len(set(counts)) == 1,
          f"每轮行数：{counts}")
    check("无重复的 域名+IP 组合",
          len({ln.strip() for ln in text.splitlines()
               if any(d in ln.lower() for d in DOMAINS)}) == counts[-1],
          "存在重复行")
    return text


def main():
    print("=" * 66)
    print(" hosts 安全改写测试")
    print("=" * 66)

    # ---------------------------------------------------------------- 场景 1
    run_case("场景1：全新 hosts，只有系统默认内容", """\
# Copyright (c) 1993-2009 Microsoft Corp.
127.0.0.1       localhost
::1             localhost
192.168.1.10    nas.local
10.0.0.5        printer.lan
""")

    # ---------------------------------------------------------------- 场景 2
    run_case("场景2：已有原项目 cf_pin.py 写的托管段（另一套标记）", """\
127.0.0.1       localhost
192.168.1.10    nas.local
# >>> CLOUDFLARE-PIN BEGIN (managed by cf_pin.py) >>>
104.26.5.1 open-design.ai
104.26.5.1 www.open-design.ai
# <<< CLOUDFLARE-PIN END <<<
10.0.0.5        printer.lan
""")

    # ---------------------------------------------------------------- 场景 3
    run_case("场景3：机主手工加过 open-design.ai 条目（带注释）", """\
127.0.0.1       localhost
192.168.1.10    nas.local
104.26.5.1   open-design.ai    # 我自己加的，别删
10.0.0.5        printer.lan
""")

    # ---------------------------------------------------------------- 场景 4
    run_case("场景4：本工具已有托管段（重复运行）", """\
127.0.0.1       localhost
# >>> CF-HUNT BEGIN (managed by save-your-open-design) >>>
104.99.99.1 open-design.ai
104.99.99.1 www.open-design.ai
# <<< CF-HUNT END <<<
192.168.1.10    nas.local
""")

    # ---------------------------------------------------------------- 场景 5
    run_case("场景5：一行写了多个域名，只改本工具的域名", """\
127.0.0.1       localhost
104.26.5.1  open-design.ai  myblog.local  # 混在一行
192.168.1.10    nas.local
""")

    # ---------------------------------------------------------------- 场景 6
    print("\n--- 场景6：屏蔽类条目（指向 0.0.0.0）应给出警告 ---")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "hosts")
        original = "127.0.0.1 localhost\n0.0.0.0 open-design.ai  # 故意屏蔽\n"
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(original)
        st = H.detect_state(H.read_hosts(path), DOMAINS)
        check("检测到屏蔽条目并给出警告", len(st["warnings"]) > 0,
              f"warnings={st['warnings']}")
        if st["warnings"]:
            print(f"  警告：{st['warnings'][0]}")

    # ---------------------------------------------------------------- 场景 7
    print("\n--- 场景7：还原只删自己的段，不动其他规则 ---")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "hosts")
        original = ("127.0.0.1 localhost\n"
                    "192.168.1.10 nas.local\n"
                    f"{H.BEGIN_MARK}\n104.18.57.1 open-design.ai\n{H.END_MARK}\n"
                    "10.0.0.5 printer.lan\n")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(original)
        changed, backup, msg = H.revert_hosts(path)
        after = H.read_hosts(path)
        check("还原后托管段消失", H.BEGIN_MARK not in after)
        check("还原后保留 localhost", "localhost" in after)
        check("还原后保留 nas.local", "nas.local" in after)
        check("还原后保留 printer.lan", "printer.lan" in after)
        print(f"  {msg}")

    # ---------------------------------------------------------------- 场景 8
    print("\n--- 场景8：CRLF 换行不被破坏 ---")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "hosts")
        original = "127.0.0.1 localhost\r\n192.168.1.10 nas.local\r\n"
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(original)
        H.write_hosts(IPS, DOMAINS, path)
        raw = open(path, "rb").read()
        check("保持 CRLF", b"\r\n" in raw)
        check("没有混入裸 LF", b"\n" not in raw.replace(b"\r\n", b""))
        check("原有内容还在", b"nas.local" in raw)

    # ---------------------------------------------------------------- 场景 9
    check_idempotent(
        "场景9：其他工具托管段里有多行同域名（幂等回归）", """\
127.0.0.1       localhost
# >>> CLOUDFLARE-PIN BEGIN (managed by cf_pin.py) >>>
104.18.57.1 open-design.ai
104.18.56.1 open-design.ai
104.18.57.1 www.open-design.ai
104.18.56.1 www.open-design.ai
104.18.57.1 amr-link.open-design.ai
# <<< CLOUDFLARE-PIN END <<<
192.168.1.10    nas.local
""")

    # ---------------------------------------------------------------- 场景 10
    check_idempotent(
        "场景10：手工裸条目有多行同域名（幂等回归）", """\
127.0.0.1       localhost
104.26.5.1   open-design.ai    # 我自己加的
104.26.6.1   open-design.ai
104.26.5.1   www.open-design.ai
192.168.1.10    nas.local
""")

    # ---------------------------------------------------------------- 场景 11
    check_idempotent(
        "场景11：本工具自己的段（重复运行的幂等回归）", """\
127.0.0.1       localhost
# >>> CF-HUNT BEGIN (managed by save-your-open-design) >>>
104.99.99.1 open-design.ai
104.99.99.1 www.open-design.ai
# <<< CF-HUNT END <<<
192.168.1.10    nas.local
""")

    # ---------------------------------------------------------------- 汇总
    print("\n" + "=" * 66)
    print(f" 通过 {PASS} 项，失败 {FAIL} 项")
    print("=" * 66)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
