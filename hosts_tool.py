# -*- coding: utf-8 -*-
"""hosts_tool.py —— 跨平台 hosts 读写（安全优先）。

核心原则（这是本工具最要紧的部分）：

  1. **绝不删除别人的规则。**
     只动与本工具域名相关的行，其余内容逐字节原样保留。

  2. **先检测，再决定怎么改。**
     - 已有本工具写的托管段        → 原地更新那一段
     - 已有原项目 cf_pin.py 的段   → 原地改段内的 IP，保留它的标记
     - 已有手工写的裸条目          → 原地改那一行的 IP，保留行尾注释
     - 什么都没有                  → 在文件末尾新增托管段

  3. **写入前先备份，原子替换，失败不留半截文件。**

  4. **权限不足不硬来**，把现成内容和步骤交给用户手抄。

平台差异全部收敛在这里：
  Windows  C:\\Windows\\System32\\drivers\\etc\\hosts   ipconfig /flushdns
  Linux    /etc/hosts                                  resolvectl / nscd
  macOS    /etc/hosts                                  killall -HUP mDNSResponder
"""
from __future__ import annotations

import glob
import ipaddress
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

BEGIN_MARK = "# >>> CF-HUNT BEGIN (managed by save-your-open-design) >>>"
END_MARK = "# <<< CF-HUNT END <<<"

# 其他同类工具可能留下的块标记（例如原项目 cf_pin.py）
_FOREIGN_BEGIN_RE = re.compile(r"^\s*#\s*>>>.*>>>\s*$")
_FOREIGN_END_RE = re.compile(r"^\s*#\s*<<<.*<<<\s*$")


# ===================================================================== 平台
def is_windows():
    return os.name == "nt"


def is_macos():
    return sys.platform == "darwin"


def is_linux():
    return sys.platform.startswith("linux")


def platform_name():
    if is_windows():
        return "Windows"
    if is_macos():
        return "macOS"
    if is_linux():
        return "Linux"
    return platform.system() or "Unknown"


def hosts_path():
    if os.environ.get("CF_HUNT_HOSTS"):
        return os.environ["CF_HUNT_HOSTS"]
    if is_windows():
        root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
        return os.path.join(root, "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


# ===================================================================== 权限
def is_admin():
    if is_windows():
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:                                     # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def elevate_windows():
    """弹 UAC 以管理员身份重启自己。返回 True 表示已拉起。"""
    if not is_windows():
        return False
    import ctypes
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = subprocess.list2cmdline(sys.argv[1:])
        else:
            exe = sys.executable
            params = subprocess.list2cmdline(
                [os.path.abspath(sys.argv[0])] + sys.argv[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(rc) > 32
    except Exception:                                         # noqa: BLE001
        return False


# ===================================================================== 底层
def read_hosts(path=None):
    # newline="" 是关键：不加的话 Python 会把 CRLF 统一翻译成 LF，
    # 读回来的内容已经变样，之后写回就破坏了 Windows hosts 的换行。
    path = path or hosts_path()
    with open(path, "r", encoding="utf-8", errors="surrogateescape",
              newline="") as f:
        return f.read()


def detect_eol(text):
    return "\r\n" if "\r\n" in text else "\n"


def _to_lines(text):
    """统一换行后切成行列表（不含 EOL）。"""
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _split_comment(line):
    """把一行切成 (内容, 注释)。"""
    idx = line.find("#")
    if idx < 0:
        return line, ""
    return line[:idx], line[idx:]


def _indent(line):
    return line[:len(line) - len(line.lstrip())]


def _parse_entry(line):
    """解析 hosts 条目行，返回 (ip, [hostname...])；不是条目返回 (None, [])。"""
    body, _ = _split_comment(line)
    parts = body.split()
    if len(parts) < 2:
        return None, []
    try:
        ipaddress.IPv4Address(parts[0])
    except ValueError:
        return None, []
    return parts[0], parts[1:]


def _cf_nets():
    """CF 官方段，用于判断某个 IP 是不是「已经是指向 CF 的配置」。"""
    try:
        from cf_hunt import CF_RANGES
        return [ipaddress.ip_network(r) for r in CF_RANGES]
    except Exception:                                         # noqa: BLE001
        return []


def looks_like_cf_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _cf_nets())


# ===================================================================== 检测
def detect_state(text, domains):
    """扫描 hosts，找出与本工具域名相关的全部配置。

    返回 dict，供状态展示和写入决策使用。
    """
    dset = {d.lower() for d in domains}
    lines = _to_lines(text)
    mine, foreign, bare = [], [], []
    in_mine = False
    cur = None
    other_count = 0

    for idx, line in enumerate(lines):
        ln = idx + 1
        s = line.strip()
        if s == BEGIN_MARK:
            in_mine = True
            continue
        if s == END_MARK:
            in_mine = False
            continue
        if in_mine:
            ip, hosts = _parse_entry(line)
            if ip:
                for h in hosts:
                    if h.lower() in dset:
                        mine.append({"line": ln, "ip": ip, "host": h})
            continue
        if cur is not None:
            if _FOREIGN_END_RE.match(s):
                foreign.append(cur)
                cur = None
                continue
            ip, hosts = _parse_entry(line)
            if ip:
                for h in hosts:
                    if h.lower() in dset:
                        cur["rows"].append({"line": ln, "ip": ip, "host": h})
            continue
        if _FOREIGN_BEGIN_RE.match(s):
            cur = {"line": ln, "marker": s, "rows": []}
            continue
        ip, hosts = _parse_entry(line)
        if ip:
            hit = [h for h in hosts if h.lower() in dset]
            if hit:
                bare.append({"line": ln, "ip": ip, "hosts": hosts, "raw": line,
                             "matched": hit})
            else:
                other_count += 1
        elif s and not s.startswith("#"):
            other_count += 1

    # 冲突提示
    warnings = []
    for b in bare:
        if not looks_like_cf_ip(b["ip"]):
            warnings.append(
                f"第 {b['line']} 行的手工条目指向 {b['ip']}（非 Cloudflare 段），"
                f"看起来是故意屏蔽；本工具会改写它，如需保留请先备份。")
    for f in foreign:
        if f["rows"]:
            warnings.append(
                f"第 {f['line']} 行发现其他工具的托管段（{f['marker']}），"
                f"将原地更新其中的 IP，保留它的标记不动。")

    return {
        "mine": mine,
        "foreign": foreign,
        "bare": bare,
        "other_count": other_count,
        "warnings": warnings,
        "has_mine_block": BEGIN_MARK in text,
        "total_lines": len(lines),
    }


def current_block(text, domains=None):
    """取当前托管段里的 (ip, domain)。"""
    if domains is None:
        domains = None
    return [(r["ip"], r["host"]) for r in detect_state(text, domains or [])["mine"]]


# ===================================================================== 生成
def render_block(ips, domains, eol="\n"):
    lines = [BEGIN_MARK]
    for d in domains:
        for ip in ips:
            lines.append(f"{ip} {d}")
    lines.append(END_MARK)
    return eol.join(lines) + eol


def plan_write(text, ips, domains):
    """计算写入方案，不落盘。

    返回 (new_text, actions)：
      actions 是给人看的变更说明，用于写入前预览。
    """
    dset = {d.lower() for d in domains}
    lines = _to_lines(text)
    eol = detect_eol(text)
    had_trailing = text.endswith("\n") or text.endswith("\r")

    out = []
    actions = []
    touched = False
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        s = line.strip()

        # ---- 本工具的旧托管段：原地换成新内容（含标记） ----
        if s == BEGIN_MARK:
            while i < n and lines[i].strip() != END_MARK:
                i += 1
            i += 1  # 跳过 END
            out.append(BEGIN_MARK)
            for d in domains:
                for ip in ips:
                    out.append(f"{ip} {d}")
            out.append(END_MARK)
            touched = True
            actions.append(f"更新已有的托管段：改成 {len(ips)} 个 IP × "
                           f"{len(domains)} 个域名")
            continue

        # ---- 其他工具的托管段：只改里面涉及本工具域名的行 ----
        if _FOREIGN_BEGIN_RE.match(s):
            out.append(line)
            i += 1
            changed = 0
            while i < n and not _FOREIGN_END_RE.match(lines[i].strip()):
                inner = lines[i]
                ip, hosts = _parse_entry(inner)
                if ip:
                    hit = [h for h in hosts if h.lower() in dset]
                    keep = [h for h in hosts if h.lower() not in dset]
                    if hit:
                        indent = _indent(inner)
                        for ipx in ips:
                            out.append(f"{indent}{ipx} {' '.join(hit)}")
                        if keep:
                            out.append(f"{indent}{ip} {' '.join(keep)}")
                        changed += 1
                        touched = True
                        i += 1
                        continue
                out.append(inner)
                i += 1
            actions.append(f"更新其他工具托管段中的 {changed} 行 IP（保留其标记）")
            continue

        # ---- 手工裸条目：原地改 IP，保留缩进与行尾注释 ----
        ip, hosts = _parse_entry(line)
        if ip:
            hit = [h for h in hosts if h.lower() in dset]
            if hit:
                body, comment = _split_comment(line)
                indent = _indent(line)
                keep = [h for h in hosts if h.lower() not in dset]
                for k, ipx in enumerate(ips):
                    tail = comment if k == 0 and comment else ""
                    out.append(f"{indent}{ipx} {' '.join(hit)}{(' ' + tail) if tail else ''}")
                if keep:
                    out.append(f"{indent}{ip} {' '.join(keep)}"
                               f"{(' ' + comment) if comment else ''}")
                touched = True
                actions.append(f"改写第 {i + 1} 行的手工条目：{ip} → "
                               f"{', '.join(ips)}（保留注释）")
                i += 1
                continue

        out.append(line)
        i += 1

    # ---- 什么都没找到：末尾追加完整托管段（含标记） ----
    if not touched:
        while out and out[-1].strip() == "":
            out.pop()
        if out:
            out.append("")
        out.append(BEGIN_MARK)
        for d in domains:
            for ip in ips:
                out.append(f"{ip} {d}")
        out.append(END_MARK)
        actions.append(f"在文件末尾新增托管段：{len(ips)} 个 IP × "
                       f"{len(domains)} 个域名（未改动任何已有内容）")

    new_text = eol.join(out)
    if had_trailing or not text:
        new_text += eol
    return new_text, actions


# ===================================================================== 写入
def _atomic_write(path, text, backup=True):
    backup_path = None
    if backup and os.path.exists(path):
        stamp = time.strftime("%Y%m%d_%H%M%S")
        cand = f"{path}.bak.{stamp}"
        try:
            shutil.copy2(path, cand)
            backup_path = cand
        except OSError:
            backup_path = None

    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".cfhunt-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape",
                       newline="") as f:
            f.write(text)
        try:
            shutil.copymode(path, tmp)
        except OSError:
            pass
        delays = (0.15, 0.4, 0.8, 1.5)
        for i in range(len(delays) + 1):
            try:
                os.replace(tmp, path)
                return "atomic", backup_path
            except OSError as exc:
                if not is_windows() or getattr(exc, "winerror", None) not in (5, 32, 33):
                    break
                if i < len(delays):
                    time.sleep(delays[i])
        with open(path, "w", encoding="utf-8", errors="surrogateescape",
                  newline="") as f:
            f.write(text)
        return "in-place", backup_path
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def write_hosts(ips, domains, path=None):
    """安全写入。返回 (方式, 备份路径, 变更说明)。"""
    path = path or hosts_path()
    text = read_hosts(path)
    new_text, actions = plan_write(text, ips, domains)
    mode, backup = _atomic_write(path, new_text)
    return mode, backup, actions


def revert_hosts(path=None, full=False):
    """还原。

    full=False  只移除本工具的托管段（其他工具/手工条目不动）
    full=True   从最近的 hosts.bak.* 完整回滚
    """
    path = path or hosts_path()
    if full:
        backups = sorted(glob.glob(f"{path}.bak.*"))
        if not backups:
            return False, None, "没有找到备份文件"
        latest = backups[-1]
        text_bak = read_hosts(latest)
        _atomic_write(path, text_bak, backup=False)
        return True, latest, "已从备份完整回滚"

    text = read_hosts(path)
    if BEGIN_MARK not in text:
        return False, None, "hosts 里没有本工具写入的内容"
    lines = _to_lines(text)
    eol = detect_eol(text)
    out, skip = [], False
    for line in lines:
        s = line.strip()
        if s == BEGIN_MARK:
            skip = True
            continue
        if s == END_MARK:
            skip = False
            continue
        if not skip:
            out.append(line)
    # 去掉因删除产生的连续空行尾巴
    while len(out) > 1 and out[-1].strip() == "" and out[-2].strip() == "":
        out.pop()
    new_text = eol.join(out)
    if not new_text.endswith(("\n", "\r")):
        new_text += eol
    mode, backup = _atomic_write(path, new_text)
    return True, backup, "已移除本工具写入的托管段（其他规则保持不变）"


# ===================================================================== DNS
def flush_dns():
    try:
        if is_windows():
            r = subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                               timeout=20, text=True,
                               encoding="utf-8", errors="replace")
            return r.returncode == 0, "ipconfig /flushdns"
        if is_macos():
            for cmd in (["killall", "-HUP", "mDNSResponder"],
                        ["dscacheutil", "-flushcache"]):
                try:
                    r = subprocess.run(cmd, capture_output=True, timeout=20)
                    if r.returncode == 0:
                        return True, " ".join(cmd)
                except (OSError, subprocess.SubprocessError):
                    continue
            return False, "需要 sudo 才能刷新（不刷新通常也立即生效）"
        for cmd in (["resolvectl", "flush-caches"],
                    ["systemd-resolve", "--flush-caches"],
                    ["systemctl", "restart", "nscd"]):
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=20)
                if r.returncode == 0:
                    return True, " ".join(cmd)
            except (OSError, subprocess.SubprocessError):
                continue
        return True, "无需刷新（glibc 直接读 /etc/hosts）"
    except Exception as exc:                                  # noqa: BLE001
        return False, f"刷新失败：{exc}"


# ===================================================================== 手动
def manual_instructions(ips, domains, path=None):
    path = path or hosts_path()
    eol = "\r\n" if is_windows() else "\n"
    block = render_block(ips, domains, eol)

    if is_windows():
        steps = [
            "1. 用记事本（或任意编辑器）以管理员身份打开：",
            f"   {path}",
            "2. 先看看里面有没有已经写好的 open-design.ai 条目：",
            "   - 有：把那一行的 IP 改成本工具给出的 IP 即可，不要新增重复行",
            "   - 没有：把下面整段粘贴到文件最末尾（含 BEGIN / END 两行）",
            "3. 保存。若提示无权限，可先复制到桌面改好再覆盖回去。",
            "4. 打开命令提示符，执行：ipconfig /flushdns",
            "5. 重启浏览器，访问测试。",
        ]
        note = "提示：只追加/修改这一段，不要删除文件里原有的其他规则。"
    elif is_macos():
        steps = [
            "1. 打开终端执行：",
            f"   sudo nano {path}",
            "2. 已有 open-design.ai 条目就改它的 IP；没有就追加下面整段。",
            "3. Ctrl+O 保存、Ctrl+X 退出。",
            "4. 执行：sudo killall -HUP mDNSResponder",
            "5. 重启浏览器，访问测试。",
        ]
        note = "提示：只改动与本工具域名相关的行，其他规则保持原样。"
    else:
        steps = [
            "1. 打开终端执行：",
            f"   sudo nano {path}",
            "2. 已有 open-design.ai 条目就改它的 IP；没有就在末尾追加下面整段。",
            "3. 保存退出后刷新缓存（三选一，能跑通即可）：",
            "   sudo resolvectl flush-caches",
            "   sudo systemd-resolve --flush-caches",
            "   sudo systemctl restart nscd",
            "4. 重启浏览器，访问测试。",
        ]
        note = "提示：没有 systemd 的老发行版直接读 /etc/hosts，不刷新也立即生效。"

    return {"path": path, "block": block, "steps": steps, "note": note}


if __name__ == "__main__":
    print("platform :", platform_name())
    print("hosts    :", hosts_path())
    print("admin    :", is_admin())
    try:
        t = read_hosts()
        print("可读      : 是（%d 字符）" % len(t))
        st = detect_state(t, ["open-design.ai", "www.open-design.ai"])
        print("托管段    :", len(st["mine"]), "条")
        print("其他工具段:", len(st["foreign"]), "个")
        print("手工条目  :", len(st["bare"]), "条")
        print("其他规则  :", st["other_count"], "条")
    except OSError as exc:
        print("可读      : 否（%s）" % exc)
