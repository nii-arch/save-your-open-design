# save-your-open-design

> 拯救你的 OpenDesign 订阅，让你连通的畅快些，毕竟 OD 的订阅超划算。

一条丢包 30~50% 的国际线路，能让任何订阅都变得毫无价值。

这个工具给你这条线路找一条干净的 Cloudflare 边缘 IP，写进 hosts，绕开那条烂路。

Windows / macOS / Linux 都能用，纯 Python 标准库，零依赖。

---

## 快速开始

| 方式 | 文件 | 说明 |
|---|---|---|
| **Windows** | `dist/cf-hunt-windows.exe` | 双击运行，不需要装 Python |
| **全平台** | `dist/cf-hunt.pyz` | 需要 Python 3.8+，`python cf-hunt.pyz` |
| **源码** | `python app.py` | 交互菜单 |

打开后选 `1`，程序会自己扫描、挑零丢包的 IP、备份原 hosts、写入、刷新 DNS。

```
  1. 扫描优选 IP 并写入 hosts（推荐）
  2. 只扫描，不修改系统
  3. 查看当前状态（会先检测已有配置）
  4. 还原 hosts（只移除本工具写入的部分）
  5. 手动修改说明（不想让程序动系统时用）
  0. 退出
```

**程序会自己申请管理员权限。** 如果 UAC 被拒绝或写入被安全软件拦截，它不会硬来，而是打印现成的配置块和步骤，让你手动复制。

---

## 不用程序：手动改 hosts（纯文本方案）

如果你不想让任何程序碰系统文件，就用手工方式。整个过程只需要**记事本**和**一个 IP**。

### 第一步：拿到 IP

让程序扫出来，但不写 hosts：

```bash
python app.py scan
```

输出的表格里，挑「丢包」是 `0.0%` 的那几行，把 IP 记下来，一般取 2 个。

**记下这两个 IP，下面要用。** 不要抄别人现成的 IP——路由按运营商和地区分，抄来的基本无效。

### 第二步：用记事本打开 hosts

**Windows 的关键点：记事本必须用管理员身份开，否则存不进去。**

1. 按 `Win` 键，输入 `notepad` 或 `记事本`
2. 在搜索结果上**右键 → 以管理员身份运行**
3. 记事本里点 `文件 → 打开`
4. 地址栏粘贴这个路径，回车：

   ```
   C:\Windows\System32\drivers\etc
   ```

5. 右下角把文件类型改成 `所有文件 (*.*)`，选中 `hosts`，打开

> 找不到「以管理员身份运行」？也可以先把 hosts 复制到桌面，用普通记事本改，改完再复制回原目录（会弹 UAC 确认）。

### 第三步：把内容粘到最后

滚动到文件**最末尾**，另起一行，粘贴下面这段，**把两处 `<你的IP>` 换成你扫到的 IP**：

```
# >>> CF-HUNT BEGIN (managed by save-your-open-design) >>>
<你的IP-1> open-design.ai
<你的IP-2> open-design.ai
<你的IP-1> www.open-design.ai
<你的IP-2> www.open-design.ai
# <<< CF-HUNT END <<<
```

替换后应该长这样（`< >` 尖括号也要去掉）：

```
# >>> CF-HUNT BEGIN (managed by save-your-open-design) >>>
203.0.113.10 open-design.ai
203.0.113.20 open-design.ai
203.0.113.10 www.open-design.ai
203.0.113.20 www.open-design.ai
# <<< CF-HUNT END <<<
```

> 上面 `203.0.113.x` 是示例用的占位地址，**不能直接用**，必须换成你自己扫出来的。

**注意两点：**

- **别删原有的任何一行。** `127.0.0.1 localhost` 那些是系统自带的，删了会出问题。
- **如果里面已经有 `open-design.ai` 的行**，别新增，**直接改那一行的 IP** 就行。否则两条规则会冲突，先出现的那条生效，你新写的等于没用。

### 第四步：保存 + 刷新缓存

`Ctrl+S` 保存。然后按 `Win+R` 输入 `cmd`，执行：

```bash
ipconfig /flushdns
```

重启浏览器，访问试试。

### 还原

把上面那 6 行（含首尾 `#` 标记）整段删掉，再 `ipconfig /flushdns` 即可。

---

## macOS / Linux

路径是 `/etc/hosts`，需要 `sudo`。

```bash
sudo nano /etc/hosts
# 粘贴同样的那 6 行到末尾，Ctrl+O 保存，Ctrl+X 退出
```

刷新缓存：

```bash
# macOS
sudo killall -HUP mDNSResponder

# Linux（systemd）
sudo resolvectl flush-caches

# Linux（没有 systemd 的老发行版）
# 不用刷新，glibc 每次查 /etc/hosts 都是现读
```

macOS 上如果 `.pyz` 被 Gatekeeper 拦，右键 → 打开，或在终端里 `python3 cf-hunt.pyz`。

---

## 程序怎么改 hosts（不会删你的规则）

这是它和一般「一键改 hosts」脚本最大的区别：**先检测，再决定怎么改。**

| 发现什么 | 怎么处理 |
|---|---|
| 已有本工具写的段 | 原地更新，不新增重复条目 |
| 已有其他工具的段（如原项目的 `CLOUDFLARE-PIN`） | 原地改 IP，保留它的标记 |
| 已有手工添加的条目 | 原地改那一行的 IP，保留缩进和注释 |
| 什么都没有 | 在文件末尾新增一段 |

**与这些域名无关的规则一行都不动。** 包括局域网设备映射、广告屏蔽、公司内网域名，全部逐字节保留。

如果发现 `0.0.0.0 open-design.ai` 这类**故意屏蔽**的条目，会先警告再改——因为改它等于解除屏蔽。

`还原` 也只移除本工具自己写的那一段。这部分有 8 个场景的测试，跑 `python test_hosts_tool.py` 可以自己验证。

---

## 原理

Cloudflare 是全球 anycast：官方公布的 15 个 IPv4 段里，**任何一个 IP** 只要 TLS 的 SNI 和 HTTP 的 Host 头对得上，都能正常服务这个域名，证书也完全有效。

但从你家宽带出发，到同一个域名的不同 CF 边缘 IP，**走的国际路由可能完全不同**——有的 30~50% 丢包、一个请求要 3~9 秒，有的 0 丢包、0.8 秒返回。

系统 DNS 只给你「就近」的答案，它不测线路质量。而 hosts 的优先级高于 DNS。

所以：**把域名钉在实测最好的 IP 上，浏览器就绕开了那个坏答案。**

剩下的就是一个纯测量问题：怎么在 5952 个候选里找出你这条线上最干净的那个。

核心原则是**单次探测不算数**：

```
候选池    CF 官方 15 段，每个 /20 取样本点（376 个覆盖全部 /24）
  ↓
TCP 粗筛  能连通的留下
  ↓
HTTPS    真实 TLS + SNI + Host，读 /cdn-cgi/trace 确认机房
  ↓
多采样    每个 IP 串行打 6 次，算丢包率和 p50/p95
```

**只写零丢包的 IP。** 宁可不改，也不把有丢包的塞进去——那会让浏览器随机卡顿，比不配还糟。

---

## 注意事项

**浏览器开了 DoH 会让 hosts 失效。** Chrome / Edge 的「安全 DNS」绕过系统 hosts。配完没效果先去 `设置 → 隐私和安全 → 安全 DNS` 关掉。

**360 / 火绒 / 电脑管家会拦截写 hosts。** 它们的「hosts 文件保护」连管理员权限也拦，表现是程序报「权限不足」。改之前先把安全软件退出，改完再打开。

**ping 不通是正常的。** Cloudflare 边缘 IP 多数不回 ICMP，`ping` 超时不代表不能用，TCP/TLS 不受影响。

**IP 不能复制给别人。** 优选结果强依赖你自己的运营商和地理位置。同城同运营商大概率有效，跨省跨运营商必须重扫。

**路由会变。** 今天最好的 IP 一个月后可能不是。变慢了就重跑一次。

**安全。** 本程序只做两件事：发起 HTTPS 请求测速、读写 hosts 中自己标记的那一段。没有联网上报，没有信息收集，没有远程执行。

---

## 项目结构

```
app.py              交互菜单 + 扫描编排（入口）
hosts_tool.py       跨平台 hosts 读写、备份、刷新 DNS、提权
cf_hunt.py          底层扫描器（pool / screen / probe / verify）
cf_final.py         候选 IP 与 DNS 基线的对比
cf_ab.py            交错 A/B 对照实验
test_hosts_tool.py  hosts 改写安全测试
cf-hunt.spec        PyInstaller 配置
build_pyz.py        打 .pyz 的脚本
```

自己构建：

```bash
# Windows exe
pip install pyinstaller
pyinstaller cf-hunt.spec --noconfirm

# 全平台 .pyz（不需要 PyInstaller）
python build_pyz.py
```

---

## 赞助

如果这个工具帮你省了时间，欢迎请我喝杯咖啡 ☕

<!-- 收款码放在此处。把图片存成 donate/wechat.jpg 后取消下面的注释 -->

<!--
<img src="donate/wechat.jpg" width="220" alt="微信赞赏码">
-->

**说明：** 赞助是自愿支持，不构成购买任何商品或服务，也不附带功能承诺或技术支持。

---

## 致谢

思路来自 **[ft5191306/open-design-ip-optimizer](https://github.com/ft5191306/open-design-ip-optimizer)**——「Cloudflare anycast + 优选 IP 写 hosts」这个想法是它提出的，没有它就没有这个工具。

**原项目的代码一行未改、未分发。** 如果你只想用脚本改 hosts，直接用它的 `cf_pin.py` 也完全够。

候选 IP 池来自 [Cloudflare 官方公布的 IPv4 段](https://www.cloudflare.com/ips/)。

---

## 许可证

[MIT](LICENSE)
