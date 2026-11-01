# save-your-open-design

> 拯救你的 OpenDesign 订阅，让你连通的畅快些，毕竟 OD 的订阅超划算。

一条丢包 30~50% 的国际线路，能让任何订阅都变得毫无价值。这个工具做的事很简单：**给你这条线路找一条干净的路，然后钉住它。**

Windows / macOS / Linux 都能用。纯 Python 标准库，零依赖。

---

## 起因与致敬

本项目受 **[ft5191306/open-design-ip-optimizer](https://github.com/ft5191306/open-design-ip-optimizer)** 启发。

那个项目提出并实现了一个很聪明的思路：

> Cloudflare 是全球 anycast 网络，同一个域名可以从任意一个 Cloudflare 边缘 IP 进入。
> 挑一个对**你本地线路**最快的 IP，写进 `hosts`，就能绕开 DNS 分给你的那条烂路。

这个洞察是对的，也是本项目的全部出发点。

我们在自己的网络环境里按它的流程跑了一遍，结果是 **`合格 0 个`**——不是思路错，是测量方法在那个特定线路条件下失效了（原因见下文）。于是我们保留原理、重写了测量部分，把它做成了带界面的可执行程序。

**原项目的代码一行未改、未分发**，仅作为思路来源在本文档中引用。它的 `cf_pin.py` 有很扎实的工程细节（写入前逐域名校验证书、原子写入、自动备份、失败回退），如果你只想用 Python 脚本改 hosts，我们仍然推荐直接用它的。

---

## 原理：为什么这招有效

### 1. Cloudflare 是 anycast

`open-design.ai` 解析出来的 IP **不是唯一的**。Cloudflare 官方公布 15 个 IPv4 段，其中**任何一个** IP，只要 TLS 握手的 SNI 和 HTTP 请求的 Host 头是对的，都能正常服务这个域名，证书也完全有效。

这不是漏洞，是 anycast 的设计：一个 IP 在全球几百个机房都有实例，你在哪里就连到最近的那个。

### 2. 但"能服务"不等于"快"

从你家宽带出发，到不同 Cloudflare 边缘 IP 的**国际路由可能完全不同**：

- 有的 IP 走拥塞线路 → 丢包 30~50%，一个 HTTPS 请求要 3~9 秒
- 有的 IP 走干净线路 → 0 丢包，同样的请求 0.8~0.9 秒

同一个运营商、同一个时刻、同一个域名，差别就在选哪个 IP。

### 3. 系统 DNS 不知道这件事

DNS 只负责给你一个「就近」的答案，它不测你的线路质量，也不知道哪条路由此刻干净。

### 4. hosts 优先级高于 DNS

所以把域名钉在实测最好的 IP 上，浏览器就绕开了那个坏答案。

**问题从「哪个域名能通」变成了「我这条线上哪个 IP 最干净」——这是个纯测量问题。**

---

## 和原项目的区别

原项目的问题是**测量方法**，不是原理。

| | 原项目 `cf_pin.py` | 本项目 |
|---|---|---|
| 候选池 | 256 个 IP | **5952 个**（CF 官方 15 段，每 /24 取 1） |
| 筛选方式 | 直接 HTTPS 探测 | **三层**：TCP → HTTPS → 串行多采样 |
| 并发 | 60 路 | **6 路** |
| 超时 | 1.5 秒 | **5~6 秒** |
| 判定依据 | 单次 p95 | **丢包率 + p50/p95**（多次采样） |
| 对照实验 | 无 | **交错 A/B**，排除瞬时抖动 |
| 形态 | Python 脚本 | **可执行程序 + 交互菜单** |

### 原项目在我们这条线上为什么扫不出东西

三个原因叠在一起：

1. **超时太紧。** `DOMAIN_TIMEOUT = 1.5s`，而这台机器到 Cloudflare 的 TCP RTT 约 200ms，一次完整 HTTPS 至少 3 个往返（TCP + TLS + HTTP）≈ 700ms。只要有一次重传就超 1.5 秒，直接被记成 999ms 惩罚值。
2. **并发太高。** 12 个域名探测 worker × 5 个域名 = 60 路并发 TLS，把家用宽带的上行打满，自己制造了拥塞。
3. **结果：全员超时。** 我们的两次实测都是 `合格 0 个`，所有候选的 p95 都顶到 999ms 惩罚值——那不是"IP 都坏"，是测量方法把自己打崩了。

---

## 我们怎么做的

四层筛选，层层收窄。核心原则是：**单次探测不能作为决策依据**，只有多次采样算出的丢包率才算数。

```
pool    生成候选池        CF 官方 15 段，每 /24 取 1 个，随机采样
  ↓
screen  TCP 粗筛          只保留能建立 TCP 连接的
  ↓
probe   HTTPS 复筛        真实 TLS + SNI + Host，读 /cdn-cgi/trace 拿机房
  ↓
verify  串行终选          每个 IP 打 N 次，算丢包率 + p50/p95
  ↓
ab      交错对照（可选）   同一时间窗轮流打，证明是路由差异而非瞬时抖动
```

### 关键设计

- **必须做真实 HTTPS 探测。** TCP RTT 快不代表能跑 HTTPS——我们实测过香港机房的 IP TCP 只要 143ms，但 TLS 握手全失败。只测延迟会选错。
- **必须串行多次采样。** 第一次探测里一堆 IP 看着都只要 1.0~1.3 秒，串行打 8 次才发现其中 11 个有 12.5%~50% 的丢包。单次数据会骗人。
- **只写零丢包的 IP。** 宁可什么都不写，也不要把有丢包的 IP 塞进 hosts——那会让浏览器随机卡顿，比不配还糟。

---

## 实测数据

以下全部是真实测量结果，同一天、同一台机器、同一条宽带。

### 写入 hosts 前后对比（每个域名 6 次采样）

| 域名 | 默认 DNS 路径 | 优选 IP 后 |
|---|---|---|
| open-design.ai | **33.3% 丢包**，p50 3031ms | **0% 丢包**，p50 813ms |
| www.open-design.ai | 50.0% 丢包，p50 3090ms | 0% 丢包，p50 852ms |
| amr-link.open-design.ai | 50.0% 丢包，p50 5024ms | 0% 丢包，p50 854ms |
| cloudflare.com | 0% 丢包，p50 1236ms | 0% 丢包，p50 849ms |
| www.cloudflare.com | 0% 丢包，p50 1222ms | 0% 丢包，p50 845ms |

### 交错 A/B 对照（证明不是运气）

同一时间窗口内轮流请求两个 IP，各 15 轮：

| | 104.18.55.1 | 104.24.156.1 |
|---|---|---|
| 成功 | **15/15** | 9/15 |
| 丢包 | **0.0%** | 40.0% |
| p50 | **943ms** | 2903ms |
| p95 | **1249ms** | 5109ms |

两个 IP 在同一个时间窗里稳定分化 → 是路由差异，不是链路抖动。

### 一个有意思的发现：黄金前缀

把 `104.18.0.0/16` 全段 256 个 IP 扫了一遍，前 16 名**正好是 `104.18.48.1` ~ `104.18.63.1` 连续一段**，耗时 824~999ms，其余段全在 1060ms 以上。

对这 16 个 IP 各打 8 次：**15 个 0 丢包**，128 次请求只失败 1 次。

也就是说，`104.18.48.0/20` 这个前缀在这条宽带上走的是一条明显更干净的国际路由。**这个结论只对我们这条线路成立，换运营商/换省份必须重扫。**

### 最终效果

写入 hosts 后，实际访问首页：

- 首页 **242,147 字节完整拉到**，HTTP 200
- 连续 10 次请求：**10/10 成功**，中位数 1.37 秒，波动范围 1.30~1.51 秒
- 写之前：33~50% 的请求直接失败

---

## 改 hosts 之前，先检测

这是本工具和一般「一键改 hosts」脚本最重要的区别：**它不会盲写，也不会删你的规则。**

每次写入前先扫描 hosts，分四种情况处理：

| 发现的情况 | 处理方式 |
|---|---|
| **已有本工具写的托管段** | 原地更新那一段（换 IP），不新增重复条目 |
| **已有原项目 `cf_pin.py` 写的段**（标记是 `CLOUDFLARE-PIN`） | 原地改段内的 IP，**保留它的标记** |
| **已有手工添加的裸条目**（如 `104.x.x.x open-design.ai`） | 原地改那一行的 IP，**保留缩进和行尾注释** |
| **什么都没有** | 在文件末尾新增托管段 |

**无论哪种情况，与这些域名无关的规则一行都不动。** 包括：`127.0.0.1 localhost`、局域网设备映射、广告屏蔽条目、公司内网域名——全部逐字节保留。

### 为什么必须先检测

不检测会有两个真实后果：

1. **重复条目冲突。** 如果 hosts 里已经有一条 `104.26.5.1 open-design.ai`，你再追加一条 `104.18.57.1 open-design.ai`，系统会用**先匹配到的**那条——新写的规则等于没生效。
2. **覆盖别人的成果。** 如果之前用原项目的 `cf_pin.py` 配过，它有自己的一套标记。识别不到就会各写一段，两条规则打架。

### 会给出警告的情况

如果 hosts 里的是 `0.0.0.0 open-design.ai` 这类**故意屏蔽**的条目（指向非 Cloudflare 段），程序会先警告：

> 第 2 行的手工条目指向 0.0.0.0（非 Cloudflare 段），看起来是故意屏蔽；本工具会改写它，如需保留请先备份。

因为改写它等于解除屏蔽——这可能是你不想要的，所以先提醒。

### 还原也不动别人

`还原` 只移除**本工具自己写的那一段**。其他工具写的、你手工加的规则，全部原样保留。

---

## 怎么用

### 方式一：下载可执行程序（推荐给普通用户）

从 [Releases](../../releases) 下载对应平台的文件：

| 平台 | 文件 | 说明 |
|---|---|---|
| Windows | `cf-hunt-windows.exe` | 双击运行，无需 Python |
| 全平台 | `cf-hunt.pyz` | 需要已装 Python 3.8+ |

打开后是一个菜单：

```
  1. 扫描优选 IP 并写入 hosts（推荐）
  2. 只扫描，不修改系统
  3. 查看当前优选状态
  4. 还原 hosts（撤销本工具的改动）
  5. 手动修改说明（不想让程序动系统时用）
  0. 退出
```

选 `1`，等 2~3 分钟，程序会自己扫描、挑零丢包的 IP、备份原 hosts、写入、刷新 DNS。

**程序会自己申请管理员权限。** 如果 UAC 弹窗被拒绝、或者写入被安全软件拦截，程序**不会硬来**，而是直接打印现成的配置块和分步操作说明，让你自己复制粘贴。

### 方式二：从源码跑

```bash
# 交互菜单
python app.py

# 或者用子命令
python app.py scan      # 只扫描
python app.py apply     # 扫描并写入
python app.py status    # 查看状态
python app.py revert    # 还原
python app.py manual    # 打印手动说明
```

### 方式三：只用底层扫描器（改域名、改参数）

```bash
# 生成候选池（默认全部 5952 个，可 --limit 限制）
python cf_hunt.py pool --limit 500

# TCP 粗筛
python cf_hunt.py screen --concurrency 24 --timeout 1.5

# HTTPS 复筛
python cf_hunt.py probe --top 60 --concurrency 6 --timeout 5

# 串行终选（每 IP 打 8 次）
python cf_hunt.py verify --top 12 --n 8 --gap 0.3

# 交错 A/B 对照
python cf_ab.py 1.2.3.4 5.6.7.8 --n 15
```

想扫自己的域名：

```bash
python cf_hunt.py probe --domains "your-site.com,www.your-site.com"
python app.py apply --domains "your-site.com,www.your-site.com"
```

> 前提：该域名必须由 Cloudflare 托管。否则任意 CF 边缘 IP 都不会为它提供有效证书。

---

## 跨平台说明

扫描逻辑三平台完全相同，差异只在这三处：

| | Windows | macOS | Linux |
|---|---|---|---|
| hosts 路径 | `C:\Windows\System32\drivers\etc\hosts` | `/etc/hosts` | `/etc/hosts` |
| 刷新 DNS | `ipconfig /flushdns` | `sudo killall -HUP mDNSResponder` | `resolvectl flush-caches` / `nscd` / 无需刷新 |
| 提权 | UAC 弹窗，或右键「以管理员身份运行」 | `sudo` | `sudo` |

程序会自动识别平台并选对路径和命令，不需要你配置。

### Windows 用户注意

如果双击后提示权限不足，**右键程序 → 以管理员身份运行**。

程序也会自己尝试弹 UAC 提权，但某些环境（组策略限制、安全软件拦截）下会失败，这时走手动路径。

### Linux 用户注意

```bash
sudo python3 app.py
```

不想让程序改系统？用只扫描模式，然后按 `python app.py manual` 打印的内容自己改 `/etc/hosts`。

没有 systemd 的老发行版（glibc 直接读 `/etc/hosts`）刷新缓存这步可以跳过。

---

## 手动修改方案

如果程序无法写入（权限、杀软、公司电脑策略），`app.py manual` 会打印这样的内容：

```
# >>> CF-HUNT BEGIN (managed by save-your-open-design) >>>
104.18.57.1 open-design.ai
104.18.56.1 open-design.ai
104.18.57.1 www.open-design.ai
104.18.56.1 www.open-design.ai
# <<< CF-HUNT END <<<
```

把整段（含首尾标记）追加到 hosts 文件末尾即可。标记的作用是让程序以后能准确找到并只动这一段，不碰你原有的内容。

**还原方法**：把这一整段删掉。

---

## 注意事项

### 浏览器开了 DoH 会让 hosts 失效

Chrome / Edge 的「安全 DNS」会绕过系统 hosts 直接走加密 DNS。如果配完没效果，先去 `设置 → 隐私和安全 → 安全 DNS` 关掉。

### ICMP 不通是正常的

Cloudflare 边缘 IP 多数不回 ping。`ping` 超时不代表不能用，TCP/TLS 不受影响。

### IP 不能复制给别人

优选结果强依赖**你自己的运营商和地理位置**。同一份 IP 表在同城同运营商的人那里大概率还有效，跨省跨运营商就必须重扫。

### 路由会变

国际路由会变，今天最好的 IP 一个月后可能不是最好的。觉得变慢了就重跑一次。

### 安全问题

本程序只做两件事：发起 HTTPS 请求测速、读写 hosts 中自己标记的那一段。

代码里没有任何外发行为——不联网上报数据、不收集信息、不执行远程下发的代码。全部逻辑可审计，只用到 `socket` / `ssl` / `subprocess` 这几个标准库模块。

---

## 项目结构

```
save-your-open-design/
├── app.py           交互菜单 + 扫描编排（入口）
├── hosts_tool.py    跨平台 hosts 读写、备份、刷新 DNS、提权
├── cf_hunt.py       底层扫描器（pool / screen / probe / verify）
├── cf_final.py      候选 IP 与 DNS 基线的同口径对比
├── cf_ab.py         交错 A/B 对照实验
├── LICENSE          MIT
└── .github/
    └── FUNDING.yml  赞助按钮配置
```

---

## 自己构建

### Windows exe

```bash
pip install pyinstaller
pyinstaller --onefile --name cf-hunt-windows --console app.py
```

产物在 `dist/cf-hunt-windows.exe`，单文件，目标机器不需要装 Python。

### 全平台 `.pyz`（不需要 PyInstaller）

```bash
python -m zipapp . -m "app:main" -o cf-hunt.pyz -p "/usr/bin/env python3"
```

产物约几十 KB，任何装了 Python 3.8+ 的系统都能跑。

### 说明

PyInstaller **不能交叉编译**：Windows 上只能打出 Windows 的 exe，要 Linux/macOS 的二进制得在对应系统上各打一次。

所以本项目优先推荐 `.pyz`——一份文件全平台通用，代价是用户需要有 Python 环境。

---

## 环境

- Python 3.8+
- 仅标准库：`socket` / `ssl` / `ipaddress` / `statistics` / `subprocess` / `zipapp`
- 无第三方运行时依赖（PyInstaller 只在构建时用）

---

## 许可证与致谢

本项目以 **MIT** 许可证发布，详见 [LICENSE](LICENSE)。

**致谢：**

- **[ft5191306/open-design-ip-optimizer](https://github.com/ft5191306/open-design-ip-optimizer)** — 核心思路的来源。没有它提出的「Cloudflare anycast + 优选 IP 写 hosts」，就没有这个工具。如果你的需求只是「用脚本一键改 hosts」，直接用它的 `cf_pin.py` 更好，工程细节比我们写得更扎实。
- **[Cloudflare](https://www.cloudflare.com/ips/)** — 官方公布的 IPv4 段列表，是本项目候选池的全部来源。
