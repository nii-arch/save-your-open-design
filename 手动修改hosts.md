# 手动修改 hosts 指南

不用任何程序，纯手工操作。只需要**记事本**和**一个 IP**。

---

## 一、先拿到 IP

优选 IP 必须现扫，不能抄别人的——路由按运营商和地区分，抄来的大概率无效。

```bash
python app.py scan
```

输出长这样（IP 只是示范，你扫出来的肯定不一样）：

```
    IP              机房          成功      丢包      p50      p95
    203.0.113.10    SJC      6/6      0.0%    761ms    788ms
    203.0.113.20    SJC      6/6      0.0%    771ms    815ms
    203.0.113.77    LAX      3/6     50.0%   3150ms   7361ms
```

**只挑「丢包」是 `0.0%` 的行。** 有丢包的别用，会让浏览器随机卡顿。

一般取 2 个，写进 hosts 后系统会自动用第一个，第一个不通时切第二个。

---

## 二、Windows：用记事本编辑

### 关键：记事本必须以管理员身份运行

用普通记事本打开会提示「拒绝访问」，存不进去。

**做法一（推荐）**

1. 按 `Win` 键，输入 `notepad`（或 `记事本`）
2. 在搜索结果上**右键 → 以管理员身份运行**
3. 弹出的 UAC 窗口点「是」
4. 记事本里点 `文件 → 打开`
5. 在文件名框里粘贴：

   ```
   C:\Windows\System32\drivers\etc\hosts
   ```

   回车
6. 如果看不到文件：把右下角的文件类型从 `文本文档 (*.txt)` 改成 `所有文件 (*.*)`

**做法二（找不到右键菜单时）**

1. 普通记事本打开 `C:\Windows\System32\drivers\etc\hosts`（只读也行）
2. `文件 → 另存为`，存到桌面，文件名 `hosts`
3. 改完保存
4. 把桌面上的 `hosts` 复制回 `C:\Windows\System32\drivers\etc\`
5. 覆盖时点「继续」并同意 UAC

> **不要用 Word、写字板、WPS。** 它们会加隐藏格式、改编码、加 `.txt` 后缀，直接把 hosts 弄坏。

### 粘贴什么

滚动到文件**最末尾**，另起一行，粘贴这段，**把 `<你的IP-1>` 和 `<你的IP-2>` 换成你扫到的 IP**：

```
# >>> CF-HUNT BEGIN (managed by save-your-open-design) >>>
<你的IP-1> open-design.ai
<你的IP-2> open-design.ai
<你的IP-1> www.open-design.ai
<你的IP-2> www.open-design.ai
<你的IP-1> amr-link.open-design.ai
<你的IP-2> amr-link.open-design.ai
# <<< CF-HUNT END <<<
```

最后两行是**客户端 API**（`amr-link`），漏了的话网页会变快、但客户端请求还是慢。

替换后应该长这样（**尖括号也要去掉**）：

```
# >>> CF-HUNT BEGIN (managed by save-your-open-design) >>>
203.0.113.10 open-design.ai
203.0.113.20 open-design.ai
203.0.113.10 www.open-design.ai
203.0.113.20 www.open-design.ai
203.0.113.10 amr-link.open-design.ai
203.0.113.20 amr-link.open-design.ai
# <<< CF-HUNT END <<<
```

> `203.0.113.x` 只是占位示例，**不能直接用**。必须换成你自己扫出来的 IP。

### 两条铁律

**1. 别删原有的任何一行**

你的 hosts 里通常已经有这些，全部保留：

```
127.0.0.1       localhost
::1             localhost
```

删了会导致部分程序变慢或异常。

**2. 已经有 open-design.ai 的行，改它，别新增**

先看看文件里有没有类似这样的行：

```
203.0.113.99  open-design.ai
```

- **有**：把 `203.0.113.99` 改成你扫到的新 IP。**不要**在末尾再追加一段，否则两条规则冲突——系统用先匹配到的那条，你新写的等于没生效。
- **没有**：才按上面那样在末尾追加。

### 保存并刷新

`Ctrl+S` 保存。若提示「是否以管理员身份保存」，点「是」。

然后按 `Win+R`，输入 `cmd`，回车，执行：

```bash
ipconfig /flushdns
```

重启浏览器，访问 `open-design.ai` 试试。

---

## 三、macOS / Linux

```bash
sudo nano /etc/hosts
```

粘贴同样的那 8 行到末尾。`Ctrl+O` 保存，回车确认，`Ctrl+X` 退出。

刷新缓存：

```bash
# macOS
sudo killall -HUP mDNSResponder

# Linux（systemd 系：Ubuntu / Debian / Fedora / Arch 等）
sudo resolvectl flush-caches

# Linux（装了 nscd）
sudo systemctl restart nscd

# Linux（都没有的老发行版）
# 什么都不用做，glibc 每次查 /etc/hosts 都是现读
```

---

## 四、怎么验证生效了

改之前先记下当前解析到的 IP：

```bash
nslookup open-design.ai
```

改完再跑一次，应该显示你写进去的 IP。

Windows 上也可以：

```bash
ping open-design.ai
```

**注意：`ping` 超时不代表失败。** Cloudflare 边缘 IP 多数不回 ICMP 包，这是正常的，浏览器走 TCP/TLS 不受影响。

最直接的验证：打开浏览器访问，看是否变快。

---

## 五、怎么还原

用记事本（还是要管理员权限）打开 hosts，把上面那 8 行**整段删掉**——从 `# >>> CF-HUNT BEGIN` 到 `# <<< CF-HUNT END` 全部删除。

然后：

```bash
ipconfig /flushdns
```

---

## 六、配了没效果？按顺序查

**1. 浏览器开了安全 DNS（最常见）**

Chrome / Edge / Brave 的「安全 DNS / DoH」会**直接绕过 hosts**。

- Chrome：`设置 → 隐私和安全 → 安全 → 使用安全 DNS` → 关掉
- Edge：`设置 → 隐私、搜索和服务 → 安全性 → 使用安全 DNS` → 关掉

**2. hosts 没真的存进去**

重新用管理员记事本打开，确认那几行还在。保存失败的话会悄悄恢复到原样。

**3. 写错格式**

- 每行是 `IP 域名`，中间用**空格或 Tab**隔开，不是逗号
- 不要有中文标点
- 编码用 ANSI 或 UTF-8（无 BOM），别用 UTF-16

**4. IP 本身不行了**

路由会变。重新跑 `python app.py scan`，换一个 0 丢包的。

**5. 还有代理在跑**

如果开着 Clash / V2Ray 之类的 TUN 模式，流量先被它们接管，hosts 可能不起作用。先关掉再测。

**6. hosts 存不进去（提示拒绝访问，即使是管理员）**

360 安全卫士、火绒、腾讯电脑管家的「hosts 文件保护」会拦截写入，权限再高也拦。

先把安全软件退出（或临时关闭「hosts 文件保护」），改完再打开。

---

## 七、安全提醒

- 改 hosts 需要管理员权限，这是正常的，没有别的办法
- hosts 只影响**域名解析**，不代理流量、不改变路由，风险很低
- 出问题随时删掉那几行就能恢复，不会损坏系统
- 改之前建议复制一份备份：`copy hosts hosts.bak`
