# 排查手册

按「症状」查原因。每条都写清**怎么确认**，不要凭感觉猜。

---

## 一、`打不开进程 xxx，请用管理员权限运行`

**原因**：`OpenProcess(PROCESS_VM_READ)` 被拒。读别的进程内存必须提权。

**确认**：

```powershell
# 输出若是 False，就是没有管理员权限
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

**处置**：右键终端 → 以管理员身份运行，再执行脚本。

---

## 二、`没找到运行中的 Weixin.exe`

**原因**：微信没开，或进程名不是 `Weixin.exe`。

**确认**：

```powershell
Get-Process | Where-Object { $_.ProcessName -match "Weixin|WeChat" } | Select-Object ProcessName, Id
```

**注意**：

- 微信 **4.x** 主进程叫 `Weixin.exe`
- 微信 **3.x** 叫 `WeChat.exe`（本工具针对 4.x）
- `WeChatAppEx.exe` 是小程序宿主，**不是**主进程，别选它

**处置**：登录微信并保持运行。

---

## 三、`没有命中特征结构`（最常见）

三种可能，按顺序排除：

### 3.1 微信已经跑很久了

**确认**：看微信进程启动时间。

```powershell
Get-Process Weixin | Select-Object Id, StartTime
```

如果启动时间是几小时甚至几天前 → 基本就是这个原因。内部结构早已释放。

**处置**：

```bash
python scripts/extract_key.py --db "<目录>" --restart
```

`--restart` 会杀掉微信再拉起。微信 4.x 通常**自动恢复登录态**，不用重新扫码。
但如果你的账号设了每次登录都要手机确认，就得手动确认一下。

### 3.2 微信版本升级，特征变了

**确认**：先确认 3.1 已排除（刚重启就扫仍然 0 命中），且确实有管理员权限。

**处置**：需要重新定位特征。思路：

1. 用调试器（如 x64dbg）attach 到刚启动的微信
2. 观察它在打开 `.db` 文件后，堆上分配的结构
3. 找到「指向 32 字节缓冲区」的指针位置，记录该位置附近的固定字节
4. 替换 `extract_key.py` 顶部的 `SIG_TAIL` 与 `SIG_PREFIX`

⚠️ **不要**为了省事去用调试器 hook 函数或注入 DLL。微信有反调试机制，
触发后可能导致**账号风险**（封号）。读内存是相对温和的方式，hook 不是。

### 3.3 扫错了进程

**确认**：脚本默认选内存占用最大的那个。多开微信时这个策略可能选错。

**处置**：手动指定。

```powershell
Get-Process Weixin | Select-Object Id, @{n="内存MB";e={[math]::Round($_.WorkingSet64/1MB)}}
```

挑内存最大的那个（通常是当前登录账号的主进程），用 `--pid <ID>` 指定。

---

## 四、`N 个候选 × M 种变换 = ... 次尝试，均未通过校验`

**好消息**：特征定位成功了，候选确实拿到了。
**坏消息**：候选里没有真正的 key，或者缺了 XOR 这一步。

### 4.1 没给 `--xor-key`

微信 4.x 通常需要 `final = raw XOR xor_key`。没给的话脚本只验证 `raw` 本身，
当然过不了。

**处置**：找到你这版微信的 XOR 常量。来源：

- 从 `Weixin.dll` 静态分析（社区工具 `LifeArchiveProject/WeChatDataAnalysis` 的 `scan.py` 做这个）
- 或者用 `--dump` 导出所有候选，拿去别处交叉验证

### 4.2 XOR 常量不对

不同小版本可能不同。确认你拿到的常量对应的是**当前安装的版本号**。

查版本：

```powershell
(Get-Item "C:\Program Files\Tencent\Weixin\Weixin.exe").VersionInfo.FileVersion
```

### 4.3 数据目录指向了别的账号

多账号时最容易犯。每个 `db_storage` 对应一个 wxid，**只有当前登录的那个能用当前内存里的 key**。

**确认**：

```powershell
Get-ChildItem "$env:USERPROFILE\Documents\xwechat_files" -Directory | Select-Object Name, LastWriteTime
```

挑 `LastWriteTime` 最新的那个（正在用的账号）。

---

## 五、`校验用数据库 N 个` 但全部 `[不匹配]`

**原因**：key 是真的，但 db 文件不是这个 key 的。

**常见场景**：

1. 数据目录指向了另一个微信账号
2. key 是旧的（微信重装/注销重登后密钥会变）
3. 文件是三方的（其他软件也用 SQLCipher，但口令不同）

**确认**：换一个 db 再试；确认目录对应的 wxid 与当前登录账号一致。

**判断 key 是否过期**：如果同一把 key 昨天还能用、今天突然不行了，
基本就是微信重登换了密钥。重新提取。

---

## 六、`页大小不是 4096` / 文件太小

**原因**：目标不是 SQLCipher 加密的微信数据库，或者文件损坏。

**确认**：

```powershell
# 看前 16 字节。SQLCipher 加密库的开头是随机字节，不是 "SQLite format 3"
$b = [System.IO.File]::ReadAllBytes("<文件>")[0..15]
($b | ForEach-Object { $_.ToString("x2") }) -join ""
```

如果开头正好是 `53514c69746520666f726d6174203300`（即 "SQLite format 3"），
说明这个库**根本没加密**，不需要 key。

---

## 七、性能参考

| 操作 | 耗时 |
|---|---|
| 校验一个 db（单次 PBKDF2） | 约 40~90 毫秒 |
| 扫完整微信内存（约 1GB） | 约 30~90 秒 |
| 20 个候选 × 2 种变换 × 20 个库 | 约 1 分钟内 |

如果校验慢得离谱（每个库好几秒），检查是不是在跑多个 Python 进程抢 CPU。

---

## 八、安全提醒

- 排查过程中**不要**把真实 key 贴到公开的 issue、论坛、聊天群里
- 日志文件里如果带了 key，用完记得删
- 这个 key 能解开该账号全部本地聊天记录，泄漏后果等同于交出聊天记录原件
