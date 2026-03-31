# SelectInfo

## Update Note

- `web_scan` 已拆分为两个独立模块:
  - `web_fingerprint`: 只做 nmap Web 指纹识别
  - `directory_scan`: 只对已识别的 Web URL 跑 `dirsearch`
- `main.py` 和批量流程现在会分别询问是否执行这两个步骤

一个面向信息收集场景的命令行工具，把下面这条链路串起来：

子域名收集 -> 泛解析过滤 -> DNS 校验 -> 端口扫描 -> Web 指纹 -> 目录扫描 -> JSON 输出

当前更适合内部使用和持续开发，不是完整发行版。

## 它能做什么

- 调用 `Subfinder`、`OneForAll` 收集子域名
- 自动去重并做 DNS 校验
- 检测泛解析并过滤无效结果
- 调用本地 `nmap` 做端口扫描
- 对开放端口做 Web 指纹识别
- 对识别出的 Web URL 调用 `dirsearch` 做目录扫描
- 输出单目标结果和批量汇总结果
- 提供交互入口、CLI 和 MCP 服务统一管理工具配置

## 快速开始

1. 安装 Python 依赖

```bash
python -m pip install -r requirements.txt
```

2. 准备外部工具

- `nmap`
- `Subfinder`
- `OneForAll`
- `dirsearch`（可选，仅用于目录扫描）

3. 在项目根目录运行

```bash
python main.py
```

如果你只想单独管理工具配置，也可以直接用 CLI：

```bash
python cli.py -show
```

### Ubuntu/Debian 直接部署

推荐直接运行项目内置安装脚本：

```bash
bash scripts/install_linux.sh
```

这个脚本会一次性完成：

- 安装 `nmap`、`python3-pip`、`python3-dev`、`python3-testresources` 等系统依赖
- 安装根项目依赖、`tools/oneforall/requirements.txt`、`tools/dirsearch/requirements.txt`
- 修复 `tools/subfinder/subfinder` 和 `OneForAll` 内置 `massdns` Linux 二进制的执行权限
- 运行 `python cli.py -check` 做安装后自检

Linux 部署时请注意：

- `config/local_settings.json` 是本机本地覆盖配置，不要直接从 Windows 机器复制
- 如果误复制了旧配置，删除该文件或重新用 CLI 设置路径即可
- 当前 Linux 默认 `nmap` 参数为 `-sS -Pn -T4`，适合 `root/capabilities` 运行；普通用户建议改成 `-sT -Pn -T4`

## 工具准备

### nmap

必须安装。

- Windows:
  - 确保 `nmap.exe` 在系统 `PATH` 中
  - 或在工具配置里手动指定路径
- Linux:

```bash
sudo apt install nmap
```

默认端口扫描参数：

- Windows: `-sT -Pn -T4`
- Linux / macOS: `-sS -Pn -T4`

说明：

- Linux 默认 `-sS` 依赖 `root` 或 `CAP_NET_RAW` / `CAP_NET_ADMIN`
- 如果你在 Linux 上使用普通用户运行，可以执行 `python cli.py -nmap "-sT -Pn -T4"`

### Subfinder

- 项目地址: `https://github.com/projectdiscovery/subfinder`
- 默认位置:
  - Windows: `tools/subfinder/subfinder.exe`
  - Linux/macOS: `tools/subfinder/subfinder`
- Linux 首次部署后如果可执行权限丢失，执行：

```bash
chmod +x tools/subfinder/subfinder
```

### OneForAll

- 项目地址: `https://github.com/shmilylty/OneForAll`
- 默认位置: `tools/oneforall/`
- Linux 直接安装 `tools/oneforall/requirements.txt` 即可，已兼容 Windows 专属依赖
- 如果当前 Python 缺少标准库 `sqlite3`，项目会优先使用 `pysqlite3-binary` 作为兼容替代

### dirsearch

- 项目地址: `https://github.com/maurosoria/dirsearch`
- 默认位置: `tools/dirsearch/dirsearch.py`
- 当前只支持手动配置路径，不支持自动下载

## 使用方式

启动后会先做工具自检，然后进入交互流程。

支持三种入口：

- `python main.py`
  - 交互式扫描和工具配置
- `python cli.py ...`
  - 适合快速修改工具路径和参数
- `python mcp_server.py`
  - 适合 AI 通过 MCP 协议管理工具配置
  - 根目录 `requirements.txt` 已包含 `mcp` 依赖

### CLI 示例

```bash
python cli.py -show
python cli.py -check
python cli.py -nmap "-sS -Pn"
python cli.py -oneforall "--takeover False --port medium"
python cli.py -subfinder "-recursive"
python cli.py -dirsearch "--exclude-status 404"
python cli.py -dirsearch-path "D:\Tools\dirsearch\dirsearch.py"
python cli.py -reset dirsearch
```

Linux 常见配置示例：

```bash
python cli.py -subfinder-path "./tools/subfinder/subfinder"
python cli.py -dirsearch-path "./tools/dirsearch/dirsearch.py"
python cli.py -nmap "-sS -Pn -T4"
```

## 输出结果

结果默认写到 `results/`。

你会看到两类文件：

- 单个目标结果: `<domain>_YYYYMMDD_HHMMSS.json`
- 批量汇总结果: `batch_summary_YYYYMMDD_HHMMSS.json`

单个结果里主要包含：

- `target`
- `statistics`
- `subdomains`
- `port_scan`
- `web_scan`

其中：

- `port_scan.hosts` 是 `IP -> 开放端口列表`
- `web_scan.targets` 是识别出的 Web 目标
- `web_scan.targets[*].dirsearch.findings` 是目录扫描发现

## Web 扫描链路

Web 扫描是可选步骤，只会在端口扫描之后执行。

处理顺序：

1. `nmap` 先发现开放端口
2. 再对开放端口做强指纹识别
3. 只对识别为 Web 的目标生成 URL
4. 最后对这些 URL 运行 `dirsearch`

当前 Web 识别依赖：

- `-Pn`
- `-sV`
- `--version-all`
- `--script http-title,http-server-header,ssl-cert`

Web 目标始终使用子域名 URL，而不是裸 IP。

## MCP 服务

启动方式：

```bash
python mcp_server.py
```

服务名：`selectinfo-tools`

支持的配置能力包括：

- 列出工具
- 获取工具状态和参数
- 设置工具路径
- 修改工具参数
- 重置工具参数
- 执行工具自检
- 导出配置快照

## 测试

运行全部测试：

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

也可以直接在 `tests/` 目录下执行单个测试文件，例如：

```bash
python .\test_web_fingerprint_scanner.py
```

Ubuntu/Debian 部署后的建议验证顺序：

```bash
python cli.py -check
python cli.py -show
python -m unittest discover -s tests -p "test_*.py" -v
python main.py
python mcp_server.py
```

## 常见问题

### 提示工具不可用

先跑自检：

```bash
python tools/self_check.py
```

确认是：

- 未安装
- 已安装但不可执行
- 路径配置错误

### `nmap` 检测失败

确认下面任意一种成立：

- 终端执行 `nmap --version` 能成功
- 已通过工具配置或 CLI 设置 `nmap` 路径

### `dirsearch` 不可用

当前必须手动配置路径，例如：

```bash
python cli.py -dirsearch-path "D:\Tools\dirsearch\dirsearch.py"
```

Linux 上通常是：

```bash
python cli.py -dirsearch-path "./tools/dirsearch/dirsearch.py"
```

如果 `dirsearch` 缺失，`web_scan` 仍会做 nmap 指纹识别，但目录扫描会标记为 `skipped_unavailable`。

### 复制了 Windows 的 `config/local_settings.json`

这个文件是主机本地配置，建议不要跨机器复制。

如果 Linux 上误带了 Windows 路径配置，可以任选一种处理方式：

- 删除 `config/local_settings.json`，让项目回到默认探测逻辑
- 用 CLI 重新设置本机路径，例如 `python cli.py -subfinder-path "./tools/subfinder/subfinder"`

### 中文乱码

源码和 README 都使用 UTF-8。如果终端仍乱码，通常是终端编码问题。Windows PowerShell 建议使用 UTF-8 环境运行。
