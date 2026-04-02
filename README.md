# SelectInfo

面向信息收集场景的命令行工具，把下面这条链路串起来：

`子域名收集 -> 泛解析过滤 -> DNS 校验 -> 端口扫描 -> Web 指纹 -> 目录扫描 -> JSON 输出`

**当前状态**

- 交互式入口会先一次性确认所有扫描选项，再开始长任务。
- 根目录 `requirements.txt` 是统一 Python 安装入口，覆盖主项目、MCP、内置 `OneForAll` 和 `dirsearch`。
- 单次扫描结果新增 `tool_runs` 字段，用来记录每个子域名工具的执行状态、返回码和计数。
- `runtime/` 仅存放运行时状态，不再作为需要跟踪的源码内容。

**目录**

- [快速开始](#quick-start)
- [安装与部署](#install)
- [工具准备](#tool-setup)
- [使用方式](#usage)
- [输出结果](#output)
- [扫描流程说明](#scan-flow)
- [测试](#testing)
- [常见问题](#faq)
- [贡献指南](#contributing)
- [免责声明](#responsible-use)
- [许可证](#license)

<a id="quick-start"></a>
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
python scan.py example.com --port-scan --web-fingerprint
python scan.py example.com --tools subfinder --nmap-args "-sV -Pn"
python main.py
```

如果你只想管理工具配置，也可以直接运行：

```bash
python tools/self_check.py
# edit config/local_settings.json
```

<a id="install"></a>
## 安装与部署

默认推荐在项目根目录执行：

```bash
python -m pip install -r requirements.txt
```

### Ubuntu / Debian

推荐直接运行内置安装脚本：

```bash
bash scripts/install_linux.sh
```

这个脚本会一次性完成：

- 安装 `nmap`、`python3-pip`、`python3-dev` 等系统依赖
- 安装根目录 `requirements.txt`
- 修复 `tools/subfinder/subfinder` 和 `tools/oneforall/thirdparty/massdns` 的执行权限
- 运行 `python tools/self_check.py` 做安装后自检

Linux 部署时请注意：

- `config/local_settings.json` 是主机本地覆盖配置，不要直接从别的机器复制
- `runtime/` 是运行时目录，缺失时会自动再生
- Linux 默认 `nmap` 参数是 `-sS -Pn -T4`
- 如果你不是 `root`，也没有给 `nmap` 配置 `CAP_NET_RAW/CAP_NET_ADMIN`，建议改成：

```bash
# edit config/local_settings.json
```

<a id="tool-setup"></a>
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

默认参数：

- Windows: `-sT -Pn -T4`
- Linux / macOS: `-sS -Pn -T4`

### Subfinder

- 项目地址: `https://github.com/projectdiscovery/subfinder`
- 默认位置:
  - Windows: `tools/subfinder/subfinder.exe`
  - Linux / macOS: `tools/subfinder/subfinder`
- 运行时配置写到 `runtime/subfinder_home/.config/subfinder/`
- 这些配置文件只在运行时自动生成，不需要手动提交

如果 Linux 上提示权限问题：

```bash
chmod +x tools/subfinder/subfinder
```

如果已经有执行位仍然报 `Permission denied`，通常要继续检查挂载点是否为 `noexec`。

### OneForAll

- 项目地址: `https://github.com/shmilylty/OneForAll`
- 默认位置: `tools/oneforall/`
- 根目录 `requirements.txt` 已包含它的 Python 依赖
- 每次运行都会写唯一导出文件到 `runtime/oneforall/exports/`
- 包装器只解析本次导出文件，不再复用 `tools/oneforall/results/` 里的旧结果

关于 sqlite：

- `OneForAll` 仍然依赖可用的 `sqlite3`
- 如果当前 Python 缺少标准库 `sqlite3`，项目会尝试使用 `pysqlite3-binary`
- 只有 `python tools/self_check.py` 验证通过时，才会把它标记成可用

### dirsearch

- 项目地址: `https://github.com/maurosoria/dirsearch`
- 默认位置: `tools/dirsearch/dirsearch.py`
- 根目录 `requirements.txt` 已包含它的 Python 依赖
- 目前只支持手动配置路径，不支持自动下载

<a id="usage"></a>
## 使用方式

支持三种入口：

- `python scan.py <domain>`
- `python scan.py <domain> --nmap-args "-sV -Pn"`（仅本次运行生效，不会修改本地配置）
  - 闈炰氦浜掑紡鎵弿锛岄€傚悎浜虹被鐢ㄦ埛鐩存帴鎵ц鍗曠洰鏍囨垨鎵归噺浠诲姟
- `python main.py`
  - 交互式扫描和工具配置
- 直接编辑 `config/local_settings.json`
  - 适合修改本机工具路径、本机参数覆盖和排障
- `python mcp_server.py`
  - 通过 MCP 管理工具配置

### 配置示例

```bash
python scan.py example.com --port-scan --web-fingerprint
python scan.py --targets-file domains.txt --port-scan --web-fingerprint --directory-scan
python scan.py example.com --tools subfinder --output results/example.json
python scan.py example.com --tools oneforall --subfinder-args "-rl 50" --nmap-args "-sV -Pn"
python tools/self_check.py
# edit config/local_settings.json
```

### MCP 服务

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

<a id="output"></a>
## 输出结果

结果默认写到 `results/`。

你会看到两类文件：

- 单个目标结果: `<domain>_YYYYMMDD_HHMMSS.json`
- 批量汇总结果: `batch_summary_YYYYMMDD_HHMMSS.json`
- 面向人类的摘要报告: `<name>.summary.csv`

单次扫描结果的核心字段包括：

- `target`
- `statistics`
- `subdomains`
- `tool_runs`
- `port_scan`
- `web_fingerprint`
- `directory_scan`

其中：

- `tool_runs.<tool> = {status, return_code, message, raw_count, valid_count}`
- `port_scan.hosts` 是 `IP -> 开放端口列表`
- `web_fingerprint.targets` 是识别出的 Web 目标
- `directory_scan.targets[*].findings` 是目录扫描发现

`tool_runs.<tool>.status` 只会是下面四种之一：

- `completed`
- `error`
- `timeout`
- `skipped`

<a id="scan-flow"></a>
## 扫描流程说明

### 主流程

1. 子域名工具收集结果并合并去重
2. 根据配置执行泛解析过滤和 DNS 校验
3. 对有效 IP 运行端口扫描
4. 对开放 Web 端口执行指纹识别
5. 只对已识别的 Web URL 运行目录扫描

### Web 指纹默认参数

- `-Pn`
- `-sV`
- `--version-light`
- `--max-retries 1`
- `--host-timeout 90s`
- `--script-timeout 15s`
- `--script http-title,http-server-header,ssl-cert`

<a id="testing"></a>
## 测试

运行全部测试：

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

部署后的推荐验证顺序：

```bash
python tools/self_check.py
python -m unittest discover -s tests -p "test_*.py" -v
python main.py
python mcp_server.py
```

<a id="faq"></a>
## 常见问题

### 提示工具不可用

先跑自检：

```bash
python tools/self_check.py
```

重点看它到底是：

- `未安装`
- `已安装但不可用`
- `路径错误`
- `权限 / noexec`
- `sqlite3 / Python 依赖问题`

### `nmap` 检测失败

确认下面任意一项成立：

- 终端执行 `nmap --version` 能成功
- 已通过工具配置菜单或 `config/local_settings.json` 设置 `nmap` 路径
- Linux 下如果使用 `-sS`，具备 `root` 或 `CAP_NET_RAW/CAP_NET_ADMIN`

### `dirsearch` 不可用

当前需要手动配置路径，例如：

直接编辑 `config/local_settings.json`，把 `tool_paths.dirsearch` 指到 `./tools/dirsearch/dirsearch.py`。

如果 `dirsearch` 缺失，`web_fingerprint` 仍会执行，但目录扫描会标记为 `skipped_unavailable`。

### 复制了别的机器上的 `config/local_settings.json`

这个文件是主机本地配置，建议不要跨机器复制。

如果 Linux 上误带了 Windows 路径配置，可以：

- 删除 `config/local_settings.json`
- 或直接编辑 `config/local_settings.json` 设置本机路径，例如：

```json
{
  "tool_paths": {
    "subfinder": "./tools/subfinder/subfinder"
  }
}
```

<a id="contributing"></a>
## 贡献指南

欢迎通过 Issue 或 Pull Request 参与改进。

- 提交问题前，先确认能否通过 `python tools/self_check.py` 和测试命令复现
- 提交 PR 时尽量说明改动背景、影响范围和验证方式
- 如果涉及工具行为或输出结构变更，请同步更新 README

更详细的约定见 [CONTRIBUTING.md](./CONTRIBUTING.md)。

<a id="responsible-use"></a>
## 免责声明

本项目仅适用于以下场景：

- 你拥有或被明确授权测试的资产
- 学习、研究和自有环境排查
- 在合法合规前提下的安全验证

请不要将本项目用于未授权的扫描、探测或任何可能影响他人系统稳定性的行为。使用者应自行承担使用风险，并遵守所在地法律、平台规则与目标系统授权边界。

<a id="license"></a>
## 许可证

当前仓库还没有补充根目录 `LICENSE` 文件。

这意味着仓库虽然已公开，但授权边界仍然不够清晰。正式作为开源项目长期维护前，建议尽快补齐根目录 `LICENSE`，并在这里放出明确链接。仓库内置的第三方工具与源码仍分别遵循各自上游许可证。
