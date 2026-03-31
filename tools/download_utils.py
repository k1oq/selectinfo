"""
工具下载与解压辅助函数。
"""
from __future__ import annotations

import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

import requests

import config
from utils.logger import get_logger

logger = get_logger(__name__)


def download_file(url: str, destination: Path, timeout: int = 120) -> Path:
    """下载文件到目标路径。"""
    destination.parent.mkdir(parents=True, exist_ok=True)

    with requests.get(url, stream=True, timeout=timeout) as response:
        response.raise_for_status()
        with open(destination, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024 * 128):
                if chunk:
                    f.write(chunk)

    return destination


def extract_archive(archive_path: Path, destination: Path):
    """解压 zip 或 tar.gz 压缩包。"""
    destination.mkdir(parents=True, exist_ok=True)

    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(destination)
        return

    suffixes = archive_path.suffixes
    if suffixes[-2:] == [".tar", ".gz"] or archive_path.suffix == ".tgz":
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(destination)
        return

    raise ValueError(f"不支持的压缩格式: {archive_path}")


def find_file(root: Path, filename: str) -> Path | None:
    """递归查找指定文件名。"""
    for path in root.rglob(filename):
        if path.is_file():
            return path
    return None


def copy_tree_contents(source_dir: Path, destination_dir: Path):
    """复制目录内容到目标目录。"""
    destination_dir.mkdir(parents=True, exist_ok=True)

    for item in source_dir.iterdir():
        target = destination_dir / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target)


class TempExtractionDir:
    """临时解压目录上下文。"""

    def __enter__(self) -> Path:
        self._temp_dir = Path(tempfile.mkdtemp(prefix="selectinfo_"))
        return self._temp_dir

    def __exit__(self, exc_type, exc, tb):
        shutil.rmtree(self._temp_dir, ignore_errors=True)


def download_subfinder_release(target_path: Path, system: str, arch: str) -> bool:
    """下载并解压 subfinder。"""
    try:
        response = requests.get(
            "https://api.github.com/repos/projectdiscovery/subfinder/releases/latest",
            timeout=30,
        )
        response.raise_for_status()
        release = response.json()
    except Exception as exc:
        logger.error(f"[red]获取 Subfinder 最新版本失败: {exc}[/red]")
        return False

    asset_url = ""
    asset_name = ""
    expected_suffix = ".zip" if system == "windows" else ".tar.gz"

    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if f"_{system}_{arch}" in name and name.endswith(expected_suffix):
            asset_name = name
            asset_url = asset.get("browser_download_url", "")
            break

    if not asset_url:
        logger.error(f"[red]未找到适用于当前平台的 Subfinder 发行包: {system}/{arch}[/red]")
        return False

    executable_name = "subfinder.exe" if system == "windows" else "subfinder"

    with TempExtractionDir() as temp_dir:
        archive_path = temp_dir / asset_name
        try:
            download_file(asset_url, archive_path)
            extract_archive(archive_path, temp_dir / "extracted")
            extracted_binary = find_file(temp_dir / "extracted", executable_name)
            if not extracted_binary:
                logger.error("[red]下载完成，但未找到 subfinder 可执行文件[/red]")
                return False

            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(extracted_binary, target_path)
            if system != "windows":
                target_path.chmod(0o755)
            return True
        except Exception as exc:
            logger.error(f"[red]下载 Subfinder 失败: {exc}[/red]")
            return False


def download_oneforall_repo(target_dir: Path) -> bool:
    """下载 OneForAll 仓库压缩包。"""
    repo_candidates = [
        ("master", "https://github.com/shmilylty/OneForAll/archive/refs/heads/master.zip"),
        ("main", "https://github.com/shmilylty/OneForAll/archive/refs/heads/main.zip"),
    ]

    with TempExtractionDir() as temp_dir:
        extracted_root = temp_dir / "extracted"

        for branch_name, url in repo_candidates:
            archive_path = temp_dir / f"oneforall_{branch_name}.zip"
            try:
                download_file(url, archive_path)
                extract_archive(archive_path, extracted_root)
                break
            except Exception:
                continue
        else:
            logger.error("[red]下载 OneForAll 失败，请检查网络或稍后重试[/red]")
            return False

        extracted_script = find_file(extracted_root, "oneforall.py")
        if not extracted_script:
            logger.error("[red]下载完成，但未找到 oneforall.py[/red]")
            return False

        source_root = extracted_script.parent
        copy_tree_contents(source_root, target_dir)
        return True


def detect_nmap_path(expected_location: Path) -> str:
    """检测 nmap 可执行文件位置。"""
    candidates: list[str] = []
    configured = config.get_tool_path("nmap")
    if configured:
        candidates.append(configured)

    candidates.extend(["nmap", str(expected_location)])

    for candidate in candidates:
        try:
            result = subprocess.run(
                [candidate, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return candidate
        except Exception:
            continue

    return ""
