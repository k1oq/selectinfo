"""
日志工具
"""
import logging
from rich.console import Console
from rich.logging import RichHandler

# Rich console 实例
console = Console()

def get_logger(name: str) -> logging.Logger:
    """获取日志记录器"""
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    
    return logger
