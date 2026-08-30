#!/usr/bin/env python3
# att-fuzz/gui_demo.py
"""离线演示入口:FakeHw 模拟 GATT server,无硬件跑通 GUI 全流程。

用法: python3 att-fuzz/gui_demo.py [--port 8765]
说明:
- 目标档案选 "__demo__"(已内置 FakeHw 假耳机)
- 只支持 发现 / Fuzz / 重放(广播探测在模拟器上无意义)
- 语料直接用 strategies/ 全目录,建议配 max-cases 演示
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "python_cli"))
sys.path.insert(0, str(REPO / "att-fuzz"))

import os
os.environ["ATT_FUZZ_DEMO"] = "1"     # 必须在导入 gui 之前

from gui.app import main

if __name__ == "__main__":
    main()
