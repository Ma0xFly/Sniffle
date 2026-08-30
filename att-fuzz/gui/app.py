#!/usr/bin/env python3
# att-fuzz/gui/app.py
"""NiceGUI 应用入口。

用法(推荐直接以脚本运行,任何目录都行):
  python3 att-fuzz/gui/app.py              # 浏览器模式(本机 http://localhost:8765)
  python3 att-fuzz/gui/app.py --native     # 原生窗口(需 pip install pywebview)
  python3 att-fuzz/gui/app.py --port 9000 --host 0.0.0.0   # 允许局域网远程访问
或包模块方式(cd att-fuzz 目录):
  python3 -m gui.app
离线演示: python3 att-fuzz/gui_demo.py (FakeHw,无硬件)
"""

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python_cli"))
sys.path.insert(0, str(REPO / "att-fuzz"))

from nicegui import ui  # noqa: E402

from gui.pages import control, dashboard, results, history  # noqa: E402
import gui.state as state_mod  # noqa: E402


@ui.page("/")
def _page_control():
    control.page()


@ui.page("/dashboard")
def _page_dashboard():
    dashboard.page()


@ui.page("/results")
def _page_results():
    results.page()


@ui.page("/history")
def _page_history():
    history.page()


def main():
    ap = argparse.ArgumentParser(description="Sniffle ATT fuzzer GUI (NiceGUI)")
    ap.add_argument("--native", action="store_true", help="原生窗口(需 pywebview)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="0.0.0.0",
                    help="监听地址(0.0.0.0 允许局域网远程访问串口机)")
    ap.add_argument("--demo", action="store_true", help="离线演示(FakeHw,等价 gui_demo.py)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.demo:
        import os
        os.environ["ATT_FUZZ_DEMO"] = "1"
        state_mod.set_demo_mode(True)

    import logging
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                        datefmt="%H:%M:%S")

    ui.run(title="Sniffle ATT Fuzzer",
           host=args.host, port=args.port,
           native=args.native, reload=False, dark=True,
           show=not args.native,
           language="zh-CN")


if __name__ == "__main__":
    main()
