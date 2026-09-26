"""pbpgen 的单元测试（只用标准库 unittest）。

从仓库任意位置都能跑：这里把 tools/pbpgen 挂到 sys.path 上，
这样 `python -m unittest discover -s tools/pbpgen/tests` 与
`cd tools/pbpgen && python -m unittest` 两种姿势都能 import 到 pbpgen 包。
"""

import pathlib
import sys

_PACKAGE_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)