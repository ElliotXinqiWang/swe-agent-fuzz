#!/bin/bash
set -e

# 在 SWE-agent 的工具环境里安装依赖
# 具体 python/pip 路径依据你的环境，下面是比较常见的形式。

pip install --upgrade atheris
pip install --upgrade openai

echo "fuzz_atheris tool dependencies installed."
