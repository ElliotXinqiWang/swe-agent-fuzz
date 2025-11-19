FROM python:3.10

# 安装 clang（和基础构建链）
RUN apt-get update && \
    apt-get install -y clang && \
    apt-get clean

# 可选：提前升级 pip
RUN pip install --upgrade pip

# 可选：提前安装 atheris + pytest（你可以也可以不预装）
RUN pip install "atheris==2.3.0" pytest

# 不需要 CMD，让 SWE-agent 自己控制
