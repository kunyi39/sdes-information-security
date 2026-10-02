# S-DES 作业程序使用说明

## 环境与启动

- Python 3.10 或更新版本；GUI 使用 Python 自带的 Tkinter，不需要安装第三方包。
- 在本文件所在目录打开终端，运行：

```powershell
python gui_app.py
```

## 界面功能

### 分组加解密

输入 8 位二进制分组和 10 位二进制密钥，点击“加密”或“解密”。输出仍是 8 位二进制。加密时输入明文，解密时输入密文。

### ASCII 字符串

在明文框输入 ASCII 文本和 10 位密钥，点击加密后得到十六进制密文。解密时将十六进制密文放入密文框，再点击解密。每个 ASCII 字节独立作为一个 S-DES 分组处理，不添加填充。非 ASCII 字符会被拒绝。

### 暴力破解

每行输入一组明密文对，格式为 `8位明文 空格 8位密文`。可以输入多行。程序穷举 1024 个 10 位密钥，显示所有匹配密钥、开始和结束时间以及耗时。运行录屏时可将该结果连同系统时钟一并录入，作为作业演示材料。

### 密钥碰撞分析

“分析该明文”会对输入的固定明文枚举 1024 个密钥，报告不同密文数、发生多密钥碰撞的密文数和示例。“穷举全部 256 个明文”逐一检查完整明文空间。

## 命令行核心接口

```python
from sdes import (
    generate_subkeys, encrypt_block, decrypt_block,
    encrypt_bytes, decrypt_bytes, encrypt_text, decrypt_text,
)
```

`encrypt_text` 返回大写十六进制密文；`decrypt_text` 接收十六进制密文并返回 ASCII 字符串。暴力破解和密钥碰撞分析接口见 `cryptanalysis.py`。

## 运行测试

```powershell
python -m unittest -v
```

测试结果和交叉测试步骤见 `TEST_RESULTS.md`。交叉测试向量见 `cross_test_vectors.csv`；CSV 中的组员程序实测栏须在与组员交换程序或结果后填写。
