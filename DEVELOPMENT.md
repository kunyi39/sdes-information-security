# S-DES 开发说明

## 文件结构

- `sdes.py`：作业参数、子密钥生成、分组加解密、字节和 ASCII 文本接口。
- `cryptanalysis.py`：穷举密钥搜索、单个明密文对候选密钥分析、固定明文密钥碰撞分析，以及全明文穷举。
- `gui_app.py`：Tkinter 界面，提供分组、ASCII 文本、暴力破解和碰撞分析四个页面。
- `test_sdes.py`：参数、测试向量和核心算法测试。
- `test_extended_features.py`：文本、暴力破解和碰撞分析测试。
- `cross_test_vectors.csv`：组员交叉测试用例及结果记录栏。

## 位串与参数约定

置换位置从左向右、从 1 开始编号。LS1 和 LS2 是分别应用于左右 5 位密钥半区的循环左移置换；生成 K2 时，在 LS1 结果上再应用 LS2。S 盒的行号取输入 4 位的外侧两位，列号取中间两位。所有置换与 S 盒参数均位于 `sdes.py`，SBox2 使用作业要求文件所列数值。

## 核心函数

- `generate_subkeys(key) -> (k1, k2)`：10 位二进制密钥转成两个 8 位子密钥。
- `encrypt_block(plaintext, key) -> ciphertext`：加密一个 8 位二进制分组。
- `decrypt_block(ciphertext, key) -> plaintext`：解密一个 8 位二进制分组。
- `encrypt_bytes(data, key)` / `decrypt_bytes(data, key)`：逐字节处理 `bytes`。
- `encrypt_text(text, key)`：ASCII 文本加密，结果为大写十六进制字符串。
- `decrypt_text(ciphertext_hex, key)`：十六进制密文解密为 ASCII 文本。
- `brute_force_keys(known_pairs)`：接收 `(plaintext, ciphertext)` 对序列，返回匹配密钥、搜索数量、开始/结束时间和耗时。
- `analyze_plaintext_collisions(plaintext)`：枚举全部密钥，统计固定明文的密钥碰撞。
- `analyze_all_plaintexts()`：穷举所有 256 个明文分组及全部密钥。

输入格式错误时，核心接口抛出 `ValueError` 或 `TypeError`；GUI 将错误转换为提示框。

## 交叉测试协议

双方统一使用 8 位二进制分组、10 位二进制密钥、左起 1-based 位编号和本仓库的参数。由一方按 `cross_test_vectors.csv` 加密，将密文交给另一方解密；再交换角色。确认对方输出与 CSV 预期值一致后，填写 CSV 的接收方结果与通过状态。当前 CSV 的预期密文是本实现按指定参数产生的向量，不能代替与组员程序的实际互测记录。

## 2026-10-02 实验补充接口

- `reference_sdes.py`：独立整数位运算实现 B，公开 `generate_subkeys(key)`、`encrypt_block(plaintext, key)`、`decrypt_block(ciphertext, key)`；输入输出格式与 A 一致，不导入 A。
- `run_experiments.py`：`run_cross_tests(source: Path, output_directory: Path) -> dict` 实际执行两个方向并写实测 CSV；`analyze_random_sample(plaintext: str, key: str) -> dict` 返回随机输入对应密文、完整搜索结果及 B 对候选的复核。
- `test_cooperation.py`：新增 7 项检查，先验证失败再实现，保留 CSV 格式错误的复现、误填预期密文时的 FAIL 检查、无 Git 环境的完整实验检查和已有文件保护检查。
- `create_gui_animation.py`：将真实 GUI 原始截图合成为动图，仅此工具需要 Pillow。

自动实验先保存随机抽样输入，再加密和穷举。时间与环境保存在 JSON 中；A 的测时仍采用 `perf_counter()`，界面开始/结束时间来自现有模块的实际本地时间戳。本机是 UTC+08:00。实验脚本每次选择新的输出目录，不覆盖之前的原始记录。
