**S-DES 作业程序使用说明**  
**环境与启动**  
- Python 3.10 或更新版本；GUI 使用 Python 自带的 Tkinter，不需要安装第三方包。  
- 在本文件所在目录打开终端，运行：  
python gui_app.py  
   
**界面功能**  
**分组加解密**  
输入 8 位二进制分组和 10 位二进制密钥，点击“加密”或“解密”。输出仍是 8 位二进制。加密时输入明文，解密时输入密文。  
**ASCII 字符串**  
在明文框输入 ASCII 文本和 10 位密钥，点击加密后得到十六进制密文。解密时将十六进制密文放入密文框，再点击解密。每个 ASCII 字节独立作为一个 S-DES 分组处理，不添加填充。非 ASCII 字符会被拒绝。  
**暴力破解**  
每行输入一组明密文对，格式为 8位明文 空格 8位密文。可以输入多行。程序穷举 1024 个 10 位密钥，显示所有匹配密钥、开始和结束时间以及耗时。运行录屏时可将该结果连同系统时钟一并录入，作为作业演示材料。  
**密钥碰撞分析**  
“分析该明文”会对输入的固定明文枚举 1024 个密钥，报告不同密文数、发生多密钥碰撞的密文数和示例。“穷举全部 256 个明文”逐一检查完整明文空间。  
**命令行核心接口**  

```python
from sdes import (
    generate_subkeys, encrypt_block, decrypt_block,
    encrypt_bytes, decrypt_bytes, encrypt_text, decrypt_text,
)
```

   
encrypt_text 返回大写十六进制密文；decrypt_text 接收十六进制密文并返回 ASCII 字符串。暴力破解和密钥碰撞分析接口见 cryptanalysis.py。  
**运行测试**  
python -m unittest -v  
   
测试结果见 TEST_RESULTS.md 和 EXPERIMENT_RESULTS.md。交叉测试向量见 cross_test_vectors.csv，已填写本机 A 与独立实现 B 的双向实际输出；两位同学各自复跑的协作记录见 COOPERATION.md 。  
**独立实现与实验补充**  
新增 reference_sdes.py 使用整数位运算实现 B，不导入原字符串实现 A。运行全部实测实验：  
py -3.13 -m unittest -v  
 py -3.13 run_experiments.py  
   
每次保存到新的 artifacts/run_... 目录，包含两个方向的互测 CSV、随机抽样原始输入、全部候选密钥和全明文空间分析。--fill-vectors 可将新实测表复制回 cross_test_vectors.csv；原输入会先备份到该次结果目录。  
第4关真实 GUI 操作动图见 artifacts/stage4-bruteforce.gif。它由真实截图组成，画面停留是阅读时间，实际破解耗时看程序显示的测量值。已有动图无需安装额外依赖；仅重新运行 create_gui_animation.py 制作动图时需要 Pillow。  
本机 python 名称指向 Inkscape 的 Python，因此推荐使用已验证的 py -3.13。其他电脑可使用其实际安装的 Python 3.10+ 执行相同脚本。  
