"""Tkinter interface for S-DES blocks, ASCII text, and key analysis."""

import tkinter as tk
from tkinter import messagebox, ttk

from cryptanalysis import analyze_all_plaintexts, analyze_plaintext_collisions, brute_force_keys
from sdes import decrypt_block, decrypt_text, encrypt_block, encrypt_text


class SDESApp(tk.Tk):
    """Desktop application for the S-DES assignment features."""

    def __init__(self) -> None:
        super().__init__()
        self.title("S-DES 加密与分析工具")
        self.geometry("760x600")
        self.minsize(680, 520)
        self.configure(padx=16, pady=14)
        self._build_interface()

    def _build_interface(self) -> None:
        ttk.Label(self, text="S-DES 加密与分析工具", font=("Microsoft YaHei UI", 16, "bold")).pack(
            anchor="w", pady=(0, 10)
        )
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        self._build_block_tab(notebook)
        self._build_text_tab(notebook)
        self._build_bruteforce_tab(notebook)
        self._build_analysis_tab(notebook)

    @staticmethod
    def _output_box(parent: ttk.Frame, height: int = 5) -> tk.Text:
        box = tk.Text(parent, height=height, wrap="word", font=("Consolas", 10))
        box.configure(state="disabled")
        return box

    @staticmethod
    def _set_output(box: tk.Text, text: str) -> None:
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    @staticmethod
    def _key_row(parent: ttk.Frame, row: int) -> tk.StringVar:
        variable = tk.StringVar()
        ttk.Label(parent, text="密钥（10 位二进制）").grid(row=row, column=0, sticky="w", pady=5)
        ttk.Entry(parent, textvariable=variable, width=34).grid(
            row=row, column=1, sticky="ew", pady=5
        )
        return variable

    def _build_block_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=18)
        notebook.add(tab, text="分组加解密")
        tab.columnconfigure(1, weight=1)
        self.block_var = tk.StringVar()
        self.block_result = tk.StringVar(value="")

        ttk.Label(tab, text="输入分组（8 位二进制）").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(tab, textvariable=self.block_var).grid(row=0, column=1, sticky="ew", pady=5)
        self.block_key_var = self._key_row(tab, 1)

        buttons = ttk.Frame(tab)
        buttons.grid(row=2, column=0, columnspan=2, sticky="w", pady=12)
        ttk.Button(buttons, text="加密", command=lambda: self._run_block(encrypt_block)).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(buttons, text="解密", command=lambda: self._run_block(decrypt_block)).pack(
            side="left", padx=8
        )
        ttk.Button(buttons, text="清空", command=self._clear_block).pack(side="left", padx=8)
        ttk.Label(tab, text="输出（8 位二进制）").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(tab, textvariable=self.block_result, state="readonly").grid(
            row=3, column=1, sticky="ew", pady=5
        )
        ttk.Label(
            tab,
            text="加密时输入明文；解密时输入密文。位串从左到右按位置 1 开始编号。",
            wraplength=640,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(16, 0))

    def _build_text_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=18)
        notebook.add(tab, text="ASCII 字符串")
        tab.columnconfigure(1, weight=1)
        self.text_key_var = tk.StringVar()
        self.text_input = tk.Text(tab, height=7, wrap="word")
        self.text_cipher = tk.Text(tab, height=5, wrap="word", font=("Consolas", 10))
        self.text_output = self._output_box(tab, 7)

        ttk.Label(tab, text="ASCII 明文").grid(row=0, column=0, sticky="nw", pady=5)
        self.text_input.grid(row=0, column=1, sticky="ew", pady=5)
        self.text_key_var = self._key_row(tab, 1)
        ttk.Label(tab, text="十六进制密文").grid(row=2, column=0, sticky="nw", pady=5)
        self.text_cipher.grid(row=2, column=1, sticky="ew", pady=5)
        buttons = ttk.Frame(tab)
        buttons.grid(row=3, column=0, columnspan=2, sticky="w", pady=10)
        ttk.Button(buttons, text="加密明文 → 十六进制", command=self._encrypt_text).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(buttons, text="解密十六进制 → 明文", command=self._decrypt_text).pack(
            side="left", padx=8
        )
        ttk.Label(tab, text="结果").grid(row=4, column=0, sticky="nw", pady=5)
        self.text_output.grid(row=4, column=1, sticky="ew", pady=5)
        ttk.Label(
            tab,
            text="文本按 ASCII 编码，每个字节独立加密；密文用十六进制表示。非 ASCII 字符不支持。",
            wraplength=640,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))

    def _build_bruteforce_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=18)
        notebook.add(tab, text="暴力破解")
        tab.columnconfigure(0, weight=1)
        ttk.Label(
            tab,
            text="每行输入一组明密文对，格式为：8位明文 空格 8位密文。可输入多行缩小候选范围。",
            wraplength=660,
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.pairs_input = tk.Text(tab, height=6, wrap="none", font=("Consolas", 10))
        self.pairs_input.grid(row=1, column=0, sticky="nsew", pady=5)
        ttk.Button(tab, text="搜索全部 1024 个密钥", command=self._run_bruteforce).grid(
            row=2, column=0, sticky="w", pady=10
        )
        self.bruteforce_output = self._output_box(tab, 10)
        self.bruteforce_output.grid(row=3, column=0, sticky="nsew", pady=5)

    def _build_analysis_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=18)
        notebook.add(tab, text="密钥碰撞分析")
        tab.columnconfigure(1, weight=1)
        self.analysis_plaintext_var = tk.StringVar(value="10101010")
        ttk.Label(tab, text="固定明文（8 位二进制）").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(tab, textvariable=self.analysis_plaintext_var).grid(
            row=0, column=1, sticky="ew", pady=5
        )
        buttons = ttk.Frame(tab)
        buttons.grid(row=1, column=0, columnspan=2, sticky="w", pady=10)
        ttk.Button(buttons, text="分析该明文", command=self._run_collision_analysis).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(buttons, text="穷举全部 256 个明文", command=self._run_full_analysis).pack(
            side="left", padx=8
        )
        self.analysis_output = self._output_box(tab, 16)
        self.analysis_output.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=5)
        ttk.Label(
            tab,
            text="分析对固定明文枚举全部 1024 个密钥，统计不同密钥产生相同密文的情况。",
            wraplength=650,
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))

    def _run_block(self, operation) -> None:
        try:
            result = operation(self.block_var.get().strip(), self.block_key_var.get().strip())
        except (TypeError, ValueError) as error:
            self.block_result.set("")
            messagebox.showerror("输入错误", str(error), parent=self)
            return
        self.block_result.set(result)

    def _clear_block(self) -> None:
        self.block_var.set("")
        self.block_key_var.set("")
        self.block_result.set("")

    def _encrypt_text(self) -> None:
        try:
            encrypted = encrypt_text(self.text_input.get("1.0", "end-1c"), self.text_key_var.get().strip())
        except (TypeError, ValueError) as error:
            messagebox.showerror("输入错误", str(error), parent=self)
            return
        self._set_output(self.text_output, encrypted)

    def _decrypt_text(self) -> None:
        try:
            decrypted = decrypt_text(
                self.text_cipher.get("1.0", "end-1c").strip(), self.text_key_var.get().strip()
            )
        except (TypeError, ValueError) as error:
            messagebox.showerror("输入错误", str(error), parent=self)
            return
        self._set_output(self.text_output, decrypted)

    def _run_bruteforce(self) -> None:
        pairs = []
        for line_number, line in enumerate(self.pairs_input.get("1.0", "end-1c").splitlines(), 1):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) != 2:
                messagebox.showerror(
                    "输入错误", f"第 {line_number} 行应为：8位明文 空格 8位密文。", parent=self
                )
                return
            pairs.append((parts[0], parts[1]))
        try:
            result = brute_force_keys(pairs)
        except (TypeError, ValueError) as error:
            messagebox.showerror("输入错误", str(error), parent=self)
            return
        keys = "\n".join(result.candidate_keys) if result.candidate_keys else "未找到匹配密钥。"
        self._set_output(
            self.bruteforce_output,
            f"检查密钥数：{result.checked_keys}\n"
            f"开始时间：{result.started_at}\n"
            f"结束时间：{result.finished_at}\n"
            f"耗时：{result.elapsed_seconds:.6f} 秒\n"
            f"候选密钥数：{len(result.candidate_keys)}\n\n候选密钥：\n{keys}",
        )

    def _run_collision_analysis(self) -> None:
        try:
            result = analyze_plaintext_collisions(self.analysis_plaintext_var.get().strip())
        except (TypeError, ValueError) as error:
            messagebox.showerror("输入错误", str(error), parent=self)
            return
        examples = []
        for ciphertext, keys in list(result.collisions.items())[:12]:
            examples.append(f"密文 {ciphertext} ← 密钥 {', '.join(keys)}")
        output = (
            f"固定明文：{result.plaintext}\n"
            f"枚举密钥数：1024\n"
            f"不同密文数：{result.distinct_ciphertexts}\n"
            f"有多个密钥对应的密文数：{result.ciphertexts_with_multiple_keys}\n"
            f"单个密文最多对应密钥数：{result.maximum_keys_for_ciphertext}\n\n"
            "碰撞示例（最多显示12项）：\n"
            + ("\n".join(examples) if examples else "未发现碰撞")
        )
        self._set_output(self.analysis_output, output)

    def _run_full_analysis(self) -> None:
        self.configure(cursor="watch")
        self.update_idletasks()
        try:
            result = analyze_all_plaintexts()
        except (TypeError, ValueError) as error:
            messagebox.showerror("分析失败", str(error), parent=self)
            return
        finally:
            self.configure(cursor="")
        self._set_output(
            self.analysis_output,
            f"检查明文块数：{result.plaintext_blocks_checked}\n"
            f"每个明文检查的密钥数：{result.keys_checked_per_plaintext}\n"
            f"存在密钥碰撞的明文块数：{result.plaintexts_with_collisions}\n"
            f"每个明文对应的不同密文数范围："
            f"{result.minimum_distinct_ciphertexts}–{result.maximum_distinct_ciphertexts}\n\n"
            "结论：对每一个 8 位固定明文，1024 个密钥只能产生至多 256 种 8 位密文，"
            "因此必然存在不同密钥加密得到相同密文的情况。",
        )


if __name__ == "__main__":
    SDESApp().mainloop()
