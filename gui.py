import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from dns_resolver import resolve_dns, build_query, parse_response


class DNSResolverApp:
    def __init__(self, root):
        self.root = root
        root.title("DNS解析器 ")
        root.geometry("680x500")

        self.history = []
        self.current_ip = ""
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # 输入区域
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)
        ttk.Label(input_frame, text="输入完整域名：").pack(side=tk.LEFT)
        self.domain_entry = ttk.Entry(input_frame, width=30)
        self.domain_entry.pack(side=tk.LEFT, padx=5)
        self.query_btn = ttk.Button(
            input_frame, text="立即查询", command=self.start_query_thread
        )
        self.query_btn.pack(side=tk.LEFT)

        # 结果区域
        result_frame = ttk.LabelFrame(main_frame, text="查询结果")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.result_text = tk.Text(result_frame, height=4, wrap=tk.WORD, state=tk.DISABLED)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.visit_btn = ttk.Button(
            result_frame, text="访问网站", command=self.visit_website, state=tk.DISABLED
        )
        self.visit_btn.pack(pady=5)

        # 历史记录
        history_frame = ttk.LabelFrame(main_frame, text="查询历史")
        history_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.history_text = scrolledtext.ScrolledText(
            history_frame, height=8, wrap=tk.WORD, state=tk.DISABLED
        )
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 状态栏
        self.status_bar = ttk.Label(main_frame, text="就绪", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, pady=5)

    def start_query_thread(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("输入错误", "请输入要查询的域名")
            return
        self.update_status("查询中...")
        self.query_btn.config(state=tk.DISABLED)
        threading.Thread(
            target=self.perform_dns_query, args=(domain,), daemon=True
        ).start()

    def perform_dns_query(self, domain):
        try:
            ips = resolve_dns(domain)
            if ips:
                self.current_ip = ips[0]
                result = f"IP地址：{self.current_ip}"
                self.add_history(f"{domain} -> {self.current_ip}")
            else:
                result = "未找到对应的IP地址"
                self.current_ip = ""
            self.show_result(result, success=bool(ips))
        except Exception as e:
            self.show_result(f"错误：{str(e)}", success=False)
        finally:
            self.update_status("就绪")
            self.query_btn.config(state=tk.NORMAL)
            self.visit_btn.config(state=tk.NORMAL if self.current_ip else tk.DISABLED)

    def visit_website(self):
        if self.current_ip:
            try:
                import webbrowser
                webbrowser.open(f"http://{self.current_ip}")
            except Exception as e:
                messagebox.showerror("访问失败", f"无法打开网站：{str(e)}")

    def add_history(self, record):
        self.history.append(record)
        self.history_text.config(state=tk.NORMAL)
        self.history_text.insert(tk.END, record + "\n")
        self.history_text.see(tk.END)
        self.history_text.config(state=tk.DISABLED)

    def show_result(self, text, success=True):
        self.root.after(0, lambda: self._update_result(text, success))

    def _update_result(self, text, success):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)
        tag = "success" if success else "error"
        self.result_text.tag_add(tag, 1.0, tk.END)
        self.result_text.tag_config("success", foreground="green")
        self.result_text.tag_config("error", foreground="red")
        self.result_text.config(state=tk.DISABLED)

    def update_status(self, text):
        self.root.after(0, lambda: self.status_bar.config(text=text))