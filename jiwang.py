import socket
import struct
import random
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext


class DNSResolverApp:
    def __init__(self, root):
        self.root = root
        root.title("DNS解析器 v3.0")
        root.geometry("680x500")

        # 初始化历史记录
        self.history = []
        self.current_ip = ""

        # 创建界面组件
        self.create_widgets()

    def create_widgets(self):
        # 主容器
        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # 输入区域
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)

        ttk.Label(input_frame, text="输入完整域名：").pack(side=tk.LEFT)
        self.domain_entry = ttk.Entry(input_frame, width=30)
        self.domain_entry.pack(side=tk.LEFT, padx=5)

        self.query_btn = ttk.Button(
            input_frame,
            text="立即查询",
            command=self.start_query_thread
        )
        self.query_btn.pack(side=tk.LEFT)

        # 结果区域
        result_frame = ttk.LabelFrame(main_frame, text="查询结果")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.result_text = tk.Text(
            result_frame,
            height=4,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.visit_btn = ttk.Button(
            result_frame,
            text="访问网站",
            command=self.visit_website,
            state=tk.DISABLED
        )
        self.visit_btn.pack(pady=5)

        # 历史记录
        history_frame = ttk.LabelFrame(main_frame, text="查询历史")
        history_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.history_text = scrolledtext.ScrolledText(
            history_frame,
            height=8,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 状态栏
        self.status_bar = ttk.Label(
            main_frame,
            text="就绪",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X, pady=5)

    def start_query_thread(self):
        """启动查询线程"""
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("输入错误", "请输入要查询的域名")
            return

        self.update_status("查询中...")
        self.query_btn.config(state=tk.DISABLED)
        self.visit_btn.config(state=tk.DISABLED)

        threading.Thread(
            target=self.perform_dns_query,
            args=(domain,),
            daemon=True
        ).start()

    def perform_dns_query(self, domain):
        """执行DNS查询的核心逻辑"""
        try:
            query = self.build_query(domain)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(query, ('8.8.8.8', 53))
                data, _ = sock.recvfrom(512)

            ips = self.parse_response(data)
            if ips:
                self.current_ip = ips[0]
                result = f"IP地址：{self.current_ip}"
                self.add_history(f"{domain} -> {self.current_ip}")
            else:
                result = "未找到对应的IP地址"
                self.current_ip = ""

            self.show_result(result, success=bool(ips))

        except socket.timeout:
            self.show_result("错误：查询超时", success=False)
        except Exception as e:
            self.show_result(f"错误：{str(e)}", success=False)
        finally:
            self.update_status("就绪")
            self.query_btn.config(state=tk.NORMAL)
            self.visit_btn.config(state=tk.NORMAL if self.current_ip else tk.DISABLED)

    def visit_website(self):
        """访问网站功能"""
        if self.current_ip:
            try:
                webbrowser.open(f"http://{self.current_ip}")
            except Exception as e:
                messagebox.showerror("访问失败", f"无法打开网站：{str(e)}")

    def add_history(self, record):
        """添加历史记录"""
        self.history.append(record)
        self.history_text.config(state=tk.NORMAL)
        self.history_text.insert(tk.END, record + "\n")
        self.history_text.see(tk.END)
        self.history_text.config(state=tk.DISABLED)

    def show_result(self, text, success=True):
        """显示查询结果"""
        self.root.after(0, lambda: self._update_result(text, success))

    def _update_result(self, text, success):
        """更新结果区域"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)
        # 设置结果颜色
        tag = "success" if success else "error"
        self.result_text.tag_add(tag, 1.0, tk.END)
        self.result_text.tag_config("success", foreground="green")
        self.result_text.tag_config("error", foreground="red")
        self.result_text.config(state=tk.DISABLED)

    def update_status(self, text):
        """更新状态栏"""
        self.root.after(0, lambda: self.status_bar.config(text=text))

    # 以下DNS协议相关方法与之前实现保持一致
    def build_query(self, domain):
        transaction_id = random.randint(0, 65535)
        flags = 0x0100
        questions = 1
        header = struct.pack('!HHHHHH', transaction_id, flags, questions, 0, 0, 0)

        qname = b''
        for part in domain.encode().split(b'.'):
            qname += struct.pack('!B', len(part)) + part
        qname += b'\x00'

        question = qname + struct.pack('!HH', 1, 1)
        return header + question

    def parse_response(self, data):
        transaction_id, flags, qdcount, ancount, _, _ = struct.unpack('!HHHHHH', data[:12])
        if ancount == 0:
            return []

        offset = 12
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 5

        ips = []
        for _ in range(ancount):
            _, offset = self.parse_name(data, offset)
            type_, class_, ttl, data_len = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10
            if type_ == 1 and class_ == 1 and data_len == 4:
                ip = struct.unpack('!4B', data[offset:offset + 4])
                ips.append('.'.join(map(str, ip)))
            offset += data_len
        return ips

    def parse_name(self, data, offset):
        name = []
        while True:
            length = data[offset]
            if (length & 0xC0) == 0xC0:
                ptr = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
                part, _ = self.parse_name(data, ptr)
                name.extend(part)
                offset += 2
                break
            elif length == 0:
                offset += 1
                break
            else:
                offset += 1
                name.append(data[offset:offset + length].decode())
                offset += length
        return name, offset
'''

if __name__ == '__main__':
    root = tk.Tk()
    app = DNSResolverApp(root)

    # 设置界面样式
    style = ttk.Style()
    style.configure("TButton", padding=6)
    style.configure("TEntry", padding=4)

    root.mainloop()
    '''