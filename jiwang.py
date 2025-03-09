import socket
import struct
import random
import threading
import webbrowser
import re
import tkinter as tk
from tkinter import ttk, messagebox


class DNSResolverApp:
    def __init__(self, master):
        self.master = master
        master.title("DNS解析器 v3.0")
        master.geometry("520x300")
        master.resizable(False, False)

        # 样式配置
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("微软雅黑", 10))
        self.style.configure("TButton", font=("微软雅黑", 10, "bold"))
        self.style.configure("TEntry", font=("微软雅黑", 10))

        # 主框架
        self.frame = ttk.Frame(master, padding=20)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # 域名输入
        ttk.Label(self.frame, text="输入完整域名：").grid(row=0, column=0, sticky=tk.W)
        self.domain_entry = ttk.Entry(self.frame, width=35)
        self.domain_entry.grid(row=0, column=1, padx=5)
        self.domain_entry.insert(0, "google.com")  # 默认示例
        self.domain_entry.focus()

        # DNS服务器选择
        ttk.Label(self.frame, text="DNS服务器：").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.server_var = tk.StringVar(value="Google DNS")
        self.server_menu = ttk.Combobox(
            self.frame,
            textvariable=self.server_var,
            values=["阿里DNS", "114DNS", "Google DNS", "Cloudflare"],
            width=32,
            state="readonly"
        )
        self.server_menu.grid(row=1, column=1, padx=5)

        # 查询按钮
        self.query_btn = ttk.Button(self.frame, text="立即查询", command=self.start_query_thread)
        self.query_btn.grid(row=2, column=1, pady=15, sticky=tk.E)

        # 结果显示区域
        self.result_frame = ttk.LabelFrame(self.frame, text="查询结果", padding=10)
        self.result_frame.grid(row=3, column=0, columnspan=2, sticky=tk.W + tk.E)

        self.ip_label = ttk.Label(self.result_frame, text="IP地址：", foreground="#1E90FF")
        self.ip_label.grid(row=0, column=0, sticky=tk.W)

        self.access_btn = ttk.Button(
            self.result_frame,
            text="访问网站",
            command=self.open_website,
            state=tk.DISABLED
        )
        self.access_btn.grid(row=0, column=1, padx=10)

        # 状态栏
        self.status_bar = ttk.Label(self.frame, text="就绪", foreground="#666666")
        self.status_bar.grid(row=4, column=0, columnspan=2, pady=10)

    def start_query_thread(self):
        """启动查询线程"""
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("输入错误", "请输入有效的域名！")
            return

        # 增强域名验证
        if not re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", domain):
            messagebox.showwarning("格式错误", "请输入完整域名（如：www.baidu.com）")
            return

        self.query_btn["state"] = "disabled"
        self.access_btn["state"] = "disabled"
        self.status_bar.config(text="⌛ 正在查询域名...", foreground="#228B22")

        # 映射服务器IP
        server_ip = {
            "阿里DNS": "223.5.5.5",
            "114DNS": "114.114.114.114",
            "Google DNS": "8.8.8.8",
            "Cloudflare": "1.1.1.1"
        }[self.server_var.get()]

        threading.Thread(target=self.do_dns_query, args=(domain, server_ip)).start()

    def do_dns_query(self, domain, dns_server):
        """执行DNS查询"""
        try:
            ip = self.dns_resolver(domain, dns_server)
            self.show_result(ip)
            self.master.after(0, lambda: self.status_bar.config(text="✅ 查询完成", foreground="#228B22"))
        except Exception as e:
            self.master.after(0, lambda: self.status_bar.config(text=f"❌ 错误: {str(e)}", foreground="#FF4500"))
            messagebox.showerror("错误", str(e))
        finally:
            self.master.after(0, self.reset_ui)

    def show_result(self, ip):
        """显示结果并启用访问按钮"""
        self.ip_label.config(text=f"IP地址：{ip}")
        self.current_ip = ip  # 存储IP用于访问
        self.access_btn["state"] = "normal"

    def open_website(self):
        """通过IP访问网站（自动处理证书问题）"""
        if hasattr(self, 'current_ip'):
            try:
                # 优先尝试HTTPS，然后HTTP
                webbrowser.open_new_tab(f"https://{self.current_ip}")
                self.status_bar.config(text="🌐 已打开HTTPS页面（可能需要忽略证书警告）", foreground="#228B22")
            except Exception as e:
                webbrowser.open_new_tab(f"http://{self.current_ip}")
                self.status_bar.config(text="🌐 已打开HTTP页面", foreground="#228B22")
        else:
            messagebox.showwarning("警告", "请先查询有效IP地址")

    def reset_ui(self):
        """重置UI状态"""
        self.query_btn["state"] = "normal"

    # ====================== 核心DNS解析逻辑 ======================
    def dns_resolver(self, domain, dns_server):
        """DNS解析核心逻辑"""
        domain = domain.lower()  # DNS不区分大小写

        # 生成事务ID
        transaction_id = random.randint(0, 65535)

        # 构建DNS查询报文
        def build_query():
            header = struct.pack(
                '!HHHHHH',
                transaction_id,  # 事务ID
                0x0100,  # 标志：标准查询+递归请求
                1,  # 问题数
                0, 0, 0  # 回答、权威、附加数
            )
            # 编码域名（处理每个标签）
            # 在 build_query 函数中修改
            qname = b''.join(
                struct.pack('B', len(part)) + part.encode('latin-1')  # 强制使用latin-1编码
                for part in domain.split('.')
            ) + b'\x00'

            # 问题部分（A记录查询）
            question = qname + struct.pack('!HH', 1, 1)  # 类型A，类别IN
            return header + question

        # 发送并接收DNS响应
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            query = build_query()
            sock.sendto(query, (dns_server, 53))
            response, _ = sock.recvfrom(512)  # DNS UDP最大512字节

            # 验证事务ID
            resp_tid = struct.unpack('!H', response[:2])[0]
            if resp_tid != transaction_id:
                raise ValueError("响应事务ID不匹配")

            return self.parse_dns_response(response)

    def parse_dns_response(self, response):
        """优化的DNS响应解析（完整处理压缩指针）"""
        # 调试输出响应报文（十六进制）
        print("DNS响应报文（HEX）:", response.hex())

        def read_name(offset):
            """递归解析域名（支持压缩指针）"""
            labels = []
            max_jumps = 10  # 防止无限递归
            while max_jumps > 0:
                if offset >= len(response):
                    raise ValueError("响应报文损坏")

                # 处理压缩指针（0xC0开头）
                if (response[offset] & 0xC0) == 0xC0:
                    if offset + 1 >= len(response):
                        raise ValueError("压缩指针不完整")
                    ptr = (response[offset] & 0x3F) << 8 | response[offset + 1]
                    offset += 2
                    max_jumps -= 1
                    offset = ptr  # 跳转到指针位置
                    continue

                length = response[offset]
                offset += 1
                if length == 0:
                    break  # 结束符

                if length > 63:
                    raise ValueError("标签长度无效")

                labels.append(response[offset:offset + length].decode('latin-1'))
                offset += length
                max_jumps -= 1

            return ".".join(labels), offset

        # 解析头部
        _, flags, qdcount, ancount, _, _ = struct.unpack('!HHHHHH', response[:12])
        if (flags & 0x8000) == 0:
            raise ValueError("非DNS响应报文")
        if (flags & 0x0200):  # TC标志位（响应被截断）
            raise ValueError("响应被截断，请使用TCP重试")
        if ancount == 0:
            raise ValueError("该域名无有效记录")

        offset = 12  # 跳过头部

        # 跳过问题部分
        for _ in range(qdcount):
            _, offset = read_name(offset)
            offset += 4  # 跳过QTYPE和QCLASS

        # 解析回答部分
        answers = []
        for _ in range(ancount):
            # 1. 跳过资源记录域名
            _, offset = read_name(offset)

            # 2. 解析记录头
            if offset + 10 > len(response):
                raise ValueError("响应报文损坏")
            type_, _, _, data_len = struct.unpack('!HHIH', response[offset:offset + 10])
            offset += 10

            # 3. 处理记录数据
            if type_ == 1:  # A记录
                if data_len != 4:
                    raise ValueError(f"无效的IPv4地址长度：{data_len}")
                if offset + 4 > len(response):
                    raise ValueError("A记录数据超出响应范围")
                ip = socket.inet_ntoa(response[offset:offset + 4])
                answers.append(ip)
                offset += data_len
            elif type_ == 5:  # CNAME记录
                # 解析CNAME并跳过数据部分
                cname, new_offset = read_name(offset)
                print(f"发现CNAME记录: {cname}")
                offset = new_offset + data_len - (new_offset - offset)  # 计算剩余长度
            else:
                # 其他类型记录直接跳过
                offset += data_len

        if not answers:
            raise ValueError("未找到IPv4地址")
        return answers[0]

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSResolverApp(root)
    root.mainloop()