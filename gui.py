import binascii
import socket
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from dns_resolver import resolve_dns, build_query, parse_response
from dns_resolver import validate_domain
from concurrent.futures import ThreadPoolExecutor

class DNSResolverApp:
    def __init__(self, root):
        self.root = root
        root.title("DNS解析器 ")
        root.geometry("800x700")

        self.history = []
        self.current_ip = ""
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        #main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)  # 增加外边距

        # 输入区域
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)
        ttk.Label(input_frame, text="输入域名：").pack(side=tk.LEFT)
        self.domain_entry = ttk.Entry(input_frame, width=30)
        self.domain_entry.pack(side=tk.LEFT, padx=5)
        self.query_btn = ttk.Button(
            input_frame, text="立即查询", command=self.start_query_thread
        )
        self.query_btn.pack(side=tk.LEFT)

        # 结果区域
        result_frame = ttk.LabelFrame(main_frame, text="查询结果")
        result_frame.pack(fill=tk.X, pady=8, ipadx=5, ipady=2)  # 减少内边距

        # 水平布局容器
        result_row = ttk.Frame(result_frame)
        result_row.pack(pady=3, fill=tk.X)

        # IP地址标签
        self.ip_label = ttk.Label(
            result_row,
            text="IP地址：",
            font=('微软雅黑', 9)
        )
        self.ip_label.pack(side=tk.LEFT, padx=(10, 0))

        # 动态显示区域（IP地址/错误信息）
        self.display_area = ttk.Label(
            result_row,
            text="",
            font=('Consolas', 12),
            width=25,
            anchor='w'
        )
        self.display_area.pack(side=tk.LEFT, padx=(0, 15))

        # 访问按钮
        self.visit_btn = ttk.Button(
            result_row,
            text="🌐 访问网站",
            command=self.visit_website,
            state=tk.DISABLED,
            width=20
        )
        self.visit_btn.pack(side=tk.RIGHT, padx=15)  #靠右且距离边框10个像素
        #过程区域

        process_frame = ttk.LabelFrame(main_frame, text="DNS解析过程跟踪")
        process_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.process_tree = ttk.Treeview(
            process_frame,
            columns=("step", "detail"),
            show="tree",
            height=4
        )
        # ===== 过程跟踪Treeview配置 =====
        # 列定义
        self.process_tree["columns"] = ("detail")
        self.process_tree.heading("#0", text="步骤", anchor="w")
        self.process_tree.heading("detail", text="详细信息", anchor="w")

        # 列宽配置
        self.process_tree.column("#0", width=10, minwidth=10)  # 步骤列
        self.process_tree.column("detail", width=300, stretch=True)  # 详情列自动扩展

        # 布局优化
        self.process_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ========= 新增污染检测区域 =========
        pollution_frame = ttk.LabelFrame(main_frame, text="DNS污染检测")
        pollution_frame.pack(fill=tk.BOTH, expand=False, pady=3, ipadx=5, ipady=2)  # 关闭expand并减少内边距

        # 检测结果树状图
        self.pollution_tree = ttk.Treeview(
            pollution_frame,
            columns=('server', 'status', 'ip', 'confidence'),
            show='headings',
            height=3
        )

        # 配置列
        columns = [
            ('server', 'DNS服务器', 100),
            ('status', '状态', 80),
            ('ip', '返回IP', 150),
            ('confidence', '可信度', 80)
        ]
        for col_id, text, width in columns:
            self.pollution_tree.heading(col_id, text=text)
            self.pollution_tree.column(col_id, width=width, anchor='center')

        # 滚动条
        scroll = ttk.Scrollbar(pollution_frame, orient="vertical", command=self.pollution_tree.yview)
        self.pollution_tree.configure(yscrollcommand=scroll.set)
        self.pollution_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # 检测结论标签
        self.pollution_status = ttk.Label(
            pollution_frame,
            text="待检测",
            font=('微软雅黑', 9, 'bold')
        )
        self.pollution_status.pack(side=tk.BOTTOM, fill=tk.X, pady=3)

        # 历史记录
        history_frame = ttk.LabelFrame(main_frame, text="查询历史")
        history_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.history_text = scrolledtext.ScrolledText(
            history_frame, height=4, wrap=tk.WORD, state=tk.DISABLED
        )
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.ip_label.configure(font=('TkDefaultFont', 10), anchor='center')
        result_frame.configure(padding=10)  # 内边距

        # 状态栏
        self.status_bar = ttk.Label(main_frame, text="就绪", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, pady=5)

    def start_query_thread(self):
        domain = self.domain_entry.get().strip()
        # 格式验证
        if not domain:
            messagebox.showwarning("输入错误", "请输入要查询的域名")
            return
        if not validate_domain(domain):
            self.show_result("错误：域名格式不正确", success=False)
            return

        # 原查询逻辑保持不变...
        self.update_status("查询中...")
        self.query_btn.config(state=tk.DISABLED)
        threading.Thread(
            target=self.perform_dns_query, args=(domain,), daemon=True
        ).start()



    '''  
    def perform_dns_query(self, domain):
          try:
              ips = resolve_dns(domain)
              print("[DEBUG] 解析结果:", ips)  # 调试输出
              if ips:
                  self.current_ip = ips[0]
                  result = f"✅ {self.current_ip}"
                  self.add_history(f"{domain} -> {self.current_ip}")
              else:
                  result = "❌ 未找到对应的IP地址"
                  self.current_ip = ""
              self.show_result(result, success=bool(ips))
          except Exception as e:
              self.show_result(f"错误：{str(e)}", success=False)
          finally:
              self.update_status("就绪")
              self.query_btn.config(state=tk.NORMAL)
              self.visit_btn.config(state=tk.NORMAL if self.current_ip else tk.DISABLED)
      '''

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
        # 清空历史显示内容
        self.display_area.config(text="")
        if success:
            # 成功显示蓝色IP地址
            self.display_area.config(
                text=text,
                foreground="#1E90FF",
                font=('Consolas', 9, 'bold')
            )
            self.visit_btn.config(state=tk.NORMAL)
        else:
            # 错误显示红色信息
            self.display_area.config(
                text=text,
                foreground="#FF4500",
                font=('微软雅黑', 9)
            )
            self.visit_btn.config(state=tk.DISABLED)

    # self.root.after(0, lambda: self._update_result(text, success))

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

    def update_process(self, step, detail):
        """更新解析过程树"""
        item_id = self.process_tree.insert(
            "", "end",
            text=step,
            values=(detail,)
        )
        self.process_tree.see(item_id)  # 自动滚动到最新条目

#DNS污染检测
    def perform_dns_query(self, domain):
        try:
            # 初始化所有结果区域
            self._clear_all_results()
            logger = DNSLogger(self)

            # ========= 新增污染检测流程 =========
            def pollution_check():
                """污染检测子线程"""
                try:
                    servers = {
                        'Google': '8.8.8.8',
                        'Cloudflare': '1.1.1.1',
                        'Quad9': '9.9.9.9'
                    }

                    # 并发查询所有服务器
                    with ThreadPoolExecutor() as executor:
                        futures = {
                            executor.submit(resolve_dns, domain, server): name
                            for name, server in servers.items()
                        }

                        results = {}
                        for future in futures:
                            name = futures[future]
                            try:
                                ips = future.result(timeout=5)
                                results[name] = ips
                                self._update_pollution_tree(name, "✅ 正常", ips, "")
                            except Exception as e:
                                results[name] = []
                                self._update_pollution_tree(name, "❌ 异常", "", str(e))

                        # 分析结果
                        all_ips = [ip for ips in results.values() for ip in ips]
                        ip_counts = {ip: all_ips.count(ip) for ip in set(all_ips)}
                        if ip_counts:
                            max_count = max(ip_counts.values())
                            total = len(servers)
                            confidence = f"{max_count}/{total}"

                            if max_count == total:
                                status = "✅ 结果一致"
                                color = "green"
                            elif max_count >= total // 2 + 1:
                                status = "⚠️ 疑似污染"
                                color = "orange"
                            else:
                                status = "❌ 确认污染"
                                color = "red"

                            self.root.after(0, lambda:
                            self.pollution_status.config(text=status, foreground=color))
                except Exception as e:
                    self.root.after(0, lambda:
                    self.pollution_status.config(text=f"检测失败: {str(e)}", foreground="red"))

            # 启动污染检测线程
            threading.Thread(target=pollution_check, daemon=True).start()
            # 初始化过程跟踪
            self.process_tree.delete(*self.process_tree.get_children())
            logger = DNSLogger(self)

            # 步骤1：构造查询报文
            query = build_query(domain, logger)

            # 步骤2：发送请求
            logger.add_step("发送查询请求", True,
                            f"目标服务器：8.8.8.8:53"
                            )

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(query, ('8.8.8.8', 53))

                # 步骤3：接收响应
                logger.add_step("等待响应", True, "超时设置：5秒")
                data, _ = sock.recvfrom(512)
                logger.add_step("接收响应", True,
                                f"响应长度：{len(data)}字节  "
                    f"十六进制头：{binascii.hexlify(data[:12]).decode()}")
                print("等待响应"+f"十六进制头：{binascii.hexlify(data[:12]).decode()}")

            # 步骤4：解析响应
            ips = parse_response(data, logger)
            print("[DEBUG] 解析结果:", ips)  # 调试输出

            # 显示最终结果
            if ips:
                self.current_ip=ips[0]#传给“访问网站”
                self.show_result(f"✅ {self.current_ip}",success=bool(ips))
                self.add_history(f"{domain} -> {ips[0]}")
            else:
                self.show_result("❌ 未找到对应的IP地址", success=bool(ips))

        except Exception as e:
            logger.add_step("解析失败", False, str(e))

        finally:
            self.update_status("就绪")
            self.query_btn.config(state=tk.NORMAL)
            self.visit_btn.config(state=tk.NORMAL if self.current_ip else tk.DISABLED)
    def _update_pollution_tree(self, server, status, ips, error):
        """更新污染检测树"""
        ips_display = ", ".join(ips) if ips else error
        confidence = f"{len(ips)}/3" if ips else "0/3"

        # 插入数据并获取项ID
        item_id = self.pollution_tree.insert(
            "",
            "end",
            values=(server, status, ips_display, confidence)
        )

        # 滚动到新插入的项
        self.pollution_tree.see(item_id)

        # 保持自动滚动（可选）
        self.pollution_tree.yview_moveto(1)

    def _clear_all_results(self):
        """清空所有结果"""
        # 原有清空逻辑
        self.display_area.config(text="")
        self.process_tree.delete(*self.process_tree.get_children())

        # 新增清空污染检测
        self.pollution_tree.delete(*self.pollution_tree.get_children())
        self.pollution_status.config(text="检测中...", foreground="blue")
class DNSLogger:
    """解析过程记录器"""

    def __init__(self, gui):
        self.gui = gui

    def add_step(self, step, status, detail=""):
        """添加解析步骤"""
        status_icon = "✓" if status else "✗"
        self.gui.update_process(
            f"{status_icon} {step}",
            detail
        )
