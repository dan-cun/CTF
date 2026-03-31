import requests
import re

base_url = "http://challenge-1b14527012465428.sandbox.ctfhub.com:10800/flag_in_here/"


def find_flag(url):
    try:
        res = requests.get(url)
        # 匹配目录 (以 / 结尾)
        dirs = re.findall(r'href="(.+?/)"', res.text)
        for d in dirs:
            if d != '../' and d != '/flag_in_here/':
                find_flag(url + d)

        # 匹配文件 (通常是 flag.txt 或类似)
        files = re.findall(r'href="(.+?\.txt)"', res.text)
        for f in files:
            file_url = url + f
            print(f"[*] 发现文件: {file_url}")
            print(f"[!] 内容: {requests.get(file_url).text}")
    except:
        pass


print("开始深度搜索...")
find_flag(base_url)