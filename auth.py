import hashlib
import hmac
import json
import re
import requests
import time

from encrypt.base64 import get_base64
from encrypt.xencode import get_xencode

init_url = "http://172.16.1.11/"
url_get_challenge = "http://172.16.1.11/cgi-bin/get_challenge"
url_srun_portal = "http://172.16.1.11/cgi-bin/srun_portal"

username = "XXXXXXXXXX"
password = "XXXXX"

ac_id = "1"
n = "200"
type = "1"
enc = "s" + "run" + "_bx1"

os = "Windows 10"
name = "Windows"

headers = {
    'Accept': 'text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Cookie': 'lang=zh-CN',
    'Dnt': '1',
    'Host': '172.16.1.11',
    'Pragma': 'no-cache',
    'Referer': 'http://172.16.1.11/srun_portal_pc?ac_id=1&theme=basic1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 '
                  'Safari/537.36',
    'X-Requested-With': 'XMLHttpRequest'
}


def get_local_ip():
    init_res = requests.get(init_url, headers=headers)
    ip = re.search('id="user_ip" value="(.*?)"', init_res.text).group(1)
    return ip


def hmac_md5(message, key):
    hmac_hash = hmac.new(key.encode(), message.encode(), hashlib.md5)
    return hmac_hash.hexdigest()


def analysis_jsonp(response):
    jsonp_response = response.text
    # 通过正则表达式提取JSON数据
    json_data = re.search(r'\(({.*})\)', jsonp_response).group(1)
    # 解析JSON数据
    data = json.loads(json_data)
    return data


# request get_challenge to get token
def get_token(params):
    response = requests.get(url_get_challenge, headers=headers, params=params)
    return analysis_jsonp(response)['challenge']


# 调用函数获取指定接口的IP地址
ip = get_local_ip()
time_stamp = int(time.time())
callback = "jQuery112405642667473880212_" + str(time_stamp)

get_challenge_params = {
    'callback': callback,
    'username': username,
    'ip': str(ip),
    '_': str(int(time.time()))
}

token = get_token(get_challenge_params)

info = {
    "username": username,
    "password": password,
    "ip": ip,
    "acid": ac_id,
    "enc_ver": enc
}
i = "{SRBX1}" + get_base64(get_xencode(json.dumps(info), token))

hmd5 = hmac_md5(password, token)

chkstr = token + username
chkstr += token + hmd5
chkstr += token + ac_id
chkstr += token + ip
chkstr += token + n
chkstr += token + type
chkstr += token + i

srun_portal_params = {
    'callback': callback,
    'action': 'login',
    'username': username,
    'password': '{MD5}' + hmd5,
    'ac_id': ac_id,
    'ip': ip,
    'chksum': hashlib.sha1(chkstr.encode()).hexdigest(),
    'info': i,
    'n': n,
    'type': type,
    'os': os,
    'name': name,
    'double_stack': '1',
    '_': str(int(time.time()))
}

srun_portal_response = requests.get(url_srun_portal, headers=headers, params=srun_portal_params)
srun_portal_response_json = analysis_jsonp(srun_portal_response)

if srun_portal_response_json["error"] == "ok":
    print("Succeed")
else:
    print("Failure : " + str(srun_portal_response_json))
