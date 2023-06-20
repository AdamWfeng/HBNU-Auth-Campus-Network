import hashlib
import hmac
import json
import os
import re
import requests
import time
import logging

from dotenv import load_dotenv

from encrypt.base64 import get_base64
from encrypt.xencode import get_xencode


def init_params():
    global init_url, url_get_challenge, url_srun_portal, ac_id, n, type, enc, operate_system, name, headers, callback

    # 初始化 url
    init_url = "http://172.16.1.11"
    url_get_challenge = init_url + "/cgi-bin/get_challenge"
    url_srun_portal = init_url + "/cgi-bin/srun_portal"

    # 固定参数
    ac_id = "1"
    n = "200"
    type = "1"
    enc = "srun_bx1"
    # 当前操作系统 AndroidOS Windows 10 Smartphones/PDAs/Tablets
    operate_system = "Windows 10"
    name = "Windows"
    # 通用请求头
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
    time_stamp = int(time.time())
    # 回调
    callback = "jQuery112405642667473880212_" + str(time_stamp)
    logging.info("callback : " + callback)


# 获取当前 ip
def get_local_ip():
    init_res = requests.get(init_url, headers=headers)
    ip = re.search('id="user_ip" value="(.*?)"', init_res.text).group(1)
    return ip


# 获取 chkstr
def get_chkstr():
    chkstr = token + username
    chkstr += token + hmd5
    chkstr += token + ac_id
    chkstr += token + ip
    chkstr += token + n
    chkstr += token + type
    chkstr += token + i
    return chkstr


# 加密密码
def hmac_md5(message, key):
    hmac_hash = hmac.new(key.encode(), message.encode(), hashlib.md5)
    return hmac_hash.hexdigest()


# 解析 jsonp 得到 json
def analysis_jsonp(response):
    jsonp_response = response.text
    # 通过正则表达式提取JSON数据
    json_data = re.search(r'\(({.*})\)', jsonp_response).group(1)
    # 解析JSON数据
    data = json.loads(json_data)
    return data


# 获取 challenge
def get_token(params):
    response = requests.get(url_get_challenge, headers=headers, params=params)
    logging.info(response.text)
    return analysis_jsonp(response)['challenge']


# 判断 ip
def adjust_ip(ip):
    first_two_octets = ip.split(".")[0:2]
    result = ".".join(first_two_octets)

    global username, password
    if result == "10.31":
        username = os.environ.get('USERNAME_STUDENT_ID')
        password = os.environ.get('PASSWORD_STUDENT_ID')
    else:
        username = os.environ.get('USERNAME_PHONE')
        password = os.environ.get('PASSWORD_PHONE')

    logging.info("当前登录用户：" + username)


# 生产签名
def encrypt_sign():
    global i, token, hmd5, ip, username
    ip = get_local_ip()
    logging.info("当前 ip : " + ip)
    adjust_ip(ip)

    get_challenge_params = {
        'callback': callback,
        'username': username,
        'ip': str(ip),
        '_': str(int(time.time()))
    }

    token = get_token(get_challenge_params)
    logging.info("token : " + token)
    hmd5 = hmac_md5(password, token)
    logging.info("hmd5 : " + hmd5)

    info = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": enc
    }

    i = "{SRBX1}" + get_base64(get_xencode(json.dumps(info), token))
    logging.info("i: " + i)


def login():
    chkstr = get_chkstr()
    chksum = hashlib.sha1(chkstr.encode()).hexdigest()
    logging.info("chksum : " + chksum)

    srun_portal_params = {
        'callback': callback,
        'action': 'login',
        'username': username,
        'password': '{MD5}' + hmd5,
        'ac_id': ac_id,
        'ip': ip,
        'chksum': chksum,
        'info': i,
        'n': n,
        'type': type,
        'os': operate_system,
        'name': name,
        'double_stack': '1',
        '_': str(int(time.time()))
    }

    srun_portal_response = requests.get(url_srun_portal, headers=headers, params=srun_portal_params)
    srun_portal_response_json = analysis_jsonp(srun_portal_response)
    logging.info("响应数据：" + str(srun_portal_response_json))

    if srun_portal_response_json["error"] == "ok":
        logging.info("登录成功")
    else:
        # 获取错误信息
        logging.info("登录失败")
        logging.info(srun_portal_response_json['error_msg'])


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                        level=logging.INFO)
    load_dotenv()
    init_params()
    encrypt_sign()
    login()
