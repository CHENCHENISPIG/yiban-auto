import datetime
import hashlib
import json
import random
import time
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
import base64
import uuid

user = '账号'
pwd = '密码'
address = {
    "name": '详细地址',
    "location": '经纬度，百度一下，你就知道',
    "address": '详细地址，同name'
}
login_url = 'https://m.yiban.cn/api/v4/passport/login'
xbh_Certification_url = 'https://f.yiban.cn/iapp/index'
get_list_url = 'https://api.uyiban.com/officeTask/client/index/uncompletedList'
get_home_url = 'https://api.uyiban.com/base/c/auth/yiban'
qd_info_url = 'https://api.uyiban.com/officeTask/client/index/detail'
sub_url = 'https://api.uyiban.com/workFlow/c/my/apply'
person = requests.session()
access_token = ''
headers = {
    "Origin": "https://c.uyiban.com",
    "User-Agent": "Yiban",
    "AppVersion": "5.0"
}
CSRF = '666666'
cookies = {"csrf_token": CSRF}


def myRequest(url, method='get', cookie={}, header={}, allow_redirects=True, **kwargs):
    params = kwargs.get("params")
    data = kwargs.get("data")
    headers.update(header)
    cookies.update(cookie)
    if method == 'get':
        res = person.get(
            url=url,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects
        )
    else:
        res = person.post(
            url=url,
            data=data,
            params=params,
            headers=headers,
            cookies=cookies,
            allow_redirects=allow_redirects
        )
    return res


def en_subdata(data):
    AES_KEY = '2knV5VGRTScU7pOq'
    AES_IV = 'UmNWaNtM0PUdtFCs'
    aes_key = bytes(AES_KEY, 'utf-8')
    aes_iv = bytes(AES_IV, 'utf-8')
    data = bytes(data, 'utf-8')
    data = aes_pkcs7padding(data)
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted = base64.b64encode(cipher.encrypt(data))
    return base64.b64encode(encrypted)


def aes_pkcs7padding(data):
    bs = AES.block_size
    padding = bs - len(data) % bs
    padding_text = bytes(chr(padding) * padding, 'utf-8')
    return data + padding_text


def en_rsa2(pwd):
    PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
    MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6aTDM8BhCS8O0wlx2KzA
    Ajffez4G4A/QSnn1ZDuvLRbKBHm0vVBtBhD03QUnnHXvqigsOOwr4onUeNljegIC
    XC9h5exLFidQVB58MBjItMA81YVlZKBY9zth1neHeRTWlFTCx+WasvbS0HuYpF8+
    KPl7LJPjtI4XAAOLBntQGnPwCX2Ff/LgwqkZbOrHHkN444iLmViCXxNUDUMUR9bP
    A9/I5kwfyZ/mM5m8+IPhSXZ0f2uw1WLov1P4aeKkaaKCf5eL3n7/2vgq7kw2qSmR
    AGBZzW45PsjOEvygXFOy2n7AXL9nHogDiMdbe4aY2VT70sl0ccc4uvVOvVBMinOp
    d2rEpX0/8YE0dRXxukrM7i+r6lWy1lSKbP+0tQxQHNa/Cjg5W3uU+W9YmNUFc1w/
    7QT4SZrnRBEo++Xf9D3YNaOCFZXhy63IpY4eTQCJFQcXdnRbTXEdC3CtWNd7SV/h
    mfJYekb3GEV+10xLOvpe/+tCTeCDpFDJP6UuzLXBBADL2oV3D56hYlOlscjBokNU
    AYYlWgfwA91NjDsWW9mwapm/eLs4FNyH0JcMFTWH9dnl8B7PCUra/Lg/IVv6HkFE
    uCL7hVXGMbw2BZuCIC2VG1ZQ6QD64X8g5zL+HDsusQDbEJV2ZtojalTIjpxMksbR
    ZRsH+P3+NNOZOEwUdjJUAx8CAwEAAQ==
    -----END PUBLIC KEY-----
    '''
    cipher = PKCS1_v1_5.new(RSA.importKey(PUBLIC_KEY))
    cipher_text = base64.b64encode(cipher.encrypt(bytes(pwd, encoding="utf8")))
    return cipher_text.decode("utf-8")


#  登陆

def login(user, pwd):
    # 密码rsa加密
    rsa_pwd = en_rsa2(pwd)
    uu = str(uuid.uuid4())
    hl = hashlib.md5()
    hl.update(uu.encode(encoding='utf-8'))
    sig = hl.hexdigest()[0: 16]
    login_data = {
        'device': 'samsung:SM-G9750',
        'v': '5.0.8',
        'password': rsa_pwd,
        'token': '',
        'mobile': user,
        'ct': 2,
        'identify': '010045026872666',
        'sversion': '22',
        'apn': 'wifi',
        'app': '1',
        'authCode': '',
        'sig': sig
    }
    req = myRequest(login_url, data=login_data, method='post').json()
    if req['response'] == 100:
        print('login sucess...')
        global access_token
        access_token = req['data']['access_token']
    else:
        raise Exception('login error, account or password is wrong')


#  校本化认证
def xbh_Certification():
    certification = myRequest(xbh_Certification_url, params={'act': 'iapp7463'}, cookie={'loginToken': access_token},
                              allow_redirects=False)
    verifyRequest = certification.headers.get('Location').split('verify_request=')[1].split("&")[0]
    r = myRequest(get_home_url, params={"verifyRequest": verifyRequest, "CSRF": CSRF})


# 获取签到列表
def get_qd_list():
    today = datetime.datetime.today() + datetime.timedelta(hours=8 - int(time.strftime('%z')[0:3]))
    qd_list = myRequest(get_list_url, params={
        'StartTime': (today + datetime.timedelta(days=-14)).strftime('%Y-%m-%d'),
        'EndTime': "%d-%02d-%02d 23:59" % (today.year, today.month, today.day),
        'CSRF': CSRF
    }).json()['data']
    if len(qd_list) == 0:
        print('list is null')
        return
    else:
        for x in qd_list:
            task_detail = myRequest(qd_info_url, params={'TaskId': x['TaskId'], 'CSRF': CSRF}).json()['data']
            extend = {
                "TaskId": task_detail["Id"],
                "title": "任务信息",
                "content": [
                    {"label": "任务名称", "value": task_detail["Title"]},
                    {"label": "发布机构", "value": task_detail["PubOrgName"]},
                    {"label": "发布人", "value": task_detail["PubPersonName"]}
                ]
            }
            data_form = {
                "c77d35b16fb22ec70a1f33c315141dbb": "%d-%02d-%02d %02d:%02d" % (
                    today.year, today.month, today.day, today.hour, today.minute),
                "2d4135d558f849e18a5dcc87b884cce5": str(round(random.uniform(35.2, 35.8), 1)),
                "27a2a4cdf16a8c864daca54a00c4db03": address
            }
            submit_data = {}
            submit_data['WFId'] = task_detail['WFId']
            submit_data['Extend'] = json.dumps(extend, ensure_ascii=False)
            submit_data['Data'] = json.dumps(data_form, ensure_ascii=False)
            postData = json.dumps(submit_data, ensure_ascii=False)
            sub_data = myRequest(sub_url, method='post', params={'CSRF': CSRF},
                                 data={'Str': en_subdata(postData)}).json()
            if sub_data['code'] != 0:
                raise Exception('submit error')


if __name__ == '__main__':
    login(user, pwd)
    xbh_Certification()
    get_qd_list()
