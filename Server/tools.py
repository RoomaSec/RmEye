import hashlib
import base64


def base64_deocde(str):
    try:
        return base64.b64decode(str).decode('utf-8')
    except:
        return ""


def get_md5(password):
    # 1- 实例化加密对象
    md5 = hashlib.md5()
    # 2- 进⾏加密操作
    md5.update(password.encode('utf-8'))
    # 3- 返回加密后的结果
    return md5.hexdigest()
