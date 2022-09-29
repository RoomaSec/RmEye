import requests
import global_vars
import process
import hash_white_list
from threading import Thread
# 引入sqlalchemy中相关模块
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import time
from sqlalchemy import create_engine, MetaData, Table

STATUS_CLEAN = -1
STATUS_UNK = 0
STATUS_VIRUS = 1

# 自己去https://metadefender.opswat.com/注册一个申请一个免费的api
# 我这边的api有每日最大使用限制!!!!!!用的人多了很有可能会被封掉
rm_plugs_config = {
    "enable": True,
    "author": "huoji",
    "description": "opswat ioc检测扩展插件",
    "version": "0.0.1",
    # !自己去https://metadefender.opswat.com/注册一个申请一个免费的api!
    # !自己去https://metadefender.opswat.com/注册一个申请一个免费的api!
    # !自己去https://metadefender.opswat.com/注册一个申请一个免费的api!
    "apikey": "010d4868aef799750e2828fdf17a4d98",
}
g_engine = None
g_opswat_cache_hashes_table = None
g_opswat_cache_hashes_ins = None
g_opswat_cache_ip_addr_table = None
g_opswat_cache_ip_addr_ins = None
g_sql_base = declarative_base()
g_check_hashes_list = {}
g_check_ip_list = {}


class opswat_cache_hashes(g_sql_base):
    __tablename__ = "opswat_cache_hashs"
    # 定义各字段
    id = Column(Integer, primary_key=True)
    # 主机ip
    host = Column(String)
    # 进程路径
    path = Column(String)
    # hash
    hash = Column(String)
    # 时间戳
    timestamp = Column(Integer)
    # 信息 -1绿色 0 未知 1病毒
    status = Column(Integer)

    def __str__(self):
        return self.id


class opswat_cache_ip_addr(g_sql_base):
    __tablename__ = "opswat_cache_ip_addr"
    # 定义各字段
    id = Column(Integer, primary_key=True)
    # 主机ip
    host = Column(String)
    # 进程路径
    path = Column(String)
    # ip_addr
    ip_addr = Column(String)
    # 时间戳
    timestamp = Column(Integer)
    # 信息 -1绿色 0 未知 1病毒
    status = Column(Integer)

    def __str__(self):
        return self.id


def search_ip_in_opswat(ip_addr):
    request_obj = requests.Session()
    request_obj.trust_env = False
    url = "https://api.metadefender.com/v4/ip/" + ip_addr
    headers = {
        "apikey": rm_plugs_config['apikey'],
    }
    status = STATUS_UNK
    try:
        response = request_obj.get(
            url, headers=headers, timeout=30, verify=True)
        if response.status_code == 200:
            json_data = response.json()
            if 'lookup_results' in json_data:
                if json_data['lookup_results']['detected_by'] >= 1:
                    status = STATUS_VIRUS
                else:
                    status = STATUS_CLEAN
    except:
        pass
    return status


def search_hash_in_opswat(hash):
    request_obj = requests.Session()
    request_obj.trust_env = False
    url = "https://api.metadefender.com/v4/hash/" + hash
    headers = {
        "apikey": rm_plugs_config['apikey'],
    }
    status = STATUS_UNK
    try:
        response = request_obj.get(
            url, headers=headers, timeout=30, verify=True)
        if response.status_code == 200:
            json_data = response.json()
            if 'scan_all_result_i' in json_data['scan_results']:
                if json_data['scan_results']['total_detected_avs'] > 5:
                    status = STATUS_VIRUS
                else:
                    status = STATUS_CLEAN
    except:
        pass
    return status


def async_call(fn):
    def wrapper(*args, **kwargs):
        Thread(target=fn, args=args, kwargs=kwargs).start()

    return wrapper


def query_hash(pHash):
    global g_opswat_cache_hashes_table
    sql_session = sessionmaker(bind=g_engine)
    hash_info = sql_session().query(
        g_opswat_cache_hashes_table).filter_by(hash=pHash).first()
    sql_session().close()
    if hash_info is None:
        return False, None
    last_time = hash_info[4]
    status = hash_info[5]
    is_need_update = False
    # 10 day
    if time.time() - last_time > 864000:
        is_need_update = True
    return is_need_update, status


def query_ipaddr(pIp):
    global g_opswat_cache_ip_addr_table
    sql_session = sessionmaker(bind=g_engine)
    ip_info = sql_session().query(
        g_opswat_cache_ip_addr_table).filter_by(ip_addr=pIp).first()
    sql_session().close()
    if ip_info is None:
        return False, None
    last_time = ip_info[4]
    status = ip_info[5]
    is_need_update = False
    # 10 day
    if time.time() - last_time > 864000:
        is_need_update = True
    return is_need_update, status


def update_ip_addr(ip_addr, net_status):
    global g_opswat_cache_ip_addr_table
    global g_engine
    conn = g_engine.connect()
    update = (
        g_opswat_cache_ip_addr_table.update()
        .values(status=net_status,
                timestamp=int(round(time.time() * 1000)))
        .where(g_opswat_cache_ip_addr_table.c.ip_addr == ip_addr)
    )
    result = conn.execute(update)
    conn.close()
    return result


def update_hash(hash, new_status):
    global g_opswat_cache_hashes_table
    global g_engine
    conn = g_engine.connect()
    update = (
        g_opswat_cache_hashes_table.update()
        .values(
            status=new_status,
            timestamp=int(round(time.time() * 1000))
        )
        .where(
            g_opswat_cache_hashes_table.columns.hash == hash
        )
    )
    result = conn.execute(update)
    conn.close()
    return result


def push_ip_addr(host, path, ip_addr, status):
    global g_opswat_cache_ip_addr_table
    global g_engine
    conn = g_engine.connect()
    insert = g_opswat_cache_ip_addr_table.insert().values(
        host=host,
        path=path,
        ip_addr=ip_addr,
        status=status,
        timestamp=int(round(time.time() * 1000))
    )
    result = conn.execute(insert)
    conn.close()
    return result


def push_hash(
    host,
    path,
    hash,
    status
):
    global g_engine
    global g_opswat_cache_hashes_table
    global g_opswat_cache_hashes_ins
    ins = g_opswat_cache_hashes_ins.values(
        host=host,
        path=path,
        hash=hash,
        status=status,
        timestamp=int(round(time.time() * 1000))
    )
    # 连接引擎
    conn = g_engine.connect()
    # 执行语句
    result = conn.execute(ins)
    conn.close()
    # print(raw_json)
    return result


@async_call
def asnyc_check_ip(current_process: process.Process, host, ip):
    global g_check_ip_list
    if ip in g_check_ip_list and g_check_ip_list[ip] != -2:
        return g_check_ip_list[ip]
    g_check_ip_list[ip] = STATUS_UNK
    cache_need_update, cache_status = query_ipaddr(ip)
    if cache_need_update or cache_status is None:
        create_one = False
        if cache_status is None:
            create_one = True
        cache_status = search_ip_in_opswat(ip)
        if create_one:
            push_ip_addr(host, current_process.path, ip, cache_status)
        else:
            push_ip_addr(ip, cache_status)

    if cache_status == STATUS_VIRUS:
        current_process.set_score(666, "恶意网络链接IP:{}".format(ip))
    elif cache_status == STATUS_UNK:
        # crowdstrike: 这个我熟
        current_process.set_score(10, "低信誉ip链接:{}".format(ip))
    g_check_ip_list[ip] = cache_status


@async_call
def asnyc_check_domian(current_process: process.Process, host, domain):
    pass


@async_call
def asnyc_check_hash(current_process: process.Process, host):
    global g_check_hashes_list
    hash = current_process.md5
    if hash in g_check_hashes_list and g_check_hashes_list[hash] != -2:
        return g_check_hashes_list[hash]
    g_check_hashes_list[hash] = STATUS_UNK
    cache_need_update, cache_status = query_hash(hash)
    if cache_need_update or cache_status is None:
        create_one = False
        if cache_status is None:
            create_one = True
        cache_status = search_hash_in_opswat(hash)
        if create_one:
            push_hash(host, current_process.path, hash, cache_status)
        else:
            update_hash(hash, cache_status)

    if cache_status == STATUS_VIRUS:
        current_process.set_score(666, "恶意软件")
    elif cache_status == STATUS_UNK:
        # crowdstrike: 这个我熟
        current_process.set_score(10, "低信誉文件")
    g_check_hashes_list[hash] = cache_status


def rule_new_process_create(current_process: process.Process, host, raw_log_data, json_log_data):
    global g_check_hashes_list
    if rm_plugs_config['apikey'] != "" is not None and hash_white_list.check_in_while_list(current_process) == False:
        g_check_hashes_list[current_process.md5] = -2
        asnyc_check_hash(current_process, host)
    return global_vars.THREAT_TYPE_NONE


def rule_new_process_action(current_process: process.Process, host, raw_log_data, json_log_data):
    global g_check_ip_list
    if rm_plugs_config['apikey'] != "" is not None and json_log_data['action'] == 'networkconnect' and hash_white_list.check_in_while_list(current_process) == False:
        # print('network connect{}'.format(
        #    json_log_data['data']['destinationip']))
        ip_addr = json_log_data['data']['destinationip']
        if len(ip_addr) >= 5:
            g_check_ip_list[json_log_data['data']['destinationip']] = -2
            asnyc_check_ip(current_process, host,
                           json_log_data['data']['destinationip'])
    return global_vars.THREAT_TYPE_NONE


def rule_init():
    pass


def plugin_init():
    global g_engine
    global g_metadata
    global g_sql_base
    global g_opswat_cache_hashes_table
    global g_opswat_cache_hashes_ins
    global g_opswat_cache_ip_addr_table
    global g_opswat_cache_ip_addr_ins
    print('opswat ioc检测扩展插件 2022/9/23 by huoji')

    if rm_plugs_config['apikey'] != "":
        g_engine = create_engine(
            "sqlite:///plugin_opswat_cache.db?check_same_thread=False", echo=False)
        g_sql_base.metadata.create_all(g_engine)
        g_metadata = MetaData(g_engine)
        g_opswat_cache_hashes_table = Table(
            "opswat_cache_hashs", g_metadata, autoload=True)
        g_opswat_cache_hashes_ins = g_opswat_cache_hashes_table.insert()
        g_opswat_cache_ip_addr_table = Table(
            "opswat_cache_ip_addr", g_metadata, autoload=True)
        g_opswat_cache_ip_addr_ins = g_opswat_cache_ip_addr_table.insert()
    else:
        print('opswat ioc检测扩展插件未配置apikey,自己去metadefender.opswat.com申请一个!')
