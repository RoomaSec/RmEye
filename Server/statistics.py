import time
import sql

all_log_num = 0
host_list = {}
last_update_time = 0


def get_host_list():
    global host_list
    return host_list


def update_host_list(host):
    global host_list
    host_list[host] = 1


def update_loged_num(host):
    global all_log_num
    global host_list
    global last_update_time

    all_log_num += 1
    if host not in host_list:
        host_list[host] = {
            'last_update_time': time.time(),
            'log_num': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'all_log_num': 0
        }
    host_list[host]['all_log_num'] += 1
    if time.time() - host_list[host]['last_update_time'] > 60:
        host_list[host]['last_update_time'] = time.time()
        host_list[host]['log_num'].append(host_list[host]['all_log_num'])
        host_list[host]['all_log_num'] = 0
        if len(host_list[host]['log_num']) > 10:
            del host_list[host]['log_num'][0]


def get_loged_num():
    global all_log_num
    if all_log_num > 30000000:
        all_log_num = 0
    return all_log_num


def get_threat_nums():
    # sqlite的count啥的还不如自己查出来自己统计
    host_list = get_host_list()
    # 懒得做了...
    # last_logs = sql.query_last_raw_process_log(10)
    # for iter in last_logs:
    # print(last_logs)
    threat_datas = sql.query_all_threat_log(-1)
    return_data = {"all": len(threat_datas), "confirm": 0,
                   "ingore": 0, "working": 0, "all_log_num": get_loged_num(), "host_list": host_list}
    for iter in threat_datas:
        if iter[9] == 1:
            return_data["confirm"] += 1
        elif iter[9] == 2:
            return_data["ingore"] += 1
        if iter[7] == 0:
            return_data["working"] += 1
    return return_data
