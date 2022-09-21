import json
import time

import process
import rule
import sql
import global_vars
import config
import plugin
import hash_white_list

LOG_TYPE_PROCESS_CREATE = 1
LOG_TYPE_PROCESS_ACTION = 2


def update_att_ck(process: process.Process, score, hit_name, attck_t_list):
    if process.is_white or process.chain.root_process.is_white or process.parent_process.is_white:
        score = 0
    for t in attck_t_list:
        process.set_attck(score, t, hit_name)
    # 更新命中的规则
    return global_vars.THREAT_TYPE_PROCESS


def update_threat(process: process.Process, score, rule_hit_name):
    had_threat = global_vars.THREAT_TYPE_NONE
    if process.is_white or process.chain.root_process.is_white or process.parent_process.is_white:
        return had_threat
    if score > 0:
        # 更新命中的规则
        process.set_score(score, rule_hit_name)
        had_threat = global_vars.THREAT_TYPE_PROCESS
    return had_threat


def match_threat(process: process.Process, log, log_type):
    had_threat = global_vars.THREAT_TYPE_NONE
    success_match = False
    hit_name = ''
    hit_score = 0
    is_ioa = False
    if log_type == LOG_TYPE_PROCESS_CREATE:
        success_match, is_ioa, attck_t_list, hit_score, rule_hit_name = rule.calc_score_in_create_process(
            log)
    elif log_type == LOG_TYPE_PROCESS_ACTION:
        success_match, is_ioa, attck_t_list, hit_score, rule_hit_name = rule.calc_score_in_action(
            log)
    if success_match == False:
        return had_threat, is_ioa, hit_name, hit_score
    # 匹配到了首先更新att&ck的t
    had_threat = update_att_ck(
        process, hit_score, rule_hit_name, attck_t_list)
    hit_name = rule_hit_name
    if is_ioa:
        had_threat = update_threat(
            process, hit_score, rule_hit_name)
    else:
        is_match_software, software_name, software_score = rule.match_att_ck_software(
            process.chain.attck_hit_list)
        if is_match_software:
            # 匹配到software了,设置为ioa
            had_threat = update_threat(
                process, software_score, software_name)
            hit_name = software_name
            hit_score = software_score
    #print('match_threat', process.path, is_ioa, hit_name, hit_score)
    # if had_threat != global_vars.THREAT_TYPE_NONE:
    #    print('path: {} hit_name: {} socre: {}'.format(
    #          process.path, hit_name, hit_score))
    return had_threat, is_ioa, hit_name, hit_score


def process_log(host, json_log, raw_log):
    log = json_log["data"]
    had_threat = global_vars.THREAT_TYPE_NONE
    current_process: process.Process = None
    rule_hit_name = ""
    score = 0
    chain_hash = ""
    params = ""
    user = ""
    is_ioa = False

    if json_log["action"] == "processcreate":
        pid = log["processid"]
        ppid = log["parentprocessid"]
        path = log["image"]
        params = log["commandline"]
        user = log["user"]
        hash = log["hashes"].split(",")[0].split("=")[1]

        parent_pid = log["parentprocessid"]
        parent_ppid = parent_pid
        parent_path = log["parentimage"]
        parent_params = log["parentcommandline"]
        parent_user = log["parentuser"]
        create_time = int(round(time.time() * 1000))

        if path in process.skip_process_path or path in process.skip_process_path:
            return
        parent_process: process.Process = process.get_process_by_pid(ppid)

        if hash in process.skip_md5:
            return
        if parent_process is None or parent_path in process.root_process_path:
            # build a process
            parent_process = process.Process(
                parent_pid,
                parent_ppid,
                parent_path,
                parent_params,
                create_time - 1,
                "None",
                parent_user,
                host,
            )
            is_white_list = hash in hash_white_list.g_white_list
            child = process.Process(
                pid, ppid, path, params, create_time, hash, parent_user, host, is_white_list
            )
            parent_process.parent_process = parent_process
            child.parent_process = parent_process
            chain = process.create_chain(parent_process)
            chain.add_process(child, parent_pid)
            current_process = child

            had_threat, is_ioa, rule_hit_name, score = match_threat(
                current_process, log, LOG_TYPE_PROCESS_CREATE)
        else:
            is_white_list = hash in hash_white_list.g_white_list
            child = process.Process(
                pid, ppid, path, params, create_time, hash, user, host, is_white_list
            )
            child.parent_process = parent_process
            parent_process.chain.add_process(child, ppid)
            current_process = child

            had_threat, is_ioa, rule_hit_name, score = match_threat(
                current_process, log, LOG_TYPE_PROCESS_CREATE)

        had_threat_plugin = plugin.dispath_rule_new_process_create(
            host, current_process, raw_log, json_log
        )
        if had_threat == global_vars.THREAT_TYPE_NONE:
            had_threat = had_threat_plugin
    elif json_log["action"] == "processterminal":
        pid = log["processid"]
        current_process = process.get_process_by_pid(pid)
        if current_process is not None:
            plugin.dispath_process_terminal(
                host, current_process, raw_log, json_log)
            current_process.active = False
            current_process.chain.terminate_count += 1
            if current_process.chain.terminate_count >= (
                current_process.chain.active_count - 1
            ):
                current_process.chain.active = False
                if current_process.chain.risk_score >= config.MAX_THREAT_SCORE:
                    sql.update_threat_log(
                        host,
                        current_process.chain.risk_score,
                        json.dumps(current_process.chain.operationlist),
                        json.dumps(current_process.chain.attck_hit_list),
                        current_process.chain.hash,
                        current_process.chain.get_json(),
                        global_vars.THREAT_TYPE_PROCESS,
                        True,
                    )
                process.g_ProcessChainList.remove(current_process.chain)
    elif "processid" in log:
        current_process = process.get_process_by_pid(log["processid"])
        if current_process is not None:
            log["action"] = json_log["action"]
            had_threat, is_ioa, rule_hit_name, score = match_threat(
                current_process, log, LOG_TYPE_PROCESS_ACTION)
            had_threat_plugin = plugin.dispath_rule_new_process_action(
                host, current_process, raw_log, json_log
            )
            if had_threat == global_vars.THREAT_TYPE_NONE:
                had_threat = had_threat_plugin

    if current_process is not None:
        # if current_process.path.find("f.exe") != -1:
        #    print(log)
        if current_process.chain.risk_score >= config.MAX_THREAT_SCORE:
            if had_threat == global_vars.THREAT_TYPE_PROCESS:
                current_process.chain.update_process_tree()
                threat = sql.select_threat_by_chain_id(
                    host, current_process.chain.hash, global_vars.THREAT_TYPE_PROCESS
                )
                if len(threat) == 0:
                    process_info: process.Process = None

                    if len(current_process.chain.process_list) > 1:
                        process_info = current_process.chain.process_list[1]
                    else:
                        process_info = current_process
                    info_save_data = {
                        "path": process_info.path,
                        "hash": process_info.md5,
                        "params": process_info.params,
                        "user": process_info.user,
                        "create_time": process_info.time,
                    }
                    sql.push_threat_log(
                        host,
                        current_process.chain.risk_score,
                        json.dumps(current_process.chain.operationlist),
                        json.dumps(current_process.chain.attck_hit_list),
                        current_process.chain.hash,
                        current_process.chain.get_json(),
                        global_vars.THREAT_TYPE_PROCESS,
                        json.dumps(info_save_data),
                    )
                else:
                    sql.update_threat_log(
                        host,
                        current_process.chain.risk_score,
                        json.dumps(current_process.chain.operationlist),
                        json.dumps(current_process.chain.attck_hit_list),
                        current_process.chain.hash,
                        current_process.chain.get_json(),
                        global_vars.THREAT_TYPE_PROCESS,
                        current_process.chain.active == False,
                    )
    parent_pid = 0
    target_pid = 0
    self_hash = ""
    target_image_path = ""
    target_hash = ""
    raw_json_log = json.loads(raw_log)

    if current_process is not None:
        chain_hash = current_process.chain.hash
        parent_pid = current_process.ppid
        if "TargetProcessId" in raw_json_log:
            target_process: process.Process = current_process.chain.find_process_by_pid(
                raw_json_log["TargetProcessId"]
            )
            target_pid = target_process.pid
            target_image_path = target_process.path
            target_hash = target_process.md5
        self_hash = current_process.md5
    # 以后有其他排除需求再优化
    # if json_log['action'] == 'imageload' and (json_log['data']['imageloaded'][len(json_log['data']['imageloaded']) - 4:] == '.exe' or json_log['data']['imageloaded'] in hash_white_list.g_white_dll_load_list):
    #    return

    if json_log['action'] == 'imageload':
        return

    sql.push_process_raw(
        host,
        raw_json_log,
        rule_hit_name,
        score,
        chain_hash,
        had_threat,
        parent_pid,
        target_pid,
        self_hash,
        target_image_path,
        target_hash,
        params,
        user,
    )
    '''
    for iter in process.g_ProcessChainList:
        item: process.Process = iter
        if item.risk_score >= config.MAX_THREAT_SCORE:
            item.print_process()
    '''


def process_raw_log(raw_logs: list) -> list:
    return_data = []
    process_chain_list = []

    raw_logs.sort(key=operator.attrgetter("timestamp"))

    def _get_process_chain(pid, host: str) -> process.ProcessChain:
        for iter in process_chain_list:
            chain_item: process.ProcessChain = iter
            if chain_item.host != host:
                continue
            process_item = chain_item.find_process_by_pid(pid)
            if process_item is not None:
                return chain_item
        return None

    for log in raw_logs:
        log: sql.raw_process_log = log
        pid = log.pid
        ppid = log.ppid
        path = log.path
        params = log.commandline
        user = log.user
        hash = log.hash
        create_time = log.timestamp
        host = log.host
        current_process: process.Process = None
        if path in process.skip_process_path:
            continue
        if log.action.lower() == "processcreate":

            chain = _get_process_chain(pid, host)
            if chain is not None:
                parent_process = chain.find_process_by_pid(ppid)
            else:
                parent_process = None

            if chain is None:
                # build a process chain
                current_process = process.Process(
                    pid, ppid, path, params, create_time, hash, user, host
                )
                chain = process.create_chain(current_process)
                process_chain_list.append(chain)
            else:
                current_process = process.Process(
                    pid, ppid, path, params, create_time, hash, user, host
                )
                chain.add_process(current_process, ppid)
        elif log.action.lower() == "processterminal":
            chain = _get_process_chain(pid, host)
            if chain is not None:
                current_process = chain.find_process_by_pid(pid)
                current_process.active = False
                current_process.chain.terminate_count += 1
                if (
                    current_process.chain.terminate_count
                    >= current_process.chain.active_count
                ):
                    current_process.chain.active = False
            else:
                # 不在指定时段内被创建的进程的结束事件
                continue
        else:
            chain = _get_process_chain(pid, host)
            if chain is None:
                continue
            current_process = chain.find_process_by_pid(pid)
            if current_process is None:
                continue

        # if current_process is None :
        #     breakpoint()
        start_process = current_process.chain.root_process
        start_process_info = {
            "path": start_process.path,
            "hash": start_process.md5,
            "params": start_process.params,
            "user": start_process.user,
            "create_time": start_process.time,
        }
        return_data.append(
            {
                "host": current_process.host,
                "chain_hash": current_process.chain.hash,
                "hit_rule": log.hit,
                "time": log.timestamp,
                "type": log.type,
                "risk_score": log.score,
                "id": log.id,
                "is_end": current_process.chain.active == False,
                "start_process": start_process_info,
            }
        )

    return return_data
