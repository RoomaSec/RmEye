import global_vars
import process
#import yara

rm_plugs_config = {
    "enable": True,
    "author": "huoji",
    "description": "基于进程链的uac提权检测",
    "version": "0.0.1"
}


def intergritylevel_to_int(str_name):
    if str_name == 'high':
        return 3
    elif str_name == 'medium':
        return 2
    return 1


def rule_new_process_create(current_process: process.Process, host, raw_log_data, json_log_data):
    if 'integritylevel' in json_log_data['data']:
        integritylevel = intergritylevel_to_int(
            json_log_data['data']['integritylevel'])
        current_process.plugin_var['uac_flag'] = integritylevel

        if 'uac_flag' not in current_process.chain.root_process.plugin_var:
            current_process.chain.root_process.plugin_var['uac_flag'] = integritylevel
        if integritylevel > current_process.chain.root_process.plugin_var['uac_flag']:
            print('[uac bypass detect] detect uac bypass in process chain {}'.format(
                current_process.path))
            current_process.chain.root_process.plugin_var['uac_flag'] = integritylevel
            current_process.set_score(300, "[UAC提权]进程权限等级变动")
            return global_vars.THREAT_TYPE_PROCESS
        # print('process chain: {} path: {} level: {} log level: {}'.format(
        #    current_process.chain_hash, current_process.path, integritylevel, current_process.chain.root_process.plugin_var['uac_flag']))
    return global_vars.THREAT_TYPE_NONE


def rule_new_process_action(current_process, host, raw_log_data, json_log_data):
    return global_vars.THREAT_TYPE_NONE


def rule_init():
    print('[helloworld plugin] rule init')


def plugin_init():
    print('[helloworld plugin] plugin init')
