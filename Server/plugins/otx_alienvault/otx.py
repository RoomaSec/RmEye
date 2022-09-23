import global_vars
import process

rm_plugs_config = {
    "enable": True,
    "author": "huoji",
    "description": "otx alienvault ioc检测扩展插件",
    "version": "0.0.1"
}


def rule_new_process_create(current_process: process.Process, host, raw_log_data, json_log_data):
    return global_vars.THREAT_TYPE_NONE


def rule_new_process_action(current_process: process.Process, host, raw_log_data, json_log_data):
    return global_vars.THREAT_TYPE_NONE


def rule_init():
    pass


def plugin_init():
    print('otx alienvault ioc检测扩展插件 2022/9/23 by huoji')
