import global_vars
import process

rm_plugs_config = {
    "enable": True,
    "author": "huoji",
    "description": "检测mimikatz",
    "version": "0.0.1"
}

mimikatz_dll_list = [
    'c:\\windows\\system32\\advapi32.dll',
    'c:\\windows\\system32\\crypt32.dll',
    'c:\\windows\\system32\\cryptdll.dll',
    'c:\\windows\\system32\\gdi32.dll',
    'c:\\windows\\system32\\imm32.dll',
    'c:\\windows\\system32\\msasn1.dll',
    'c:\\windows\\system32\\msvcrt.dll',
    'c:\\windows\\system32\\rpcrt4.dll',
    'c:\\windows\\system32\\rsaenh.dll',
    'c:\\windows\\system32\\samlib.dll',
    'c:\\windows\\system32\\sechost.dll',
    'c:\\windows\\system32\\secur32.dll',
    'c:\\windows\\system32\\shell32.dll',
    'c:\\windows\\system32\\shlwapi.dll',
    'c:\\windows\\system32\\sspicli.dll',
    'c:\\windows\\system32\\user32.dll',
    'c:\\windows\\system32\\vaultcli.dll',
]


def rule_new_process_create(current_process: process.Process, host, raw_log_data, json_log_data):
    # 服务端提供了一个 plugin_var 变量用于存放当前进程插件的上下文
    if current_process.path != 'c:\\windows\\system32\\wbem\\wmic.exe' and current_process.parent_process.path != 'c:\\windows\\system32\\svchost.exe' and current_process.path != 'c:\\windows\\system32\\svchost.exe':
        current_process.plugin_var['mimikatz_matched_num'] = 0
        current_process.plugin_var['mimikatz_detected'] = False
    return global_vars.THREAT_TYPE_NONE


def rule_new_process_action(current_process: process.Process, host, raw_log_data, json_log_data):
    global mimikatz_dll_list
    # 如果日志的action是imageload(dll加载)
    if 'mimikatz_detected' in current_process.plugin_var and json_log_data['action'] == 'imageload' and current_process.plugin_var['mimikatz_detected'] == False:
        # 把日志中的dll路径取出来
        dll_path = json_log_data['data']['imageloaded']
        # 如果dll的路径在mimikatz的路径里面,进程上下文+1
        if dll_path in mimikatz_dll_list:
            current_process.plugin_var['mimikatz_matched_num'] += 1
        if current_process.plugin_var['mimikatz_matched_num'] >= len(mimikatz_dll_list):
            current_process.set_score(300, "[mimikatz]检测到疑似mimikatz进程")
            current_process.plugin_var['mimikatz_detected'] = True
            return global_vars.THREAT_TYPE_PROCESS
    return global_vars.THREAT_TYPE_NONE


def rule_init():
    pass


def plugin_init():
    print('mimikatz检测插件 2022/9/5 by huoji')
