from imp import find_module, load_module
import global_vars
import sys
import os


def reload_plugs():
    for index in range(len(global_vars.g_plugs)):
        _, plug_obj = global_vars.g_plugs[index]
        del sys.modules[plug_obj.__name__]
        del plug_obj
    global_vars.g_plugs = walk_path_get_plugs(
        global_vars.PLUGS_PATH)


def walk_path_get_plugs(pPath):
    plugs = []
    for root, dirs, files in os.walk(pPath):
        for file in files:
            if file.endswith(".py"):
                module_name = file[:-3]
                plugs_path = os.path.join(root, file)
                if module_name not in sys.modules:
                    file_handle, file_path, dect = find_module(
                        module_name, [root])
                    try:
                        print("load module:", module_name)
                        module_obj = load_module(
                            module_name, file_handle, file_path, dect)
                        print("load module_obj:", module_obj)
                        if hasattr(module_obj, "rm_plugs_config") == False \
                                or hasattr(module_obj, "plugin_init") == False \
                                or 'author' not in module_obj.rm_plugs_config.keys() \
                                or 'description' not in module_obj.rm_plugs_config.keys() \
                                or 'version' not in module_obj.rm_plugs_config.keys() \
                                or "enable" in module_obj.rm_plugs_config.keys() and module_obj.rm_plugs_config['enable'] == False:
                            del module_obj
                            del sys.modules[module_name]
                            continue
                        print('----------------------------------')
                        print('加载模块: {} 模块作者: {} 模块介绍: {} 版本: {}'.format(
                            module_name, module_obj.rm_plugs_config['author'], module_obj.rm_plugs_config['description'], module_obj.rm_plugs_config['version']))
                        plugs.append((plugs_path, module_obj))
                        module_obj.plugin_init()
                    finally:
                        if file_handle:
                            file_handle.close()
    return plugs


def dispath_process_terminal(host, current_process, raw_log_data, json_log_data):
    for index in range(len(global_vars.g_plugs)):
        _, plug_obj = global_vars.g_plugs[index]
        if hasattr(plug_obj, "process_terminal"):
            plug_obj.process_terminal(
                current_process, host, raw_log_data, json_log_data)


def dispath_rule_new_process_create(host, current_process, raw_log_data, json_log_data):
    threat_type = global_vars.THREAT_TYPE_NONE
    for index in range(len(global_vars.g_plugs)):
        _, plug_obj = global_vars.g_plugs[index]
        if hasattr(plug_obj, "rule_new_process_create"):
            if threat_type == global_vars.THREAT_TYPE_NONE:
                threat_type = plug_obj.rule_new_process_create(
                    current_process, host, raw_log_data, json_log_data)
            else:
                plug_obj.rule_new_process_create(
                    current_process, host, raw_log_data, json_log_data)
    return threat_type


def dispath_rule_new_process_action(host, current_process, raw_log_data, json_log_data):
    threat_type = global_vars.THREAT_TYPE_NONE
    for index in range(len(global_vars.g_plugs)):
        _, plug_obj = global_vars.g_plugs[index]
        if hasattr(plug_obj, "rule_new_process_action"):
            if threat_type == global_vars.THREAT_TYPE_NONE:
                threat_type = plug_obj.rule_new_process_action(
                    current_process, host, raw_log_data, json_log_data)
            else:
                plug_obj.rule_new_process_action(
                    current_process, host, raw_log_data, json_log_data)
    return threat_type


def dispath_rule_init():
    for index in range(len(global_vars.g_plugs)):
        _, plug_obj = global_vars.g_plugs[index]
        if hasattr(plug_obj, "rule_init"):
            plug_obj.rule_init()

# 有性能问题,以后再说


def dispath_html_menu():
    plugin_menu = []
    for index in range(len(global_vars.g_plugs)):
        _, plug_obj = global_vars.g_plugs[index]
    if hasattr(plug_obj, "html_menu"):
        plugin_menu.append(plug_obj.html_menu())
    return plugin_menu


def dispath_html_draw(name):
    for index in range(len(global_vars.g_plugs)):
        _, plug_obj = global_vars.g_plugs[index]
    if hasattr(plug_obj, "html_draw"):
        if plug_obj.rm_plugs_config['html'] == name:
            return plug_obj.html_draw()
    return 'Access Denied '
