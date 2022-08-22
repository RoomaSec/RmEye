
import json
from sqlalchemy import false
import tools
import time

skip_process_path = ['c:\\program files\\rivet networks\\smartbyte\\raps.exe',
                     'c:\\program files (x86)\\sogouinput\\11.5.0.5352\\pinyinup.exe',
                     'c:\\program files (x86)\\google\\update\\googleupdate.exe',
                     "c:\\program files\\google\\chrome\\application\\chrome.exe",
                     "d:\\programs\\microsoft vs code\\code.exe",
                     "c:\\windows\\temp\\inv4cdf_tmp\\invcol.exe",
                     "d:\\program files (x86)\\microsoft visual studio\\2019\\community\\common7\\ide\\devenv.exe",
                     "c:\\program files\\dell\\saremediation\\agent\\dellsupportassistremedationservice.exe",
                     "d:\\program files (x86)\\microsoft visual studio\\2019\\community\\common7\\ide\\extensions\\microsoft\\liveshare\\agent\\vsls-agent.exe",
                     "d:\\program files (x86)\\microsoft visual studio\\2019\\community\\common7\\servicehub\\controller\\microsoft.servicehub.controller.exe ",
                     "d:\\program files (x86)\\microsoft visual studio\\2019\\community\\vc\\tools\\msvc\\14.29.30133\\bin\\hostx86\\x64\\cl.exe",
                     "c:\\program files\\git\\mingw64\\bin\\git.exe",
                     "c:\\windows\\system32\\usoclient.exe",
                     "c:\\windows\\system32\\winlogon.exe",
                     "c:\\windows\\system32\\userinit.exe",
                     "c:\\windows\\system32\\dwm.exe",
                     "c:\\windows\\system32\\compattelrunner.exe",
                     "c:\\windows\\system32\\searchindexer.exe",
                     "c:\\windows\\system32\\searchprotocolhost.exe",
                     'c:\\windows\\system32\\runtimebroker.exe',
                     'c:\\windows\\system32\\backgroundtaskhost.exe',
                     'c:\\program files\\dell\\supportassistagent\\pcd\\supportassist\\dsapi.exe',
                     'c:\\program files\\dell\\supportassistagent\\pcd\\supportassist\\systemidlecheck.exe',
                     'c:\\program files (x86)\\microsoft\\edgeupdate\\microsoftedgeupdate.exe',
                     'c:\\program files\\common files\\mcafee\\platform\\core\\mchost.exe',
                     'c:\\windows\\system32\\mmc.exe',
                     'c:\\program files (x86)\\microsoft\\edge\\application\\101.0.1210.53\\identity_helper.exe',
                     'c:\\windows\\system32\\audiodg.exe',
                     'c:\\windows\\system32\\smartscreen.exe',
                     'c:\\program files\\rmroot\\rm_service.exe',
                     'c:\\windows\\immersivecontrolpanel\\systemsettings.exe',
                     'c:\\program files (x86)\\microsoft\\edge\\application\\msedge.exe',
                     'c:\\users\\localhost\\appdata\\local\\programs\\microsoft vs code\\code.exe',
                     'c:\\program files (x86)\\aliwangwang\\aliim.exe',
                     'c:\\program files\\git\\cmd\\git.exe',
                     'c:\\windows\\system32\\taskmgr.exe',
                     'd:\\tools\\microsoft vs code\\code.exe']
trust_list = [
    ['node.exe', 'wmic.exe', 'conhost.exe', 'powershell.exe'],
    ['tqclient.exe', 'wscavctrl.exe', 'regsvr32.exe', 'dumpuper.exe'],
    ['tqclient.exe', 'tqassetregister.exe', 'wscavctrl.exe'],
    ['code.exe', 'conhost.exe', 'bash.exe', 'powershell.exe', 'go.exe'],
    ['code.exe', 'conhost.exe', 'bash.exe', 'powershell.exe'],
    ['explorer.exe', 'thunder.exe', 'xlliveud.exe', 'aplayer.exe'],
    ['ddvdatacollector.exe',
        'atiw.exe'],
]
skip_md5 = [
    '82bcb342bce193dfe1740a13bce62e81',
    '406b23ca616e3ba6cf6033934ff073fc',
    'c9d7fa5d48de4f3b9615595c336f6bdb',
    '0cff71e27df7f00fb1f029920bd8869a',
    '249a55048751d0c77446657437c342b7',
    '452012f093d716c17c5cf93e31dd075a',
    'b8ba559709e05485ce9ee39c5a028e30',
    'cb83db7acb08ccd0370200eed9a1803b',
    'cde7786dba838941e42814f611be4fcd',
    '0b50aa0f894d6a65f3fd749cb0c6a5f2',
    '0d46559e826c8a7b5d432d0a91954ba2',
    'c07447a5b870e76bafa14ea2b39282c2',
    'b55ad19c6c110e9bf985bc8674f7bcb3',
    'c69459ddbf5c2114bfd70b170b8807e0',
    'c8e806dd1d44c6993b6d85fa77d9f89f',
    'b9dca65ce1540b8679bc9112ea100032',
    'f7017525f394d84ce1b727f50244a9ce',
    '32275787c7c51d2310b8fe2facf2a935',
    '1acf25a85a4e0a9b7da5d948ca2a69b4',
    '84244433fa7b5b80d0b7f5abd88eb8d6',
    'ebe463f5bc61aa2d44e698b6e06df705',
    'f7c71796dab2a6077458e038d1274392'
]
root_process_path = ['c:\\windows\system32\\services.exe',
                     'c:\\windows\system32\\svchost.exe',
                     'c:\\windows\\explorer.exe',
                     'c:\\windows\\system32\\wbem\\wmiprvse.exe']
g_ProcessChainList = []

# chain
# -> (pid,ppid)
# -> (pid,ppid)


class Process:
    def __init__(self, pid, ppid, path, params, time, md5, user, host):
        self.pid = pid
        self.ppid = ppid
        self.path = path
        self.params = params
        self.chain_hash = ''
        self.active = True
        self.operationlist = {}
        self.risk_score = 0
        self.terminate = False
        self.rmpid = tools.get_md5(
            str(pid) + str(ppid) + path + params + str(time))
        self.time = time
        self.rmppid = ""
        self.root_rmpid = ""
        self.md5 = md5
        self.user = user
        self.chain: ProcessChain = None
        self.host = host

    def set_chain_data(self, chain):
        self.chain = chain

    def set_chain_hash(self, chain_hash):
        self.chain_hash = chain_hash

    def set_root_rmpid(self, root_rmpid):
        self.root_rmpid = root_rmpid

    def set_rmppid(self, rmppid):
        self.rmppid = rmppid

    def set_score(self, new_score, opertion):
        if opertion not in self.operationlist:
            self.risk_score += new_score
            self.operationlist[opertion] = 1
        else:
            self.operationlist[opertion] += 1

        if opertion not in self.chain.operationlist:
            self.chain.risk_score += new_score
            self.chain.operationlist[opertion] = 1
        else:
            self.chain.operationlist[opertion] += 1


class ProcessChain:
    def __init__(self, root_process: Process):
        # 这样的话 无论几分钟读取都是固定关掉chain hash
        self.hash = tools.get_md5(root_process.rmpid + str(root_process.time))
        self.root_process_rmid = root_process.rmpid
        self.root_process = root_process
        self.active_count = 0
        self.terminate_count = 0
        self.risk_score = 0
        self.operationlist = {}
        self.process_list = []
        self.json_arrays = []
        self.active = True
        self.rpc = False
        self.rpc_process_chain = ""
        self.time = root_process.time
        self.host = root_process.host
        self.add_root_process(root_process)

    def get_operationlist(self):
        return self.operationlist

    def find_process_by_pid(self, pid):
        for iter in self.process_list:
            process_item: Process = iter
            if process_item.pid == pid and process_item.active:
                return process_item
        return None

    def add_root_process(self, root_process: Process):
        root_process.set_chain_hash(self.hash)
        root_process.set_rmppid(root_process.rmpid)
        root_process.set_chain_data(self)
        self.process_list.append(root_process)
        self.active_count += 1

    def add_process(self, new_process: Process, new_ppid):
        parent_process = self.find_process_by_pid(new_ppid)
        if parent_process is None:
            return
        new_process.set_rmppid(parent_process.rmpid)
        new_process.set_chain_hash(self.hash)
        new_process.set_root_rmpid(self.root_process_rmid)
        new_process.set_chain_data(self)
        self.process_list.append(new_process)
        self.active_count += 1

    def terminal_process(self, terminal_pid):
        process = self.find_process_by_pid(terminal_pid)
        if process is None:
            return
        process.terminate = True
        self.terminate_count += 1
        if self.terminate_count == self.active_count:
            self.active = False

    def print_node(self, node, level):
        print((" " * level) + "|--" +
              node["path"] + " 进程pid: (" + str(node["pid"]) + ") 进程ppid: (" + str(node["ppid"]) + ")进程命令行: (" + node["params"] + ") 进程hash: (" + str(node["md5"]) + ") 触发规则: " + str(node["operationlist"]) + " 进程活动:" + str(node['active']))
        for child in node["children"]:
            self.print_node(child, level + 1)

    def save_to_json(self, node):
        self.json_arrays = node

    def get_json(self):
        return json.dumps({'process_node': self.json_arrays})

    def clear_json(self):
        self.json_arrays = []

    def print_process(self):
        self.print_node(self.json_arrays, 0)

    def update_process_tree(self):
        # print('========================================================')
        # print('进程链hash: {} 进程链等级: {} 触发的行为列表 {}'.format(
        #    self.hash, self.risk_score, self.operationlist))
        pid_nodes = []
        for proc_info in self.process_list:
            node = [info for info in pid_nodes if info["rmpid"] ==
                    proc_info.rmpid]
            node = node[0] if len(node) > 0 else None

            parent_node = [
                info for info in pid_nodes if info["rmpid"] == proc_info.rmppid]
            parent_node = parent_node[0] if len(parent_node) > 0 else None

            if node is None:
                node = {
                    "path": proc_info.path,
                    "pid": proc_info.pid,
                    "ppid": proc_info.ppid,
                    "rmpid": proc_info.rmpid,
                    "rmppid": proc_info.rmppid,
                    "params": proc_info.params,
                    "operationlist": proc_info.operationlist,
                    "md5": proc_info.md5,
                    "active": proc_info.active,
                    "children": []
                }
                pid_nodes.append(node)

            if parent_node is None and proc_info.rmppid != proc_info.rmpid:
                target_info = next(
                    temp_info for temp_info in self.process_list if temp_info.rmpid == proc_info.rmppid)
                parent_node = dict()
                parent_node["active"] = target_info.active
                parent_node["path"] = target_info.path
                parent_node["ppid"] = target_info.ppid
                parent_node["pid"] = target_info.pid
                parent_node["rmpid"] = target_info.rmpid
                parent_node["rmppid"] = target_info.rmppid
                parent_node["md5"] = target_info.md5
                parent_node["params"] = target_info.params
                parent_node["operationlist"] = target_info.operationlist
                parent_node["children"] = []
                pid_nodes.append(parent_node)

            if parent_node is not None and parent_node["rmpid"] != node["rmpid"]:
                parent_node["children"].append(node)

        # find root node in pid_nodes
        root_node = next(
            info for info in pid_nodes if info["rmpid"] == self.root_process_rmid)
        #self.print_node(root_node, 0)
        self.save_to_json(root_node)


def chain_in_trust_list(chain: ProcessChain):
    # 整个进程链中如果存在(只是存在就行)这些进程就排除
    global trust_list
    global root_process_path
    is_trust = True
    for trust_process_array in trust_list:
        is_trust = True
        for trust_process in trust_process_array:
            for iter in chain.process_list:
                process: Process = iter
                if process.path.find(trust_process) == -1 and process.path not in root_process_path:
                    is_trust = False
                    break
            if is_trust == False:
                break
        if is_trust:
            break
    return is_trust


def create_chain(root_process: Process) -> ProcessChain:
    global g_ProcessChainList
    chain = ProcessChain(root_process)
    g_ProcessChainList.append(chain)
    return chain


def get_process_by_pid(pid) -> Process:
    chain_item = get_process_chain_by_pid(pid)
    if chain_item is None:
        return None
    return chain_item.find_process_by_pid(pid)


def set_process_terminal_by_pid(pid) -> None:
    chain_item = get_process_chain_by_pid(pid)
    if chain_item is None:
        return
    chain_item.terminal_process(pid)


def get_process_chain_by_pid(pid) -> ProcessChain:
    for iter in g_ProcessChainList:
        chain_item: ProcessChain = iter
        if chain_item.active:
            process_item = chain_item.find_process_by_pid(pid)
            if process_item is not None:
                return chain_item
    return None
