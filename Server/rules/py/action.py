rule = [
    {
        'rules': [
            'action == "processaccess" and targetimage =~ ".*lsass.exe" and grantedaccess & 0x0010 and sourceimage =~ ".*rundll32.exe"',
        ],
        'score': 300,
        'name': '已知内存加载mimikazt行为'
    },
    {
        'rules': [
            'action == "processaccess" and targetimage =~ ".*lsass.exe"',
        ],
        'score': 60,
        'name': 'LSASS高权限访问'
    },
    {
        'rules': [
            'action == "processaccess" and calltrace =~ ".*unknown.*" and not calltrace =~ ".*conpty\.node.*" and not calltrace =~ ".*java\.dll.*" and not calltrace =~ ".*appvisvsubsystems64\.dll.*" and not calltrace =~ ".*twinui\.dll.*" and not calltrace =~ ".*nativeimages.*" and not targetimage == "c:\\windows\\system32\\cmd.exe"',
        ],
        'score': 40,
        'name': '异常进程访问'
    },
    {
        'rules': [
            'action == "processaccess" and sourceimage =~ ".*office16.*" and calltrace =~ ".*kernelbase\.dll.*"',
        ],
        'score': 100,
        'name': 'office异常进程内存'
    },
    {
        'rules': [
            'action == "processaccess" and calltrace =~ ".*wshom\.ocx.*"',
            'action == "processaccess" and calltrace =~ ".*shell32\.dll.*"',
            'action == "processaccess" and calltrace =~ ".*dbgcore\.dll.*"',
            'action == "processaccess" and calltrace =~ ".*kernelbase\.dll\+de67e.*"',
            'action == "processaccess" and calltrace =~ ".*framedynos\.dll.*"',
        ],
        'score': 40,
        'name': '不正常的进程访问'
    },
    {
        'rules': [
            'action == "pipecreate" and pipename =~ ".*msagent.*"',
            'action == "pipecreate" and pipename =~ ".*msse.*"',
            'action == "pipecreate" and pipename =~ ".*postex_.*"',
            'action == "pipecreate" and pipename =~ ".*postex_ssh.*"',
            'action == "pipecreate" and pipename =~ ".*status_.*"',
        ],
        'score': 300,
        'name': '已知CobalStrike'
    },
    {
        'rules': [
            'action == "pipecreate" and pipename =~ ".*paexec.*"',
            'action == "pipecreate" and pipename =~ ".*remcom.*"',
            'action == "pipecreate" and pipename =~ ".*csexec.*"'
        ],
        'score': 300,
        'name': '已知内网横向工具'
    },
    {
        'rules': [
            'action == "pipecreate" and pipename =~ ".*lsadump.*"',
            'action == "pipecreate" and pipename =~ ".*cachedump.*"',
            'action == "pipecreate" and pipename =~ ".*wceservicepipe.*"'
        ],
        'score': 300,
        'name': '已知mimikazt内存dump'
    },
    # todo 懒得做详细的规则了.加油完善规则吧
    {
        'rules': [
            'action == "createremotethread"',
        ],
        'score': 60,
        'name': '疑似远程线程注入'
    },
    {
        'rules': [
            'action == "filecreatestreamhash"',
        ],
        'score': 100,
        'name': '文件流创建'
    },
    {
        'rules': [
            'action == "registryadd"',
            'action == "registryvalueSet"',
            'action == "registryobjectSet"',
        ],
        'score': 100,
        'name': '可疑注册表访问'
    },
    {
        'rules': [
            'action == "dnsquery"',
        ],
        'score': 30,
        'name': 'DNS解析'
    },
    {
        'rules': [
            'action == "networkconnect"',
        ],
        'score': 30,
        'name': '可疑网络链接'
    },
    {
        'rules': [
            'action == "clipboardchange"',
        ],
        'score': 30,
        'name': '可疑剪切板访问'
    },
    {
        'rules': [
            'action == "processtampering"',
        ],
        'score': 200,
        'name': '进程执行流劫持'
    },
    {
        'rules': [
            'action == "filedeletedetected"',
        ],
        'score': 50,
        'name': '删除可执行文件'
    },
    {
        'rules': [
            'action == "filecreate" and targetfilename =~ "c:\\\\\\\\windows\\\\\\\\.*"',
            'action == "filecreate" and targetfilename =~ ".*\.exe"',
            'action == "filecreate" and targetfilename =~ ".*\.cmd"',
            'action == "filecreate" and targetfilename =~ ".*\.bat"',
            'action == "filecreate" and targetfilename =~ ".*\.dll"',
        ],
        'score': 80,
        'name': '在windows目录创建可执行文件'
    },
    {
        'rules': [
            'action == "filecreate" and targetfilename =~ "c:\\\\\\\\windows\\\\\\\\.*"',
        ],
        'score': 50,
        'name': '在C盘目录创建文件'
    },
    {
        'rules': [
            'action == "filecreate" and targetfilename =~ "c:\\\\\\\\users\\\\\\\\.*"',
            'action == "filecreate" and targetfilename =~ ".*\.exe"',
            'action == "filecreate" and targetfilename =~ ".*\.cmd"',
            'action == "filecreate" and targetfilename =~ ".*\.bat"',
            'action == "filecreate" and targetfilename =~ ".*\.dll"',
        ],
        'score': 30,
        'name': '在appdata目录创建可执行文件'
    },
    {
        'rules': [
            'action == "filecreate"',
        ],
        'score': 50,
        'name': '创建可疑文件'
    }
]
