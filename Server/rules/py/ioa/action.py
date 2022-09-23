rule = [
    {
        'rules': [
            'action == "processaccess" and targetimage =~ ".*lsass.exe"',
        ],
        'attck_hit':['T1003'],
        'score': 100,
        'name': 'OS Credential Dumping: LSASS Memory'
    },
    {
        'rules': [
            'action == "processaccess" and targetimage =~ ".*lsass.exe" and grantedaccess & 0x0010 and sourceimage =~ ".*rundll32.exe"',
        ],
        'attck_hit':['T1003.002'],
        'score': 100,
        'name': '已知内存加载mimikazt行为'
    },
    {
        'rules': [
            'action == "processaccess" and sourceimage =~ ".*office16.*" and calltrace =~ ".*kernelbase\.dll.*"',
        ],
        'attck_hit':['T1003.002'],
        'score': 60,
        'name': 'office异常进程内存'
    },
    {
        'rules': [
            'action == "pipecreate" and pipename =~ ".*msagent.*"',
            'action == "pipecreate" and pipename =~ ".*msse.*"',
            'action == "pipecreate" and pipename =~ ".*postex_.*"',
            'action == "pipecreate" and pipename =~ ".*postex_ssh.*"',
            'action == "pipecreate" and pipename =~ ".*status_.*"',
        ],
        'attck_hit':['T1003.002'],
        'score': 100,
        'name': '已知CobalStrike'
    },
    {
        'rules': [
            'action == "pipecreate" and pipename =~ ".*paexec.*"',
            'action == "pipecreate" and pipename =~ ".*remcom.*"',
            'action == "pipecreate" and pipename =~ ".*csexec.*"'
        ],
        'attck_hit':['T1003.002'],
        'score': 100,
        'name': '已知内网横向工具'
    },
    {
        'rules': [
            'action == "pipecreate" and pipename =~ ".*lsadump.*"',
            'action == "pipecreate" and pipename =~ ".*cachedump.*"',
            'action == "pipecreate" and pipename =~ ".*wceservicepipe.*"'
        ],
        'attck_hit':['T1003.002'],
        'score': 100,
        'name': '已知mimikazt内存dump'
    },
]
