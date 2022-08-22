rule = [
    {
        'rules': [
            'originalfilename =~ ".*taskill.exe.*"',
            'originalfilename =~ ".*net.exe.*" and commandline =~ ".*stop.*"',
            'originalfilename =~ ".*sc.exe.*" and commandline =~ ".*config.*" and commandline =~ ".*disabled.*"',
        ],
        'score': 40,
        'name': '通过系统程序关闭进程'
    },
    {
        'rules': [
            'originalfilename =~ ".*curl.exe" or originalfilename =~ ".*wget.exe" or originalfilename =~ ".*dget.exe"'
        ],
        'score': 40,
        'name':'通过应用下载文件'
    },
    {
        'rules': [
            'image =~ ".*\.doc\.exe"',
            'image =~ ".*\.docx\.exe"',
            'image =~ ".*\.ppt\.exe"',
            'image =~ ".*\.pdf\.exe"',
            'image =~ ".*\.html\.exe"',
            'image =~ ".*\.htm\.exe"',
            'image =~ ".*\.zip\.exe"',
            'image =~ ".*\.rar\.exe"'
        ],
        'score': 30,
        'name':'启动双扩展名文件'
    },
    {
        'rules': [
            'commandline =~ ".*-k dcomlaunch.*"'
        ],
        'score': 30,
        'name':'通过DCOM启动了进程'
    },
    {
        'rules': [
            'originalfilename =~ ".*wbadmin.exe.*" and commandline =~ ".*delete.*"',
        ],
        'score': 70,
        'name': '通过wbadmin删除备份'
    },
    {
        'rules': [
            'originalfilename =~ ".*net.exe.*" and commandline =~ ".*view.*"',
        ],
        'score': 70,
        'name': '通过net进行远程系统发现'
    },
    {
        'rules': [
            'originalfilename =~ ".*fsutil.exe.*" and commandline =~ ".*deletejournal.*"',
        ],
        'score': 70,
        'name': '通过系统工具删除USN'
    },
    {
        'rules': [
            'originalfilename =~ ".*net.exe.*" and commandline =~ ".*user.*"',
        ],
        'score': 70,
        'name': '通过net进行系统用户发现'
    },
    {
        'rules': [
            'originalfilename =~ ".*schtasks.exe.*" and commandline =~ ".*create.*"',
        ],
        'score': 70,
        'name': '通过系统应用创建计划任务'
    },
    {
        'rules': [
            'originalfilename =~ ".*schtasks.exe.*" and commandline =~ ".*delete.*"',
        ],
        'score': 40,
        'name': '通过系统应用删除计划任务'
    },
    {
        'rules': [
            'originalfilename =~ ".*vssadmin.exe.*" and commandline =~ ".*create.*"',
        ],
        'score': 40,
        'name': '通过系统程序创建卷影备份'
    },
    {
        'rules': [
            'originalfilename =~ ".*todesk_service.*" or originalfilename =~ ".*sunloginclient.*" or originalfilename =~ ".*teamviewer_service.exe.*" or originalfilename =~ ".*logmein.*" or originalfilename =~ ".*dwrcs.*" or originalfilename =~ ".*aa_v3.*" or originalfilename =~ ".*screenconnect.*" or originalfilename =~ ".*tvnserver.*" or originalfilename =~ ".*vncserver.*"',
        ],
        'score': 20,
        'name': '已知远程协助程序'
    },
    {
        'rules': [
            'originalfilename =~ ".*phoenixminer.*" or originalfilename =~ ".*ccminer.*" or originalfilename =~ ".*csminer.exe.*" or originalfilename =~ ".*xmrig.*" or originalfilename =~ ".*xmr-stak.*"',
        ],
        'score': 300,
        'name': '已知挖矿程序'
    },
    {
        'rules': [
            'image =~ ".*\\\\\\\\appdata\\\\\\\\local\\\\\\\\temp\\\\\\\\.*" or image =~ ".*\\\\\\\\windows\\\\\\\\temp\\\\\\\\.*"',
        ],
        'score': 40,
        'name': '从临时文件创建进程'
    },
    {
        'rules': [
            'originalfilename =~ ".*rubeus.*" and commandline =~ ".*domain.*"',
        ],
        'score': 100,
        'name': '通过系统工具获取域登陆令牌'
    },
    {
        'rules': [
            'originalfilename =~ ".*whoami.*"',
        ],
        'score': 70,
        'name': 'whoami被执行'
    },
    {
        'rules': [
            'originalfilename =~ ".*\u202e.*"',
        ],
        'score': 100,
        'name': '伪装名字程序被执行'
    },
    {
        'rules': [
            'parentimage =~ ".*mmc.exe" and commandline =~ ".*eventvwr\.msc.*"',
        ],
        'score': 40,
        'name': '高权限进程被创建'
    },
    {
        'rules': [
            'originalfilename =~ ".*bcdedit.exe" and commandline =~ ".*recoveryenabled.*no.*"',
            'originalfilename =~ ".*bcdedit.exe" and commandline =~ ".*bootstatuspolicy.*ignoreallfailures.*"',
        ],
        'score': 80,
        'name': '通过系统工具关闭系统恢复'
    },
    {
        'rules': [
            'originalfilename =~ ".*wmic.exe" and commandline =~ ".*useraccount.*"',
        ],
        'score': 70,
        'name': '通过wmic进行系统用户发现'
    },
    {
        'rules': [
            'originalfilename =~ ".*wmic.exe" and commandline =~ ".*startup.*"',
        ],
        'score': 70,
        'name': '通过wmic查看系统启动项'
    },
    {
        'rules': [
            'originalfilename =~ ".*wmic.exe" and commandline =~ ".*share.*"',
        ],
        'score': 70,
        'name': '通过wmic查看系统共享'
    },
    {
        'rules': [
            'originalfilename =~ ".*wmic.exe" and commandline =~ ".*shadowcopy.*" and commandline =~ ".*delete.*"',
        ],
        'score': 70,
        'name': 'wmic删除卷影备份'
    },
    {
        'rules': [
            'originalfilename =~ ".*vssadmin.exe" and commandline =~ ".*shadows.*" and commandline =~ ".*delete.*"',
        ],
        'score': 70,
        'name': 'vssadmin删除卷影备份'
    },
    {
        'rules': [
            'originalfilename =~ ".*tasklist.exe"',
        ],
        'score': 50,
        'name': '通过tasklist查看系统信息'
    },
    {
        'rules': [
            'originalfilename =~ ".*systeminfo.exe"',
        ],
        'score': 70,
        'name': '通过systeminfo查看系统信息'
    },
    {
        'rules': [
            'originalfilename =~ ".*query.exe"',
        ],
        'score': 70,
        'name': '通过query进行系统用户发现'
    },
    {
        'rules': [
            'originalfilename =~ ".*net.exe" and commandline =~ ".*domain.*"',
            'originalfilename =~ ".*net.exe" and commandline =~ ".*view.*"',
            'originalfilename =~ ".*net.exe" and commandline =~ ".*workstation.*"'
        ],
        'score': 70,
        'name': '通过net进行本地系统用户发现'
    },
    {
        'rules': [
            'originalfilename =~ ".*setspn.exe"',
        ],
        'score': 70,
        'name': '通过setspn进行本地系统用户发现'
    },
    {
        'rules': [
            'originalfilename =~ ".*netsh.exe" and commandline =~ ".*firewall.*"',
        ],
        'score': 70,
        'name': '通过netsh关闭防火墙'
    },
    {
        'rules': [
            'originalfilename =~ ".*cmd.exe" and commandline =~ ".*ipconfig.*"',
        ],
        'score': 80,
        'name': 'cmd启动ipconfig'
    },
    {
        'rules': [
            'originalfilename =~ ".*cmd.exe" and commandline =~ ".*net.*"',
        ],
        'score': 60,
        'name': 'cmd启动net'
    },
    {
        'rules': [
            'originalfilename =~ ".*netstat.exe"',
        ],
        'score': 40,
        'name': 'netstat被运行'
    },
    {
        'rules': [
            'originalfilename =~ ".*ping.exe"',
        ],
        'score': 40,
        'name': 'ping被运行'
    },
    {
        'rules': [
            'originalfilename =~ ".*ipconfig.exe"',
        ],
        'score': 40,
        'name': 'ipconfig被运行'
    },
    {
        'rules': [
            'originalfilename =~ ".*attrib.exe"',
        ],
        'score': 40,
        'name': 'attrib被运行'
    },
    {
        'rules': [
            'originalfilename =~ ".*PSEXESVC.exe"',
        ],
        'score': 100,
        'name': 'PSEXESVC内网横向移动'
    },
    {
        'rules': [
            'originalfilename =~ "\\\\\\\\.*\\\\\\C\$.*"',
        ],
        'score': 100,
        'name': 'SMB共享启动进程'
    },
    {
        'rules': [
            'commandline =~ ".*__\d{10}\."',
            'originalfilename =~ ".*wmi_share.exe"',
        ],
        'score': 100,
        'name': 'wmic内网横向移动被触发'
    },
    {
        'rules': [
            'originalfilename =~ ".*icacls.exe"',
        ],
        'score': 40,
        'name': 'icacls被运行'
    },
    {
        'rules': [
            'originalfilename =~ "\\\\\\.*" and parentimage =~ ".*services.exe"',
        ],
        'score': 100,
        'name': '远程服务被创建'
    },
    {
        'rules': [
            'parentimage =~ ".*services.exe"',
        ],
        'score': 30,
        'name': '从服务创建的进程'
    },
    {
        'rules': [
            'originalfilename =~ ".*wscript.exe"',
            'originalfilename =~ ".*cscript.exe"',
        ],
        'score': 40,
        'name': '脚本程序被运行'
    },
    {
        'rules': [
            'originalfilename =~ ".*mofcomp.exe.*"'
        ],
        'score': 80,
        'name':'注册WMI订阅'
    },
    {
        'rules': [
            'originalfilename =~ ".*csc.exe.*"'
        ],
        'score': 80,
        'name':'.NET编译器被启动'
    },
    {
        'rules': [
            'originalfilename =~ ".*cmdkey.exe.*"'
        ],
        'score': 100,
        'name':'通过系统应用查询本机账户'
    },
    {
        'rules': [
            'originalfilename =~ ".*adfind.exe.*"'
        ],
        'score': 80,
        'name':'通过系统程序发现域信息'
    },
    # 这些是保底规则 必须放到最底下才匹配
    {
        'rules': [
            'originalfilename =~ ".*cmd.exe"'
        ],
        'score': 30,
        'name':'执行CMD命令'
    },
    {
        'rules': [
            'originalfilename =~ ".*chcp.com"'
        ],
        'score': 30,
        'name':'执行chcp.com'
    },
    {
        'rules': [
            'originalfilename =~ ".*wmic.exe.*"'
        ],
        'score': 80,
        'name':'执行wmic'
    },
    {
        'rules': [
            'originalfilename =~ ".*rundll32.exe.*"'
        ],
        'score': 20,
        'name':'通过rundll32启动进程'
    },
    {
        'rules': [
            'originalfilename =~ ".*certutil.exe"',
            'originalfilename =~ ".*curl.exe"',
            'originalfilename =~ ".*powershell.exe" and commandline =~ ".*invoke-webrequest.*"'
        ],
        'score': 80,
        'name':'通过系统命令下载文件'
    },
    {
        'rules': [
            'originalfilename =~ ".*powershell.exe"'
        ],
        'score': 80,
        'name':'Powershell被执行'
    },
]
