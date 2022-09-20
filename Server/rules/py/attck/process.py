rule = [
    {
        'rules': [
            'originalfilename =~ ".*taskill.exe.*"',
            'originalfilename =~ ".*net.exe.*" and commandline =~ ".*stop.*"',
            'originalfilename =~ ".*sc.exe.*" and commandline =~ ".*config.*" and commandline =~ ".*disabled.*"',
        ],
        'attck_hit':['T1489'],
        'score': 30,
        'name': 'Service Stop'
    },
    {
        'rules': [
            'originalfilename =~ ".*curl.exe" or originalfilename =~ ".*wget.exe" or originalfilename =~ ".*dget.exe"',
            'originalfilename =~ ".*certutil.exe"',
            'originalfilename =~ ".*powershell.exe" and commandline =~ ".*invoke-webrequest.*"'
        ],
        'attck_hit':['T1105'],
        'score': 30,
        'name':'Ingress Tool Transfer'
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
        'attck_hit':['T1036.007'],
        'score': 60,
        'name':'Masquerading: Double File Extension'
    },
    {
        'rules': [
            'commandline =~ ".*-k dcomlaunch.*"'
        ],
        'attck_hit':['T1559.001'],
        'score': 30,
        'name':'Inter-Process Communication: Component Object Model'
    },
    {
        'rules': [
            'originalfilename =~ ".*vssadmin.exe.*" and commandline =~ ".*create.*"',
        ],
        'attck_hit':['T1003.003'],
        'score': 30,
        'name':'OS Credential Dumping: NTDS'
    },
    {
        'rules': [
            'originalfilename =~ ".*wbadmin.exe.*" and commandline =~ ".*delete.*"',
            'originalfilename =~ ".*bcdedit.exe" and commandline =~ ".*recoveryenabled.*no.*"',
            'originalfilename =~ ".*bcdedit.exe" and commandline =~ ".*bootstatuspolicy.*ignoreallfailures.*"',
            'originalfilename =~ ".*wmic.exe" and commandline =~ ".*shadowcopy.*" and commandline =~ ".*delete.*"',
            'originalfilename =~ ".*vssadmin.exe" and commandline =~ ".*shadows.*" and commandline =~ ".*delete.*"',
        ],
        'attck_hit':['T1490'],
        'score': 30,
        'name': 'Inhibit System Recovery'
    },
    {
        'rules': [
            'originalfilename =~ ".*net.exe.*" and commandline =~ ".*view.*"',
            'originalfilename =~ ".*net.exe.*" and commandline =~ ".*group.*"',
            'originalfilename =~ ".*ping.exe"',

        ],
        'attck_hit':['T1018'],
        'score': 10,
        'name': 'Remote System Discovery'
    },
    {
        'rules': [
            'originalfilename =~ ".*fsutil.exe.*" and commandline =~ ".*deletejournal.*"',
        ],
        'attck_hit':['T1070.004'],
        'score': 10,
        'name': 'Indicator Removal on Host'
    },
    {
        'rules': [
            'originalfilename =~ ".*net.exe.*" and commandline =~ ".*user.*"',
            'originalfilename =~ ".*whoami.*"',
            'originalfilename =~ ".*query.exe"',
            'originalfilename =~ ".*setspn.exe"',
            'originalfilename =~ ".*cmdkey.exe.*"'
        ],
        'attck_hit':['T1087.001'],
        'score': 30,
        'name': 'Account Discovery: Local Account'
    },
    {
        'rules': [
            'originalfilename =~ ".*wmic.exe" and commandline =~ ".*useraccount.*"',
        ],
        'attck_hit':['T1087.001', 'T1047'],
        'score': 30,
        'name': 'Account Discovery: Local Account by wmic'
    },
    {
        'rules': [
            'originalfilename =~ ".*wmic.exe" and commandline =~ ".*startup.*"',
            'originalfilename =~ ".*wmic.exe" and commandline =~ ".*share.*"',

        ],
        'attck_hit':['T1082', 'T1047'],
        'score': 30,
        'name': 'System Information Discovery by wmic'
    },
    {
        'rules': [
            'originalfilename =~ ".*systeminfo.exe"',
            'originalfilename =~ ".*chcp.com"'

        ],
        'attck_hit':['T1082'],
        'score': 10,
        'name': 'System Information Discovery'
    },
    {
        'rules': [
            'originalfilename =~ ".*tasklist.exe"',
        ],
        'attck_hit':['T1057'],
        'score': 10,
        'name': 'Process Discovery'
    },
    {
        'rules': [
            'originalfilename =~ ".*at.exe.*"',
        ],
        'attck_hit':['T1053.002'],
        'score': 10,
        'name': 'Scheduled Task/Job: at'
    },
    {
        'rules': [
            'originalfilename =~ ".*schtasks.exe.*"',
        ],
        'attck_hit':['T1053.005'],
        'score': 10,
        'name': 'Scheduled Task/Job: Scheduled Task'
    },
    {
        'rules': [
            'image =~ ".*\\\\\\\\appdata\\\\\\\\local\\\\\\\\temp\\\\\\\\.*" or image =~ ".*\\\\\\\\windows\\\\\\\\temp\\\\\\\\.*"',
        ],
        'attck_hit':['T1106'],
        'score': 10,
        'name': 'Execution: Native API'
    },
    {
        'rules': [
            'originalfilename =~ ".*rubeus.*" and commandline =~ ".*domain.*"',
        ],
        'attck_hit':['T1558.003'],
        'score': 10,
        'name': 'Steal or Forge Kerberos Tickets: Kerberoasting'
    },
    {
        'rules': [
            'originalfilename =~ ".*\u202e.*"',
        ],
        'attck_hit':['T1564'],
        'score': 10,
        'name': 'Hide Artifacts'
    },
    {
        'rules': [
            'parentimage =~ ".*mmc.exe" and commandline =~ ".*eventvwr\.msc.*"',
        ],
        'attck_hit':['T1218.014'],
        'score': 10,
        'name': 'System Binary Proxy Execution: MMC'
    },
    {
        'rules': [
            'originalfilename =~ ".*net.exe" and commandline =~ ".*domain.*"',
            'originalfilename =~ ".*net.exe" and commandline =~ ".*view.*"',
            'originalfilename =~ ".*net.exe" and commandline =~ ".*workstation.*"'
        ],
        'attck_hit':['T1087.002'],
        'score': 10,
        'name': 'Account Discovery: Domain Account'
    },
    {
        'rules': [
            'originalfilename =~ ".*netsh.exe" and commandline =~ ".*firewall.*"',
        ],
        'attck_hit':['T1562.004'],
        'score': 10,
        'name': 'Impair Defenses: Disable or Modify System Firewall'
    },
    {
        'rules': [
            'originalfilename =~ ".*ipconfig.exe"',
            'originalfilename =~ ".*netstat.exe"'

        ],
        'attck_hit':['T1016'],
        'score': 10,
        'name': 'System Network Configuration Discovery'
    },
    {
        'rules': [
            'originalfilename =~ ".*attrib.exe"',
        ],
        'attck_hit':['T1564.001'],
        'score': 10,
        'name': 'Hide Artifacts: Hidden Files and Directories'
    },
    {
        'rules': [
            'originalfilename =~ ".*psexesvc.exe"',
        ],
        'attck_hit':['T1570'],
        'score': 10,
        'name': 'Lateral Tool Transfer'
    },
    {
        'rules': [
            'originalfilename =~ "\\\\\\\\.*\\\\\\C\$.*"',
        ],
        'attck_hit':['T1080'],
        'score': 10,
        'name': 'Taint Shared Content'
    },
    {
        'rules': [
            'originalfilename =~ ".*icacls.exe"',
        ],
        'attck_hit':['T1222.001'],
        'score': 10,
        'name': 'Windows File and Directory Permissions Modification'
    },
    {
        'rules': [
            'parentimage =~ ".*services.exe"',
        ],
        'attck_hit':['T1543.003'],
        'score': 10,
        'name': 'Create or Modify System Process: Windows Service'
    },
    {
        'rules': [
            'originalfilename =~ ".*werfault.exe" and parentimage =~ ".*svchost.exe"',
        ],
        'attck_hit':['T1218'],
        'score': 10,
        'name': 'System Binary Proxy Execution'
    },
    {
        'rules': [
            'originalfilename =~ ".*wscript.exe"',
            'originalfilename =~ ".*cscript.exe"',
        ],
        'attck_hit':['T1059.005'],
        'score': 10,
        'name': 'Command and Scripting Interpreter: Visual Basic'
    },
    {
        'rules': [
            'originalfilename =~ ".*mofcomp.exe.*"'
        ],
        'attck_hit':['T1546.015'],
        'score': 10,
        'name':'Event Triggered Execution: Component Object Model Hijacking'
    },
    {
        'rules': [
            'originalfilename =~ ".*csc.exe.*"'
        ],
        'attck_hit':['T1027.004'],
        'score': 10,
        'name':'Compile After Delivery'
    },
    # https://attack.mitre.org/software/S0552/
    {
        'rules': [
            'originalfilename =~ ".*adfind.exe.*"'
        ],
        'attck_hit':['T1018'],
        'score': 10,
        'name':'Remote System Discovery'
    },
    {
        'rules': [
            'originalfilename =~ ".*wmic.exe.*"'
        ],
        'attck_hit':['T1559.001'],
        'score': 30,
        'name':'Windows Management Instrumentation'
    },
    {
        'rules': [
            'originalfilename =~ ".*rundll32.exe.*"'
        ],
        'attck_hit':['T1218.011'],
        'score': 10,
        'name':'System Binary Proxy Execution: Rundll32'
    },
    {
        'rules': [
            'originalfilename =~ ".*powershell.exe"'
        ],
        'attck_hit':['T1059.001'],
        'score': 10,
        'name':'Command and Scripting Interpreter: PowerShell'
    },
]
