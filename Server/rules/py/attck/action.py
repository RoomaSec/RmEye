rule = [
    {
        'rules': [
            'action == "processaccess" and targetimage =~ ".*lsass.exe"',
        ],
        'attck_hit':['T1003'],
        'name': 'OS Credential Dumping: LSASS Memory'
    },
    {
        'rules': [
            'action == "processaccess" and calltrace =~ ".*unknown.*" and not calltrace =~ ".*conpty\.node.*" and not calltrace =~ ".*java\.dll.*" and not calltrace =~ ".*appvisvsubsystems64\.dll.*" and not calltrace =~ ".*twinui\.dll.*" and not calltrace =~ ".*nativeimages.*" and not targetimage == "c:\\windows\\system32\\cmd.exe"',
        ],
        'attck_hit':['T1620'],
        'name': 'Reflective Code Loading'
    },
    {
        'rules': [
            'action == "processaccess" and calltrace =~ ".*wshom\.ocx.*"',
            'action == "processaccess" and calltrace =~ ".*shell32\.dll.*"',
            'action == "processaccess" and calltrace =~ ".*dbgcore\.dll.*"',
            'action == "processaccess" and calltrace =~ ".*kernelbase\.dll\+de67e.*"',
            'action == "processaccess" and calltrace =~ ".*framedynos\.dll.*"',
        ],
        'attck_hit':['T1559.001'],
        'name': 'Inter-Process Communication: Component Object Model'
    },
    # todo 懒得做详细的规则了.加油完善规则吧
    {
        'rules': [
            'action == "createremotethread"',
        ],
        'attck_hit':['T1055'],
        'name': 'Process Injection'
    },
    {
        'rules': [
            'action == "filecreatestreamhash"',
        ],
        'attck_hit':['T1564.004'],
        'name': 'Hide Artifacts: NTFS File Attributes'
    },
    {
        'rules': [
            'action == "dnsquery"',
        ],
        'attck_hit':['T1071.004'],
        'name': 'Application Layer Protocol: DNS'
    },
    {
        'rules': [
            'action == "networkconnect"',
        ],
        'attck_hit':['T1071'],
        'name': 'Application Layer Protocol'
    },
    {
        'rules': [
            'action == "clipboardchange"',
        ],
        'attck_hit':['T1115'],
        'name': 'Clipboard Data Monitor API'
    },
    {
        'rules': [
            'action == "processtampering"',
        ],
        'attck_hit':['T1574'],
        'name': 'Hijack Execution Flow'
    },
    {
        'rules': [
            'action == "filecreate" and targetfilename =~ "c:\\\\\\\\windows\\\\\\\\.*"',
            'action == "filecreate" and targetfilename =~ ".*\.exe"',
            'action == "filecreate" and targetfilename =~ ".*\.cmd"',
            'action == "filecreate" and targetfilename =~ ".*\.bat"',
            'action == "filecreate" and targetfilename =~ ".*\.dll"',
        ],
        'attck_hit':['T1036.005'],
        'name': 'Masquerading: Match Legitimate Name or Location'
    },
    {
        'rules': [
            'action == "filecreate" and targetfilename =~ "c:\\\\\\\\windows\\\\\\\\.*"',
        ],
        'attck_hit':['T1036.005'],
        'name': 'Masquerading: Match Legitimate Name or Location'
    },
    {
        'rules': [
            'action == "filecreate" and targetfilename =~ "c:\\\\\\\\users\\\\\\\\.*"',
            'action == "filecreate" and targetfilename =~ ".*\.exe"',
            'action == "filecreate" and targetfilename =~ ".*\.cmd"',
            'action == "filecreate" and targetfilename =~ ".*\.bat"',
            'action == "filecreate" and targetfilename =~ ".*\.dll"',
        ],
        'attck_hit':['T1036.005'],
        'name': 'Masquerading: Match Legitimate Name or Location'
    },
    {
        'rules': [
            'action == "imageload" and imageloaded == "c:\\windows\\system32\\samlib.dll"',
        ],
        'attck_hit':['T1003.002'],
        'name': 'OS Credential Dumping: Security Account Manager'
    }
]
