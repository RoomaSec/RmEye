rule = [
    {
        'rules': [
            'originalfilename =~ ".*todesk_service.*" or originalfilename =~ ".*sunloginclient.*" or originalfilename =~ ".*teamviewer_service.exe.*" or originalfilename =~ ".*logmein.*" or originalfilename =~ ".*dwrcs.*" or originalfilename =~ ".*aa_v3.*" or originalfilename =~ ".*screenconnect.*" or originalfilename =~ ".*tvnserver.*" or originalfilename =~ ".*vncserver.*"',
        ],
        'attck_hit':['T1133'],
        'score': 30,
        'name': '已知远程协助程序'
    },
    {
        'rules': [
            'originalfilename =~ ".*phoenixminer.*" or originalfilename =~ ".*ccminer.*" or originalfilename =~ ".*csminer.exe.*" or originalfilename =~ ".*xmrig.*" or originalfilename =~ ".*xmr-stak.*"',
        ],
        'attck_hit':['T1496'],
        'score': 100,
        'name': '已知挖矿程序'
    },
    {
        'rules': [
            'originalfilename =~ "\\\\\\.*" and parentimage =~ ".*services.exe"',
        ],
        'attck_hit':['T1021.006'],
        'score': 100,
        'name': '远程服务被创建'
    },
    {
        'rules': [
            'commandline =~ ".*__\d{10}\."',
            'originalfilename =~ ".*wmi_share.exe"',
        ],
        'attck_hit':['T00000'],
        'score': 100,
        'name': 'wmic内网横向移动被触发'
    },
]
