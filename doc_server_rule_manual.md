# 服务端规则指南

编写服务端规则前，请您详细阅读本文，以便了解规则背后的故事，并帮助您更好的编写 RmEye 规则。


# 规则在何时被应用

RmEye 通过本地部署的客户端，向服务器传输行为事件。 \
服务器在收集并解析了行为事件日志后，会立即调用规则匹配函数检测该行为是否被某条规则命中。


# 规则分类

基于 RmEye 的设计思想，一切动作都基于其进程载体，所以，规则被分为 动作（action）和 进程（process）两种类型。

- [`进程规则`]

    用于在进程启动事件日志中，检测新进程的启动上下文，判断其是否为可疑行为。

- [`动作规则`]

    用于在非进程启动事件日志中，检测其特定行为上下文，判断其是否为可疑行为。

RmEye 动作规则列表编写于 `/Server/rules/py/action.py` 文件中；进程规则列表编写于 `/Server/rules/py/process.py` 文件中。


# 规则单元数据结构

```json
    {
        'rules': [
            'originalfilename =~ ".*wbadmin.exe.*" and commandline =~ ".*delete.*"',
        ],
        'score': 70,
        'name': '通过wbadmin删除备份'
    }
```
这是一个 进程（process）类型的示例规则单元，它是一个 dict 数据，包含有三个 item，\
分别是：`rules`, `score`, `name`

- [`rules`]-> `list`:

    其中包含一个或多个使用 `rule_engine` 语法的规则匹配表达式，每个表达式间的关系为 `或`，即任何一个表达式被匹配，都认为该规则已命中。

- [`score`]-> `int`:

    由一个整数表示的规则匹配分值

- [`name`]-> `str`:

    规则名称

# 适用于 RmEye 的 `rule_engine` 规则匹配表达式

`rule_engine` 表达式是服务端规则的核心，它允许用户定义一个 key-value 类型的 Query 表达式，以匹配一个 dict 数据；\
表达式的左值匹配 dict 数据中的特定键名（key），\
右值允许适用通配符、数字、字符串等进行完全匹配或模糊匹配 dict 数据中，对应左值键名的值（value）。\
需要特别注意的是，必须定义 RmEye 数据源事件日志中存在的左值，才可以使规则完全按照预期工作。

# 进程规则已支持的通用左值定义

- `processid`

    进程 PID

- `image`

    进程文件路径

- `originalfilename`

    进程原始文件名

- `hashes`

    进程 MD5 哈希

- `commandline`

    进程命令行

- `user`

    进程用户名

- `integritylevel`

    进程权限等级

- `parentprocessid`

    父进程 PID

- `parentimage`

    父进程文件路径

- `parentcommandline`

    父进程命令行

- `parentuser`

    父进程用户

# 动作规则已支持的特有左值定义

- `action`

    动作类型，包括：
    | action | 描述 |
    | ---- | ---- |
    | processaccess | 进程句柄访问 |
    | pipecreate | 命名管道创建 |
    | createremotethread | 远程线程创建 |
    | filecreatestreamhash | 文件流创建 |
    | registryadd | 注册表项新建 |
    | registryvalueSet | 注册表值项设置 |
    | registryobjectSet | 注册表对象设置 |
    | dnsquery | DNS 查询 |
    | networkconnect | 网络连接建立 |
    | clipboardchange | 剪贴板访问 |
    | processtampering | 进程执行流劫持 |
    | filedeletedetected | 可执行文件删除 |
    | filecreate | 文件创建 |
    | imageload | DLL 加载 |
    | processcreate | 进程创建（已分离为进程规则）|
    | processterminal | 进程退出（内部保留）|

- `sourceimage` - 仅适用于动作 `processaccess`

    源进程文件路径

- `targetimage` - 仅适用于动作 `processaccess`

    目标进程文件路径

- `grantedaccess` - 仅适用于动作 `processaccess`

    访问权限

- `calltrace` - 仅适用于动作 `processaccess`

    调用栈（Call Stack）

- `pipename` - 仅适用于动作 `pipecreate`

    管道名称

- `targetfilename` - 仅适用于动作 `filecreate`

    目标文件名

- `imageloaded` - 仅适用于动作 `imageload`

    已加载的映像名