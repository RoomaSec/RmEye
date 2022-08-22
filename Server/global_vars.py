import os


THREAT_TYPE_NONE = -1
THREAT_TYPE_PROCESS = 0
THREAT_TYPE_ROOTKIT = 1
THREAT_TYPE_LM = 2
THREAT_TYPE_HOSTSTATUS = 3
THREAT_TYPE_NETWORK = 4
PLUGS_PATH = os.path.dirname(os.path.realpath(__file__)) + "\\plugins\\"
g_plugs = []
