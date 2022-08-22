import rule_engine
import rules.py.process as rule_process
import rules.py.action as rule_action
import plugin
g_sample_rule = {}
g_sample_rule['process'] = rule_process.rule
g_sample_rule['action'] = rule_action.rule

base_process_rules = []
base_action_rules = []
base_host_rules = []


def calc_score_in_action(log):
    global base_action_rules
    for iter in base_action_rules:
        for rule in iter['rules']:
            # 这是or
            try:
                if rule.matches(log):
                    return iter['score'], iter['name']
            except:
                print("error: {}  ".format(log))

    return 0, ''


def calc_score_in_create_process(log):
    global base_process_rules
    for iter in base_process_rules:
        for rule in iter['rules']:
            # 这是or
            if rule.matches(log):
                return iter['score'], iter['name']
    return 0, ''


def calc_score_in_host(log):
    global base_host_rules
    for iter in base_host_rules:
        for rule in iter['rules']:
            # 这是or
            if rule.matches(log):
                return iter['score'], iter['name']
    return 0, ''


def init_rule():
    global base_process_rules
    global base_action_rules
    global base_host_rules
    for iter in g_sample_rule['process']:
        temp_process_rules = []
        for iter_i in iter['rules']:
            print(iter_i)
            temp_process_rules.append(rule_engine.Rule(
                iter_i
            ))
        base_process_rules.append(
            {'name': iter['name'], 'score': iter['score'], 'rules': temp_process_rules})
    for iter in g_sample_rule['action']:
        temp_process_rules = []
        for iter_i in iter['rules']:
            print(iter_i)
            temp_process_rules.append(rule_engine.Rule(
                iter_i
            ))
        base_action_rules.append(
            {'name': iter['name'], 'score': iter['score'], 'rules': temp_process_rules})
        '''
    for iter in g_sample_rule['host']:
        temp_process_rules = []
        for iter_i in iter['rules']:
            print(iter_i)
            temp_process_rules.append(rule_engine.Rule(
                iter_i
            ))
        base_host_rules.append(
            {'name': iter['name'], 'score': iter['score'], 'rules': temp_process_rules})
    '''
    plugin.dispath_rule_init()
    print('init rule done')
