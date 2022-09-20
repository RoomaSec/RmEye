import rule_engine
import rules.py.attck.process as attck_process
import rules.py.attck.attck as attack_software
import rules.py.attck.action as attack_action
import rules.py.ioa.action as ioa_action
import rules.py.ioa.process as ioa_process

import plugin
g_sample_rule = {}
g_sample_rule['attack_process'] = attck_process.rule
g_sample_rule['attack_action'] = attack_action.rule
g_sample_rule['attack_software'] = attack_software.rule
g_sample_rule['ioa_action'] = ioa_action.rule
g_sample_rule['ioa_process'] = ioa_process.rule
attck_process_rules = []
attck_action_rules = []
ioa_process_rules = []
ioa_action_rules = []

base_host_rules = []


def match_att_ck_software(t_list):
    # 返回是否命中,命中命中,分数

    global g_sample_rule
    is_match = False
    match_name = ''
    match_score = 0
    for iter in g_sample_rule['attack_software']:
        rule_list = iter['rules']
        min_match_num = iter['hit_num']

        match_num = 0

        for t in t_list.keys():
            if t in rule_list:
                match_num += 1
            if match_num >= min_match_num:
                is_match = True
                match_name = iter['name']
                match_score = iter['score']
                break
        if is_match:
            break
    return is_match, match_name, match_score


def calc_score_in_action(log):
    # 返回 是否匹配到,是否ioa,attck,分数,名字

    global attck_action_rules
    global ioa_action_rules
    for iter in ioa_action_rules:
        for rule in iter['rules']:
            if rule.matches(log):
                return True, True, iter['attck_hit'], iter['score'], iter['name']
    for iter in attck_action_rules:
        for rule in iter['rules']:
            if rule.matches(log):
                return True, False, iter['attck_hit'], iter['score'], iter['name']
    return False, False, [], 0, ''


def calc_score_in_create_process(log):
    # 返回 是否匹配到,是否ioa,attck,分数,名字
    global ioa_process_rules
    global attck_process_rules
    for iter in ioa_process_rules:
        for rule in iter['rules']:
            if rule.matches(log):
                return True, True, iter['attck_hit'], iter['score'], iter['name']
    for iter in attck_process_rules:
        for rule in iter['rules']:
            if rule.matches(log):
                return True, False, iter['attck_hit'], iter['score'], iter['name']
    return False, False, [], 0, ''


def init_rule():
    global attck_process_rules
    global attck_action_rules
    global ioa_process_rules
    global ioa_action_rules
    for iter in g_sample_rule['attack_process']:
        temp_process_rules = []
        score = 0
        if 'score' not in iter:
            score = 5
        else:
            score = iter['score']
        for iter_i in iter['rules']:
            print('rule: {} score: {}'.format(iter_i, score))
            temp_process_rules.append(rule_engine.Rule(
                iter_i
            ))
        attck_process_rules.append(
            {'name': iter['name'], 'attck_hit': iter['attck_hit'], 'score': score, 'rules': temp_process_rules})
    for iter in g_sample_rule['attack_action']:
        temp_process_rules = []
        score = 0
        if 'score' not in iter:
            score = 5
        else:
            score = iter['score']
        for iter_i in iter['rules']:
            print('rule: {} score: {}'.format(iter_i, score))
            temp_process_rules.append(rule_engine.Rule(
                iter_i
            ))
        attck_action_rules.append(
            {'name': iter['name'], 'attck_hit': iter['attck_hit'], 'score': score, 'rules': temp_process_rules})
    for iter in g_sample_rule['ioa_action']:
        temp_process_rules = []
        for iter_i in iter['rules']:
            print('rule: {} score: {}'.format(iter_i, score))
            temp_process_rules.append(rule_engine.Rule(
                iter_i
            ))
        ioa_action_rules.append(
            {'name': iter['name'], 'attck_hit': iter['attck_hit'], 'score': iter['score'], 'rules': temp_process_rules})
    for iter in g_sample_rule['ioa_process']:
        temp_process_rules = []
        for iter_i in iter['rules']:
            print('rule: {} score: {}'.format(iter_i, score))
            temp_process_rules.append(rule_engine.Rule(
                iter_i
            ))
        ioa_process_rules.append(
            {'name': iter['name'], 'attck_hit': iter['attck_hit'], 'score': iter['score'], 'rules': temp_process_rules})
    plugin.dispath_rule_init()
    print('init rule done')
