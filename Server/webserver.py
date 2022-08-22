import json
from flask import Flask
from flask import request
import sql
import log
import rule
import config
from flask import Flask, render_template, request
import plugin
import logging
app = Flask(__name__,
            template_folder="./templates",
            static_folder="./templates",
            static_url_path="")
app.jinja_env.variable_start_string = '{.<'
app.jinja_env.variable_end_string = '>.}'


@app.route('/')
def root():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return render_template("index.html")


@app.route('/static/<path:path>')
def on_vue_static(path):
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return app.send_static_file("./" + path)


@app.route('/plugin/<path:path>')
def on_plugin_access(path):
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return plugin.dispath_html_draw(path)


@app.route('/api/v1/get/plugin_menu')
def plugin_menu():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return {'data': {'menu': plugin.dispath_html_menu()}}


@app.route('/api/v1/get/threat_statistics', methods=['GET'])
def threat_statistics():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    # sqlite的count啥的还不如自己查出来自己统计
    threat_datas = sql.query_all_threat_log(-1)
    return_data = {
        'all': len(threat_datas),
        'confirm': 0,
        'ingore': 0,
        'working': 0
    }
    for iter in threat_datas:
        if iter[9] == 1:
            return_data['confirm'] += 1
        elif iter[9] == 2:
            return_data['ingore'] += 1
        if iter[7] == 0:
            return_data['working'] += 1
    return {'data': return_data}


@app.route('/api/v1/get/process_chain/handle', methods=['GET'])
def handle_chain_data():
    id = request.args.get('id')
    handletype = request.args.get('handletype')
    if request.remote_addr not in config.ALLOW_ACCESS_IP or (id is None or handletype is None):
        return "Access Denied"
    sql.handle_threat_log(id, handletype)
    return {'data': {'success': 1}}


@app.route('/api/v1/get/process_chain/delete', methods=['GET'])
def delete_chain_data():
    id = request.args.get('id')
    if request.remote_addr not in config.ALLOW_ACCESS_IP or id is None:
        return "Access Denied"
    sql.delete_threat(id)
    return {'data': {'success': 1}}


@app.route('/api/v1/get/process_chain/pull', methods=['GET'])
def pull_chain_data():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    id = request.args.get('id')
    return_data = {}
    if id is not None:
        threat_data = sql.query_one_threat(id)
        return_data = {
            'host': threat_data[1],
            'chain_hash': threat_data[2],
            'type': threat_data[3],
            'risk_score': threat_data[4],
            'hit_rule': json.loads(threat_data[5]),
            'chain': json.loads(threat_data[6]),
            'is_end': threat_data[7]
        }
    return {'data': return_data}


@app.route('/api/v1/get/process_chain/all')
def process_chain():
    # -1全部 0未处理的 1处理的 2忽略的
    query_type = request.args.get('query_type')
    if request.remote_addr not in config.ALLOW_ACCESS_IP or query_type is None:
        return "Access Denied"
    threat_datas = sql.query_all_threat_log(query_type)
    return_data = []
    for iter in threat_datas:
        return_data.append({
            'host': iter[0],
            'chain_hash': iter[1],
            'hit_rule': json.loads(iter[2]),
            'time': iter[3],
            'type': iter[4],
            'risk_score': iter[5],
            'id': iter[6],
            'is_end': iter[7],
            'start_process': json.loads(iter[8]),
        })
    return {'data': return_data}


@app.route('/api/v1/process', methods=['POST'])
def process():
    if request.method == 'POST':
        # print(request.data)
        body_data = request.data.decode()
        # 转小写
        host = request.remote_addr
        log.process_log(host, json.loads(body_data.lower()), body_data)

    return {'status': 'success'}


if __name__ == '__main__':
    plugin.reload_plugs()
    sql.init()
    rule.init_rule()

    # 如果你觉得日志太多了,去掉这个注释...
    flask_log = logging.getLogger('werkzeug')
    flask_log.setLevel(logging.ERROR)
    app.run(debug=True, host="0.0.0.0")
