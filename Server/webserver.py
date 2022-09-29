import logging
import hash_white_list
import json
from flask import Flask
from flask import request
import sql
import log
import config
from flask import Flask, render_template, request
import plugin
import html
import rule
import statistics
app = Flask(
    __name__,
    template_folder="./templates",
    static_folder="./templates",
    static_url_path="",
)
app.jinja_env.variable_start_string = "{.<"
app.jinja_env.variable_end_string = ">.}"


@app.route("/")
def root():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return render_template("index.html")


@app.route("/static/<path:path>")
def on_vue_static(path):
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return app.send_static_file("./" + path)


@app.route("/plugin/<path:path>")
def on_plugin_access(path):
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return plugin.dispath_html_draw(path)


@app.route("/api/v1/get/plugin_menu")
def plugin_menu():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return {"data": {"menu": plugin.dispath_html_menu()}}


@app.route("/api/v1/get/threat_statistics", methods=["GET"])
def threat_statistics():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return {"data": statistics.get_threat_nums()}


@app.route("/api/v1/query/white_list_all", methods=["GET"])
def white_list_query_all():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    all_list = sql.query_all_white_list()
    result = []
    for iter in all_list:
        result.append({
            "hash": iter[1],
            "path": iter[2],
            "timestamp": iter[3],
            "reason": iter[4]
        })
    return {"status": "success", "result": result}


@app.route("/api/v1/query/white_list", methods=["GET"])
def white_list_query():
    hash = request.args.get("hash")
    if request.remote_addr not in config.ALLOW_ACCESS_IP or hash is None or len(hash) == 0:
        return "Access Denied"
    hash = hash.lower()
    result = 0
    if hash in hash_white_list.g_white_list:
        result = 1
    return {"status": "success", "result": result}


@app.route("/api/v1/del/white_list", methods=["GET"])
def white_list_del():
    hash = request.args.get("hash")
    if request.remote_addr not in config.ALLOW_ACCESS_IP or hash is None or len(hash) == 0:
        return "Access Denied"
    hash = hash.lower()
    if hash in hash_white_list.g_white_list:
        sql.delete_white_list(hash)
        hash_white_list.g_white_list.remove(hash)
    return {"status": "success"}


@app.route("/api/v1/set/white_list", methods=["POST"])
def white_list_set():
    body_data = request.data.decode()
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    json_data = json.loads(body_data)
    hash = html.escape(json_data["hash"]).lower()
    path = html.escape(json_data["path"]).lower()
    reason = html.escape(json_data["reason"])
    hash_white_list.add_white_list(path, hash, reason)
    return {"status": "success"}


@app.route("/api/v1/get/process_chain/handle", methods=["GET"])
def handle_chain_data():
    id = request.args.get("id")
    handletype = request.args.get("handletype")
    if request.remote_addr not in config.ALLOW_ACCESS_IP or (
        id is None or handletype is None
    ):
        return "Access Denied"
    sql.handle_threat_log(id, handletype)
    return {"data": {"success": 1}}


@app.route("/api/v1/get/process_chain/delete", methods=["GET"])
def delete_chain_data():
    id = request.args.get("id")
    if request.remote_addr not in config.ALLOW_ACCESS_IP or id is None:
        return "Access Denied"
    sql.delete_threat(id)
    return {"data": {"success": 1}}


@app.route("/api/v1/get/process_chain/pull", methods=["GET"])
def pull_chain_data():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    id = request.args.get("id")
    return_data = {}
    if id is not None:
        threat_data = sql.query_one_threat(id)
        return_data = {
            "host": threat_data[1],
            "chain_hash": threat_data[2],
            "type": threat_data[3],
            "risk_score": threat_data[4],
            "hit_rule": json.loads(threat_data[5]),
            "hit_attck": json.loads(threat_data[6]),
            "chain": json.loads(threat_data[7]),
            "is_end": threat_data[8],
        }
    return {"data": return_data}


@app.route("/api/v1/get/process_chain/all")
def process_chain():
    # -1全部 0未处理的 1处理的 2忽略的
    query_type = request.args.get("query_type")
    if request.remote_addr not in config.ALLOW_ACCESS_IP or query_type is None:
        return "Access Denied"
    threat_datas = sql.query_all_threat_log(query_type)
    return_data = []
    for iter in threat_datas:
        return_data.append(
            {
                "host": iter[0],
                "chain_hash": iter[1],
                "hit_rule": json.loads(iter[2]),
                "time": iter[3],
                "type": iter[4],
                "risk_score": iter[5],
                "id": iter[6],
                "is_end": iter[7],
                "start_process": json.loads(iter[8]),
                "attck_hit_list": json.loads(iter[10]),
            }
        )
    return {"data": return_data}


@app.route("/api/v1/process", methods=["POST"])
def process():
    if request.method == "POST":
        # print(request.data)
        body_data = request.data.decode()
        # 转小写
        host = request.remote_addr
        log.process_log(host, json.loads(body_data.lower()), body_data)
        statistics.update_loged_num(host)

    return {"status": "success"}


@ app.route("/api/v1/log_hunt", methods=["POST"])
def log_rescan():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")
    raw_logs = sql.select_process_raw_log_by_time(
        int(start_time), int(end_time))
    threat_data = log.process_raw_log(raw_logs)
    return {"data": threat_data}


if __name__ == "__main__":
    plugin.reload_plugs()
    sql.init()
    rule.init_rule()
    hash_white_list.synchronization_white_list()

    # 如果你觉得日志太多了,去掉这个注释...
    flask_log = logging.getLogger("werkzeug")
    flask_log.setLevel(logging.ERROR)
    print("注意,你正在使用测试版,请随时关注github以获取最新版本:")
    print("https://github.com/RoomaSec/RmEye")
    # statistics.get_threat_nums()
    app.run(debug=True, host="0.0.0.0")
