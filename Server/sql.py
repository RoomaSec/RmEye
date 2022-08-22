from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

import time

# 引入sqlalchemy中相关模块
from sqlalchemy import create_engine, MetaData
from sqlalchemy import Column, Integer, String, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import delete
import json

g_engine = None
g_base = declarative_base()
g_metadata = None
g_rawdata_table = None
g_rawdata_table_ins = None
g_threat_table = None
g_threat_table_ins = None


class raw_process_log(g_base):
    __tablename__ = "raw_process_log"
    # 定义各字段
    id = Column(Integer, primary_key=True)
    # 主机ip
    host = Column(String)
    # 动作
    # processcreate, processterminal
    action = Column(String)
    # 进程路径
    path = Column(String)
    # 进程pid
    pid = Column(Integer)
    # 父进程pid
    ppid = Column(Integer)
    # 目标文件路径(如果有)
    target_path = Column(String)
    # 目标进程路径(如果有)
    target_image_path = Column(String)
    # 目标进程pid(如果有)
    target_image_pid = Column(Integer)
    # 目标的hash(如果有)
    target_hash = Column(String)
    # hash
    hash = Column(String)
    hit = Column(String)
    score = Column(Integer)
    chain_hash = Column(String)
    type = Column(Integer)
    # 时间戳
    timestamp = Column(Integer)
    commandline = Column(String)
    user = Column(String)
    # 原始字段
    data = Column(String)

    def __str__(self):
        return self.id


class threat_log(g_base):
    __tablename__ = "threat_log"
    # 定义各字段
    id = Column(Integer, primary_key=True)
    # 主机ip
    host = Column(String)
    # 进程链hash,其他的为000000
    process_chain_hash = Column(String)
    # type
    type = Column(Integer)
    # 分数
    risk_score = Column(Integer)
    # 命中的规则
    hit_rule = Column(String)
    # json字段
    data = Column(String)
    # 时间戳
    timestamp = Column(Integer)
    # is end
    is_end = Column(Integer)
    # start process
    start_process_info = Column(String)
    # handle type
    handle_type = Column(Integer)

    def __str__(self):
        return self.id


def init():
    global g_engine
    global g_base
    global g_metadata
    global g_rawdata_table
    global g_rawdata_table_ins
    global g_threat_table
    global g_threat_table_ins

    g_engine = create_engine("sqlite:///syseye.db?check_same_thread=False", echo=False)
    g_base.metadata.create_all(g_engine)
    g_metadata = MetaData(g_engine)
    g_rawdata_table = Table("raw_process_log", g_metadata, autoload=True)
    g_rawdata_table_ins = g_rawdata_table.insert()

    g_threat_table = Table("threat_log", g_metadata, autoload=True)
    g_threat_table_ins = g_threat_table.insert()


def push_process_raw(
    host,
    log,
    rule_hit_name,
    score,
    chain_hash,
    type,
    parent_pid,
    target_pid,
    self_hash,
    target_image_path,
    target_hash,
    commandline,
    user,
):
    global g_engine
    global g_rawdata_table
    global g_rawdata_table_ins
    timestamp = int(round(time.time() * 1000))
    # 偷懒了 有时间再重构
    ins = g_rawdata_table_ins.values(
        host=host,
        action=log["Action"],
        path=log["Data"]["Path"]
        if "Path" in log["Data"]
        else (
            log["Data"]["SourceImage"]
            if "SourceImage" in log["Data"]
            else (log["Data"]["Image"] if "Image" in log["Data"] else "")
        ),  # 只有三种情况,没有path就找sourceimage,没有sourceimage就找image
        pid=log["Data"]["ProcessId"],
        ppid=parent_pid,
        target_path=log["Data"]["TargetImage"]
        if "TargetImage" in log["Data"]
        else target_image_path,
        target_image_path=log["Data"]["TargetFilename"]
        if "TargetFilename" in log["Data"]
        else "",
        target_image_pid=target_pid,
        target_hash=target_hash,
        hash=self_hash,
        data=json.dumps(log["Data"]),
        timestamp=timestamp,
        hit=rule_hit_name,
        score=score,
        chain_hash=chain_hash,
        commandline=commandline,
        user=user,
        type=type,
    )
    # 连接引擎
    conn = g_engine.connect()
    # 执行语句
    result = conn.execute(ins)
    return result


def select_create_process_raw_log_by_time(start, end):
    global g_rawdata_table
    sql_session = sessionmaker(bind=g_engine)
    raw_log = (
        sql_session()
        .query(g_rawdata_table)
        .filter(
            raw_process_log.timestamp >= start,
            raw_process_log.timestamp < end,
            raw_process_log.action == "processcreate",
        )
    )

    sql_session().close()
    return raw_log


def select_threat_by_chain_id(host, process_chain_hash, type):
    global g_threat_table
    sql_session = sessionmaker(bind=g_engine)
    threat = (
        sql_session()
        .query(g_threat_table)
        .filter_by(host=host, process_chain_hash=process_chain_hash, type=type)
        .all()
    )
    sql_session().close()
    return threat


def update_threat_log(
    host, risk_score, hit_rule_json, process_chain_hash, raw_json, type, is_end
):
    global g_threat_table
    global g_engine
    conn = g_engine.connect()
    update = (
        g_threat_table.update()
        .values(
            risk_score=risk_score,
            hit_rule=hit_rule_json,
            data=raw_json,
            is_end=int(is_end),
        )
        .where(
            g_threat_table.columns.host == host,
            g_threat_table.columns.process_chain_hash == process_chain_hash,
            g_threat_table.columns.type == type,
        )
    )
    result = conn.execute(update)
    return result


def handle_threat_log(threat_id, handle_type):
    global g_threat_table
    global g_engine
    conn = g_engine.connect()
    update = (
        g_threat_table.update()
        .values(handle_type=handle_type, is_end=1)
        .where(g_threat_table.columns.id == int(threat_id))
    )
    result = conn.execute(update)
    return result


def delete_threat(threat_id):
    global g_threat_table
    global g_engine
    conn = g_engine.connect()
    result = conn.execute(
        delete(g_threat_table).where(g_threat_table.columns.id == int(threat_id))
    )
    return result


def query_one_threat(threat_id):
    global g_threat_table
    sql_session = sessionmaker(bind=g_engine)
    threat = sql_session().query(g_threat_table).filter_by(id=threat_id).first()
    sql_session().close()
    return threat


def query_all_threat_log(query_type):
    global g_threat_table
    sql_session = sessionmaker(bind=g_engine)
    if int(query_type) == -1:
        threat = (
            sql_session()
            .query(g_threat_table)
            .with_entities(
                threat_log.host,
                threat_log.process_chain_hash,
                threat_log.hit_rule,
                threat_log.timestamp,
                threat_log.type,
                threat_log.risk_score,
                threat_log.id,
                threat_log.is_end,
                threat_log.start_process_info,
                threat_log.handle_type,
            )
            .all()
        )
    else:
        threat = (
            sql_session()
            .query(g_threat_table)
            .with_entities(
                threat_log.host,
                threat_log.process_chain_hash,
                threat_log.hit_rule,
                threat_log.timestamp,
                threat_log.type,
                threat_log.risk_score,
                threat_log.id,
                threat_log.is_end,
                threat_log.start_process_info,
                threat_log.handle_type,
            )
            .filter_by(handle_type=query_type)
            .all()
        )
    sql_session().close()
    return threat


def push_threat_log(
    host,
    risk_score,
    hit_rule_json,
    process_chain_hash,
    raw_json,
    type,
    start_process_info,
):
    global g_engine
    global g_threat_table
    global g_threat_table_ins
    ins = g_threat_table_ins.values(
        host=host,
        risk_score=risk_score,
        process_chain_hash=process_chain_hash,
        hit_rule=hit_rule_json,
        type=type,
        data=raw_json,
        timestamp=int(round(time.time() * 1000)),
        is_end=0,
        start_process_info=start_process_info,
        handle_type=0,
    )
    # 连接引擎
    conn = g_engine.connect()
    # 执行语句
    result = conn.execute(ins)
    # print(raw_json)
    return result
