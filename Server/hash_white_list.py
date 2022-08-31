import sql
g_white_list = []


def add_white_list(path, hash, reason):
    global g_white_list
    if hash in g_white_list:
        return False
    g_white_list.append(hash)
    sql.push_white_list(path, hash, reason)


def synchronization_white_list():
    sql_data = sql.query_all_white_list()
    for data in sql_data:
        g_white_list.append(data[1])
    print("sync white list success, size: {}".format(len(sql_data)))
