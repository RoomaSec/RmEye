<template>
<div>
    <div class="row">
        <div class="col"></div>
        <div class="col">
            <div class="row q-gutter-md q-mb-sm q-pa-lg">
                <q-timeline layout="dense" side="right" color="red">
                    <template v-if="!server_threat.data || server_threat.data.length == 0">
                        <h4>暂无可用数据,下次刷新时间 {{last_refresh}}...</h4>
                    </template>
                    <template v-for="(threat, index) in server_threat.data" :key="index">
                        <q-timeline-entry :subtitle="'主机:' + threat.host" side="left">
                            <div>
                                <q-card flat bordered style="overflow: auto" :thumb-style="thumbStyle" :bar-style="barStyle">
                                    <q-card-section horizontal>
                                        <div class="bg-red-5">&nbsp;</div>
                                        <q-card-actions vertical class="justify-around q-px-md">
                                            <div>进程链hash: {{ threat.chain_hash }}</div>
                                            <div>进程: {{ threat.start_process.path }}</div>
                                            <div>用户: {{ threat.start_process.user }}</div>
                                            <div>
                                                分数:
                                                <q-chip square color="orange" text-color="white" icon-right="visibility">
                                                    {{ threat.risk_score }}
                                                </q-chip>
                                            </div>
                                            <div>
                                                活动状态:
                                                <q-chip square :color="threat.is_end == 1 ? 'negative' : 'red'" text-color="white">
                                                    {{ threat.is_end == 1 ? "已结束" : "进行中" }}
                                                </q-chip>
                                            </div>
                                            <div>
                                                ATTCK命中:
                                                <template v-for="(index, operation) in threat.attck_hit_list" :key="index">
                                                    <q-chip square color="rgb(239,243,246)">
                                                        {{ operation }}&nbsp;({{ index }})
                                                    </q-chip>
                                                </template>
                                            </div>
                                            <div>
                                                产生的威胁:
                                                <template v-for="(index, operation) in threat.hit_rule" :key="index">
                                                    <q-chip square color="red" text-color="white">
                                                        {{ operation }}&nbsp;({{ index }})
                                                    </q-chip>
                                                </template>
                                                <template v-if="JSON.stringify(threat.hit_rule) == '{}'">
                                                    <q-chip square color="negative" text-color="white">
                                                        <!--crowdstrike: 这活我熟-->
                                                        机器学习引擎
                                                    </q-chip>
                                                </template>
                                            </div>
                                            <div>
                                                <q-btn flat color="accent" @click="show_details(threat.id)" icon="open_in_new">
                                                    查看详情
                                                </q-btn>
                                                <q-btn flat color="accent" @click="search_vt(threat.start_process.hash)" icon="search">
                                                    在VT上搜索
                                                </q-btn>
                                                <q-btn flat color="accent" @click="handle_threat(threat.id, 1)" icon="done">
                                                    确认威胁
                                                </q-btn>
                                                <q-btn flat color="accent" @click="handle_threat(threat.id, 2)" icon="texture">
                                                    忽略威胁
                                                </q-btn>
                                                <q-btn flat color="accent" icon="close" @click="delete_threat(threat.id)">
                                                    删除报警
                                                </q-btn>
                                            </div>
                                        </q-card-actions>
                                    </q-card-section>
                                </q-card>
                            </div>
                        </q-timeline-entry>
                    </template>
                </q-timeline>
            </div>
        </div>
        <div class="col"></div>
    </div>
</div>
<q-dialog v-model="addwhiteListHash" persistent transition-show="scale" transition-hide="scale">
    <q-card style="min-width: 350px">
        <q-card-section>
            <div class="text-h6">填写缘由</div>
        </q-card-section>

        <q-card-section class="q-pt-none">
            <q-input dense v-model="this.whiteListPostData.reason" autofocus />
        </q-card-section>

        <q-card-actions align="right" class="text-primary">
            <q-btn flat label="取消" @click="addwhiteListHash = false" v-close-popup />
            <q-btn flat label="加入白名单" v-close-popup @click="add_to_white_hash_post()" />
        </q-card-actions>
    </q-card>
</q-dialog>
<q-dialog v-model="dialog" persistent :maximized="maximizedToggle" transition-show="slide-up" transition-hide="slide-down">
    <q-card class="text-white">
        <q-bar>
            <q-space></q-space>
            <q-btn dense flat icon="close" v-close-popup>
                <q-tooltip content-class="bg-white text-primary">Close</q-tooltip>
            </q-btn>
        </q-bar>
        <div class="row" style="width: 100%; height: 100%">
            <div ref="main_draw" style="width: 100%; height: 100%; margin-left: 5%">
                1
            </div>
        </div>
        <q-drawer show-if-above v-if="processChainShowDetails" v-model="processChainShowDetails" side="right" bordered width="350" class="text-dark">
            <q-list style="width: 100%;word-break: break-all;">
                <q-item>
                    <q-item-section>活跃状态: {{processChainDetails.active ? "运行中" : "已结束"}}</q-item-section>
                </q-item>
                <q-separator />
                <q-item>
                    <q-item-section>进程名字: {{processChainDetails.name}}</q-item-section>
                </q-item>
                <q-separator />
                <q-item>
                    <q-item-section>进程路径: {{processChainDetails.path}}</q-item-section>
                </q-item>
                <q-separator />
                <q-item>
                    <q-item-section>进程参数: {{processChainDetails.params}}</q-item-section>
                </q-item>
                <q-separator />
                <q-item>
                    <q-item-section>进程id: {{processChainDetails.pid}}</q-item-section>
                </q-item>
                <q-separator />
                <q-item>
                    <q-item-section>父进程id: {{processChainDetails.ppid}}</q-item-section>
                </q-item>
                <q-separator />
                <q-item>
                    <q-item-section>进程hash: {{processChainDetails.md5}}</q-item-section>
                </q-item>
                <q-separator />
                <q-item>
                    <q-item-section>是否在白名单中: {{processChainDetails.isWhite ? "是" : "否"}}</q-item-section>
                </q-item>
                <q-separator />
                <q-item>
                    <q-item-section>进程命中的规则:
                        <template v-for="(index, operation) in processChainDetails.hitRules" :key="index">
                            <q-chip square color="rgb(239,243,246)">
                                {{ operation }}&nbsp;({{ index }})
                            </q-chip>
                        </template>
                        <template v-if="JSON.stringify(processChainDetails.hitRules) == '{}'">
                            <q-chip square color="rgb(239,243,246)">
                                无
                            </q-chip>
                        </template>
                    </q-item-section>
                </q-item>
                <q-item>
                    <q-item-section>attck矩阵:
                        <template v-for="(index, operation) in processChainDetails.hitAttck" :key="index">
                            <q-chip square color="rgb(239,243,246)">
                                {{ operation }}&nbsp;({{ index }})
                            </q-chip>
                        </template>
                        <template v-if="JSON.stringify(processChainDetails.hitAttck) == '{}'">
                            <q-chip square color="rgb(239,243,246)">
                                无
                            </q-chip>
                        </template>
                    </q-item-section>
                </q-item>
                <q-item>
                    <q-btn icon="search" outline style="color: grey;width: 100%;" label="搜索hash" @click="search_vt(processChainDetails.md5)" />
                </q-item>
                <q-item>
                    <template v-if="processChainDetails.isWhite == false">
                        <q-btn icon="texture" outline style="color: grey;width: 100%;" label="加入白名单" @click="add_to_white_hash_pre(processChainDetails.path,processChainDetails.md5)" />
                    </template>
                    <template v-else>
                        <q-btn icon="clear" outline style="color: grey;width: 100%;" label="从白名单中删除" @click="delete_white_hash(processChainDetails.md5)" />
                    </template>
                </q-item>
            </q-list>
        </q-drawer>
    </q-card>
</q-dialog>
</template>

<script>
import {
  defineComponent
} from 'vue'

import axios from 'axios'
import * as echarts from 'echarts'
export default defineComponent({
  name: 'PageIndex',
  data: function () {
    return {
      addwhiteListHash: false,
      whiteListPostData: {
        path: '',
        hash: '',
        reason: ''
      },
      processChainShowDetails: false,
      last_refresh: 360,
      processChainDetails: {
        hash: '',
        prams: '',
        hitRules: [],
        hitAttck: [],
        isWhite: false,
        whiteListReason: ''
      },
      thumbStyle: {
        right: '4px',
        borderRadius: '5px',
        backgroundColor: '#027be3',
        width: '5px',
        opacity: 0.75
      },
      barStyle: {
        right: '2px',
        borderRadius: '9px',
        backgroundColor: '#027be3',
        width: '9px',
        opacity: 0.2
      },
      dialog: false,
      maximizedToggle: true,
      server_threat: {},
      select_chain_data: {}
    }
  },
  methods: {
    delete_white_hash (hash) {
      axios.get('/api/v1/del/white_list?hash=' + hash).then(res => {
        this.processChainDetails.isWhite = false
      })
    },
    query_white_hash (hash) {
      axios.get('/api/v1/query/white_list?hash=' + hash).then(res => {
        this.processChainDetails.isWhite = res.data.result === 1
      })
    },
    add_to_white_hash_pre (path, hash) {
      this.whiteListPostData = {
        path: path,
        hash: hash,
        reason: ''
      }
      this.addwhiteListHash = true
      console.log('addwhiteListHash', this.addwhiteListHash)
    },
    add_to_white_hash_post () {
      axios
        .post('/api/v1/set/white_list', this.whiteListPostData)
        .then((response) => {
          this.processChainDetails.isWhite = true
        })
    },
    set_chain_data (data) {
      if (data.path) {
        const str = data.path.split('\\')
        data.name = str[str.length - 1]
        console.log(data.name)
        for (const index in data.children) {
          this.set_chain_data(data.children[index])
        }
      }
    },
    draw_tree () {
      this.set_chain_data(this.select_chain_data)
      const dom = this.$refs.main_draw
      const myChart = echarts.init(dom)
      const option = {
        tooltip: {
          trigger: 'item',
          triggerOn: 'mousemove',
          formatter: function (params) {
            const contextData = params.data
            let result =
                            '<div>参数: ' +
                            contextData.params +
                            '</div>' +
                            '<div> hash: ' +
                            contextData.md5 +
                            '</div><div>命名规则列表: '
            if (contextData.operationlist.length === 0) {
              result += '无'
            }
            for (const key in contextData.operationlist) {
              result +=
                                ' ' + key + '[' + contextData.operationlist[key] + ']' + ' '
            }
            result += '</div>'
            return result
          }
        },
        series: [{
          roam: true,
          type: 'tree',
          id: 0,
          name: 'tree1',
          data: [this.select_chain_data],
          top: '5%',
          left: '15%',
          bottom: '22%',
          right: '20%',
          edgeShape: 'polyline',
          edgeForkPosition: '63%',
          initialTreeDepth: 60,
          lineStyle: {
            width: 2
          },
          label: {
            backgroundColor: '#fff',
            position: 'left',
            verticalAlign: 'middle',
            align: 'right'
          },
          leaves: {
            label: {
              position: 'right',
              verticalAlign: 'middle',
              align: 'left'
            }
          },
          emphasis: {
            focus: 'descendant'
          },
          symbolSize: [30, 30], // 宽40 高50
          symbol: 'image://data:image/png;base64,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',
          expandAndCollapse: false,
          animationDuration: 350,
          animationDurationUpdate: 450
        }]
      }
      myChart.setOption(option)
      myChart.on('click', params => {
        const data = params.data
        this.processChainDetails = {
          path: data.path,
          active: data.active,
          md5: data.md5,
          name: data.name,
          params: data.params,
          pid: data.pid,
          ppid: data.ppid,
          hitRules: data.operationlist === undefined ? {} : data.operationlist,
          hitAttck: data.attck_hit_list === undefined ? {} : data.attck_hit_list,
          isWhite: false
        }
        this.query_white_hash(data.md5)
        this.processChainShowDetails = true
      })
    },
    search_vt (hash) {
      window.open('https://www.virustotal.com/gui/search/' + hash, '_blank')
    },
    delete_threat (threatId) {
      axios
        .get('/api/v1/get/process_chain/delete?id=' + threatId, {
          'Content-Type': 'application/json'
        })
        .then((response) => {
          this.get_clientids()
        })
    },
    handle_threat (threatId, handleType) {
      axios
        .get('/api/v1/get/process_chain/handle?id=' + threatId + '&handletype=' + handleType, {
          'Content-Type': 'application/json'
        })
        .then((response) => {
          this.get_clientids()
        })
    },
    show_details (threatId) {
      axios
        .get('/api/v1/get/process_chain/pull?id=' + threatId, {
          'Content-Type': 'application/json'
        })
        .then((response) => {
          const data = response.data
          if (data.data) {
            this.select_chain_data = data.data.chain.process_node
            this.dialog = true
            console.log('this.select_chain_data', this.select_chain_data)
            this.$nextTick(() => {
              this.draw_tree()
            })
          }
        })
    },

    get_clientids () {
      const queryType = this.$route.params.queryIndex
      const queryIndex = (queryType === null || queryType === undefined) ? 0 : queryType
      axios
        .get('/api/v1/get/process_chain/all?query_type=' + queryIndex, {
          'Content-Type': 'application/json'
        })
        .then((response) => {
          const data = response.data
          if (data.data) {
            this.server_threat = {
              data: []
            }
            this.server_threat.data = data.data
          }
        })
    }
  },
  mounted () {
    this.get_clientids()
    setInterval(() => {
      this.last_refresh -= 1
      if (this.last_refresh <= 0) {
        this.get_clientids()
        this.last_refresh = 360
      }
    }, 1000)
    // this.draw_tree();
  },
  watch: {
    '$route' (val, from) { // 监听到路由（参数）改变
      // 拿到目标参数 val.query.typeCode 去再次请求数据接口
      this.get_clientids()
    }
  }
})
</script>
