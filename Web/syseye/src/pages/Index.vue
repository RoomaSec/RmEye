<template>
  <div>
    <div class="q-gutter-md q-mb-sm q-pa-lg">
    <q-card class="bg-transparent no-shadow no-border">
      <q-card-section class="q-pa-none">
        <div class="row q-col-gutter-sm">
          <div
            v-for="(item, index) in Threatitems"
            :key="index"
            class="col-md-3 col-sm-12 col-xs-12"
          >
            <q-item
              :style="`background-color: ${item.color1}`"
              class="q-pa-none"
            >
              <q-item-section
                side
                :style="`background-color: ${item.color2}`"
                class="q-pa-lg q-mr-none text-white"
              >
                <q-icon :name="item.icon" color="white" size="24px"></q-icon>
              </q-item-section>
              <q-item-section class="q-pa-md q-ml-none text-white">
                <q-item-label class="text-white text-h6 text-weight-bolder">{{
                  item.value
                }}</q-item-label>
                <q-item-label>{{ item.title }}</q-item-label>
              </q-item-section>
            </q-item>
          </div>
        </div>
      </q-card-section>
    </q-card>
    </div>
    <div class="row">
      <div class="col"></div>
      <div class="col">
        <div class="row q-gutter-md q-mb-sm q-pa-lg">
          <q-timeline layout="dense" side="right" color="red">
            <template
              v-if="!server_threat.data || server_threat.data.length == 0"
            >
              <h4>暂无可用数据,下次刷新时间 {{last_refresh}}...</h4>
            </template>
            <template
              v-for="(threat, index) in server_threat.data"
              :key="index"
            >
              <q-timeline-entry :subtitle="'主机:' + threat.host" side="left">
                <div>
                  <q-card
                    flat
                    bordered
                    style="overflow: auto"
                    :thumb-style="thumbStyle"
                    :bar-style="barStyle"
                  >
                    <q-card-section horizontal>
                      <div class="bg-red-5">&nbsp;</div>
                      <q-card-actions vertical class="justify-around q-px-md">
                        <div>进程链hash: {{ threat.chain_hash }}</div>
                        <div>进程: {{ threat.start_process.path }}</div>
                        <div>用户: {{ threat.start_process.user }}</div>
                        <div>
                          分数:
                          <q-chip
                            square
                            color="orange"
                            text-color="white"
                            icon-right="visibility"
                          >
                            {{ threat.risk_score }}
                          </q-chip>
                        </div>
                        <div>
                          活动状态:
                          <q-chip
                            square
                            :color="threat.is_end == 1 ? 'negative' : 'red'"
                            text-color="white"
                          >
                            {{ threat.is_end == 1 ? "已结束" : "进行中" }}
                          </q-chip>
                        </div>
                        <div>
                          产生的威胁:
                          <template
                            v-for="(index, operation) in threat.hit_rule"
                            :key="index"
                          >
                            <q-chip square color="rgb(239,243,246)">
                              {{ operation }}&nbsp;({{ index }})
                            </q-chip>
                          </template>
                        </div>
                        <div>
                          <q-btn
                            flat
                            color="accent"
                            @click="show_details(threat.id)"
                            icon="open_in_new"
                          >
                            查看详情
                          </q-btn>
                          <q-btn
                            flat
                            color="accent"
                            @click="search_vt(threat.start_process.hash)"
                            icon="search"
                          >
                            在VT上搜索
                          </q-btn>
                          <q-btn
                            flat
                            color="accent"
                            @click="handle_threat(threat.id, 1)"
                            icon="done"
                          >
                            确认威胁
                          </q-btn>
                          <q-btn
                            flat
                            color="accent"
                            @click="handle_threat(threat.id, 2)"
                            icon="texture"
                          >
                            忽略威胁
                          </q-btn>
                          <q-btn
                            flat
                            color="accent"
                            icon="close"
                            @click="delete_threat(threat.id)"
                          >
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
  <q-dialog
    v-model="dialog"
    persistent
    :maximized="maximizedToggle"
    transition-show="slide-up"
    transition-hide="slide-down"
  >
    <q-card class="text-white">
      <q-bar>
        <q-space></q-space>
        <q-btn
          dense
          flat
          icon="minimize"
          @click="maximizedToggle = false"
          :disable="!maximizedToggle"
        >
          <q-tooltip
            v-if="maximizedToggle"
            content-class="bg-white text-primary"
            >Minimize</q-tooltip
          >
        </q-btn>
        <q-btn
          dense
          flat
          icon="crop_square"
          @click="maximizedToggle = true"
          :disable="maximizedToggle"
        >
          <q-tooltip
            v-if="!maximizedToggle"
            content-class="bg-white text-primary"
            >Maximize</q-tooltip
          >
        </q-btn>
        <q-btn dense flat icon="close" v-close-popup>
          <q-tooltip content-class="bg-white text-primary">Close</q-tooltip>
        </q-btn>
      </q-bar>
      <div class="row" style="width: 100%; height: 100%">
        <div ref="main_draw" style="width: 100%; height: 100%; margin-left: 5%">
          1
        </div>
      </div>
    </q-card>
  </q-dialog>
</template>

<script>
import { defineComponent } from 'vue'

import axios from 'axios'
import * as echarts from 'echarts'
export default defineComponent({
  name: 'PageIndex',
  data: function () {
    return {
      last_refresh: 360,
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
      threatStatistics: {
        all: 1,
        confirm: 0,
        ingore: 1,
        working: 0
      },
      Threatitems:
       [
         {
           title: '发现的威胁',
           icon: 'remove_red_eye',
           value: '200',
           color1: '#5064b5',
           color2: '#3e51b5'
         },
         {
           title: '确认的威胁',
           icon: 'flash_on',
           value: '500',
           color1: '#f37169',
           color2: '#f34636'
         },
         {
           title: '忽略的威胁',
           icon: 'texture',
           value: '50',
           color1: '#ea6a7f',
           color2: '#ea4b64'
         },
         {
           title: '进行中的威胁',
           icon: 'bar_chart',
           value: '1020',
           color1: '#a270b1',
           color2: '#9f52b1'
         }
       ],
      dialog: false,
      maximizedToggle: true,
      server_threat: {},
      select_chain_data: {}
    }
  },
  methods: {
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
        series: [
          {
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
            symbolSize: [40, 50], // 宽40 高50
            symbol:
              'image://data:image/png;base64,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',
            expandAndCollapse: true,
            animationDuration: 550,
            animationDurationUpdate: 750
          }
        ]
      }
      myChart.setOption(option)
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
    get_threatStatistics () {
      axios
        .get('/api/v1/get/threat_statistics', {
          'Content-Type': 'application/json'
        })
        .then((response) => {
          const data = response.data
          if (data.data) {
            this.threatStatistics = data.data
            // Threatitems
            this.Threatitems[0].value = this.threatStatistics.all
            this.Threatitems[1].value = this.threatStatistics.confirm
            this.Threatitems[2].value = this.threatStatistics.ingore
            this.Threatitems[3].value = this.threatStatistics.working
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
            this.get_threatStatistics()
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
