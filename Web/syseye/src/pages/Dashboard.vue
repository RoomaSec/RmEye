<template>
<div class="q-gutter-md q-mb-sm q-pa-lg">
    <div>
        <q-card class="bg-transparent no-shadow no-border">
            <q-card-section class="q-pa-none">
                <div class="row q-col-gutter-sm">
                    <div v-for="(item, index) in Threatitems" :key="index" class="col-md-3 col-sm-12 col-xs-12">
                        <q-item :style="`background-color: ${item.color1}`" class="q-pa-none">
                            <q-item-section side :style="`background-color: ${item.color2}`" class="q-pa-lg q-mr-none text-white">
                                <q-icon :name="item.icon" color="white" size="24px"></q-icon>
                            </q-item-section>
                            <q-item-section class="q-pa-md q-ml-none text-white">
                                <q-item-label class="text-white text-h6 text-weight-bolder">{{
                  item.value
                }}</q-item-label>
                                <q-item-label>{{ item.title }}</q-item-label>
                                <q-popup-proxy>
                                <q-banner>
                                    <q-color v-model="item.color1" @change="updateCookie(Threatitems[index].color1)" class="my-picker" />
                                </q-banner>
                            </q-popup-proxy>
                            </q-item-section>
                            <q-popup-proxy>
                                <q-banner>
                                    <q-color v-model="item.color2" @change="updateCookie(Threatitems[index].color2)" class="my-picker" />
                                </q-banner>
                            </q-popup-proxy>
                        </q-item>
                    </div>
                </div>
            </q-card-section>
        </q-card>
    </div>
    <q-card class="no-shadow" style="background: rbg(255,255,255)">
        <q-card-section>
            <div class="text-h6">
                主机数量: {{threatStatistics.host_num}}/50 <q-icon name="info" class="text-brown cursor-pointer">
                    <q-popup-proxy transition-show="flip-up" transition-hide="flip-down">
                        <q-banner class="bg-brown text-white">
                            <template v-slot:avatar>
                                <q-icon name="lightbulb" />
                            </template>
                            由于python+sqlite数据库作为后端,理论上最高支持的主机数量为50.
                        </q-banner>
                    </q-popup-proxy>
                </q-icon>

            </div>
            <div class="text-subtitle2">最近日志数量: {{threatStatistics.all_log_num}}</div>
        </q-card-section>

        <q-card-section class="q-pt-none">
            <div ref="main_draw" style="width: 100%; height: 600px; ">
                1
            </div>
        </q-card-section>
    </q-card>

</div>
</template>

<script>
import Base64 from '../assets/b64.js'

import {
  defineComponent
} from 'vue'
import axios from 'axios'
import {
  Cookies
} from 'quasar'
import * as echarts from 'echarts'
export default defineComponent({
  name: 'Dashboard',
  data () {
    return {
      Threatitems: [{
        title: '发现的威胁',
        icon: 'remove_red_eye',
        value: '200',
        color1: '#EE9B00',
        color2: '#EE9B00'
      },
      {
        title: '确认的威胁',
        icon: 'flash_on',
        value: '500',
        color1: '#CA6702',
        color2: '#CA6702'
      },
      {
        title: '忽略的威胁',
        icon: 'add_moderator',
        value: '50',
        color1: '#BB3E03',
        color2: '#BB3E03'
      },
      {
        title: '进行中的威胁',
        icon: 'stream',
        value: '1020',
        color1: '#AE2012',
        color2: '#AE2012'
      }
      ],
      threatStatistics: {
        all: 1,
        confirm: 0,
        ingore: 1,
        working: 0,
        host_list: {},
        host_num: 10,
        all_log_num: 647
      }
    }
  },
  methods: {
    updateCookie (selectItem) {
      const b64Obj = new Base64()
      Cookies.set('custom_threat_item', b64Obj.encode(JSON.stringify(this.Threatitems)))
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
            this.threatStatistics.host_num = Object.keys(this.threatStatistics.host_list).length
            // Threatitems
            this.Threatitems[0].value = this.threatStatistics.all
            this.Threatitems[1].value = this.threatStatistics.confirm
            this.Threatitems[2].value = this.threatStatistics.ingore
            this.Threatitems[3].value = this.threatStatistics.working
            console.log(this.threatStatistics)

            this.draw()
          }
        })
    },
    draw () {
      const hostList = []
      const hostLoggedNumList = []
      for (const key in this.threatStatistics.host_list) {
        hostList.push(key)
        hostLoggedNumList.push({
          itemStyle: {
            color: '#005F73'
          },
          name: key,
          type: 'line',
          stack: 'Total',
          areaStyle: {},
          emphasis: {
            focus: 'series'
          },
          data: this.threatStatistics.host_list[key].log_num
        })
      }
      const dom = this.$refs.main_draw
      const myChart = echarts.init(dom)
      const option = {
        title: {
          text: '最近十分钟日志量'
        },
        tooltip: {
          trigger: 'axis',
          axisPointer: {
            type: 'cross',
            label: {
              backgroundColor: '#6a7985'
            }
          }
        },
        legend: {
          data: hostList
        },
        toolbox: {
          feature: {
            saveAsImage: {}
          }
        },
        grid: {
          left: '3%',
          right: '4%',
          bottom: '3%',
          containLabel: true
        },
        xAxis: [{
          type: 'category',
          boundaryGap: false,
          data: ['10min', '9min', '8min', '7min', '6min', '5min', '4min', '3min', '2min', '1min']
        }],
        yAxis: [{
          type: 'value'
        }],
        series: hostLoggedNumList
      }
      myChart.setOption(option)
      setTimeout(() => {
        myChart.resize()
      }, 1000)
    }
  },
  mounted () {
    this.get_threatStatistics()
    setInterval(() => {
      this.get_threatStatistics()
    }, 10000)
    const cookieCustomThreatItem = Cookies.get('custom_threat_item')
    if (cookieCustomThreatItem) {
      const b64Obj = new Base64()

      this.Threatitems = JSON.parse(b64Obj.decode(cookieCustomThreatItem))
    }
  }
})
</script>
