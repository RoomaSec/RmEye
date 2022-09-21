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
                            </q-item-section>
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
import {
  defineComponent
} from 'vue'
import axios from 'axios'
import * as echarts from 'echarts'
export default defineComponent({
  name: 'Dashboard',
  data () {
    return {
      Threatitems: [{
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
  }
})
</script>
