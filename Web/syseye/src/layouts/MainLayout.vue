<template>
<q-layout view="lHh Lpr lFf" :style="`background-color: ${colors.background}`">
    <q-header elevated height-hint="98">
        <q-toolbar class="text-white" :style="`background-color: ${colors.toolbar}`">
            <q-toolbar-title> RmEye测试版v1.0.1.3 </q-toolbar-title>
            <q-btn flat dense icon="restore" label="重置颜色" @click="cleanUpCookie">
            </q-btn>
            <q-popup-proxy>
                <q-banner>
                    <q-color v-model="colors.toolbar" @change="updateCookie(colors.toolbar)" class="my-picker" />
                </q-banner>
            </q-popup-proxy>
        </q-toolbar>
        <q-toolbar :style="`font-size: 16px;background-color: ${colors.layout}`">
            <q-breadcrumbs active-color="white">
                <q-breadcrumbs-el label="仪表盘" icon="dashboard" to="/page/dashboard" />
                <q-breadcrumbs-el label="未处理威胁列表" icon="report" to="#" @click="routerToThreatList(0);" />
                <q-breadcrumbs-el label="已处理威胁列表" icon="done" to="#" @click="routerToThreatList(1);" />
                <q-breadcrumbs-el label="已忽略威胁列表" icon="texture" to="#" @click="routerToThreatList(2);" />
                <q-breadcrumbs-el label="白名单列表" icon="list" to="#" @click="routerToWhiteList();" />
            </q-breadcrumbs>

                <q-popup-proxy>
                    <q-banner>
                        <q-color v-model="colors.layout" @change="updateCookie(colors.layout)" class="my-picker" />
                    </q-banner>
                </q-popup-proxy>
        </q-toolbar>
    </q-header>
    <template v-if="isInPlugin == false">
        <q-page-container>
            <router-view />
        </q-page-container>
    </template>
    <template v-if="isInPlugin">
        <div class="q-gutter-md q-mb-sm q-pa-lg">
            <HtmlPanel v-model:url="PluginUrl" />
        </div>
    </template>
</q-layout>
</template>

<script>
import Base64 from '../assets/b64.js'

import {
  defineComponent
} from 'vue'
import HtmlPanel from '../components/Html.vue' // 根据实际路径导入
import axios from 'axios'
import {
  Cookies
} from 'quasar'
export default defineComponent({
  components: {
    HtmlPanel
  },
  name: 'MainLayout',
  setup () {
    return {}
  },
  data: function () {
    return {
      selectLabel: 'dashboard',
      drawer: false,
      miniState: true,
      plugin: [],
      isInPlugin: false,
      PluginUrl: '',
      colors: {
        layout: 'rgb(47,43,48)',
        toolbar: 'rgb(210,61,42)',
        background: 'rgb(239, 243, 246)'
      }
    }
  },
  methods: {
    updateCookie (selectItem) {
      const b64Obj = new Base64()
      Cookies.set('custom_banner', b64Obj.encode(JSON.stringify(this.colors)))
    },
    cleanUpCookie () {
      Cookies.remove('custom_threat_item')
      Cookies.remove('custom_banner')

      // refesh
      window.location.reload()
    },
    routerToWhiteList () {
      this.isInPlugin = false
      this.$router.push({
        name: 'whitelist'
      })
    },
    routerToThreatList (index) {
      this.isInPlugin = false
      this.$router.push({
        name: 'index',
        params: {
          queryIndex: index
        }
      })
    },
    routerToPlugin (url) {
      this.isInPlugin = true
      this.PluginUrl = '/plugin/' + url
    },
    getPluginsMenu () {
      axios
        .get('/api/v1/get/plugin_menu', {
          'Content-Type': 'application/json'
        })
        .then((response) => {
          this.plugin = response.data.data.menu
          console.log(this.plugin)
        })
    }
  },
  mounted () {
    this.getPluginsMenu()
    const coockieCustomBanner = Cookies.get('custom_banner')
    if (coockieCustomBanner) {
      const b64Obj = new Base64()
      this.colors = JSON.parse(b64Obj.decode(coockieCustomBanner))
    }
  }
})
</script>

<style lang="sass">
.menu-active
  color: white
  background: #F2C037
</style>
<style type="text/css">
::-webkit-scrollbar {
  /*滚动条整体样式*/
  width: 5px;
  /*高宽分别对应横竖滚动条的尺寸*/
  height: 4px;
}

::-webkit-scrollbar-thumb {
  /*滚动条里面小方块*/
  border-radius: 15px;
  -webkit-box-shadow: inset 0 0 5px rgba(0, 0, 0, 0.2);
  background: rgb(47,43,48);
}

::-webkit-scrollbar-track {
  /*滚动条里面轨道*/
  -webkit-box-shadow: inset 0 0 5px rgba(0, 0, 0, 0.2);
  border-radius: 15px;
  background: #ededed;
}
</style>
