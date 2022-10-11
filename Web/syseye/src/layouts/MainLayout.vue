<template>
<q-layout view="lHh Lpr lFf" style="background-color: rgb(239, 243, 246)">
    <q-header elevated height-hint="98">
        <q-toolbar class="text-white" style="background-color: rgb(210,61,42)">
            <q-toolbar-title> RmEye测试版v1.0.1.3 </q-toolbar-title>
            <q-btn flat round dense icon="lightbulb"></q-btn>
        </q-toolbar>
        <q-toolbar style="font-size: 16px;background-color:rgb(47,43,48);">
            <q-breadcrumbs active-color="white">
                <q-breadcrumbs-el label="仪表盘" icon="dashboard" to="/page/dashboard" />
                <q-breadcrumbs-el label="未处理威胁列表" icon="report" to="#" @click="routerToThreatList(0);" />
                <q-breadcrumbs-el label="已处理威胁列表" icon="done" to="#" @click="routerToThreatList(1);" />
                <q-breadcrumbs-el label="已忽略威胁列表" icon="texture" to="#" @click="routerToThreatList(2);" />
                <q-breadcrumbs-el label="白名单列表" icon="list" to="#" @click="routerToWhiteList();" />
            </q-breadcrumbs>
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
import {
  defineComponent
} from 'vue'
import HtmlPanel from '../components/Html.vue' // 根据实际路径导入
import axios from 'axios'
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
      PluginUrl: ''
    }
  },
  methods: {
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
