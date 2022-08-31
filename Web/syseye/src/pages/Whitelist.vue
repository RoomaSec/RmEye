<template>
    <q-table
      class="q-pa-lg"
      :dense="$q.screen.lt.md"
      title="白名单列表"
      :columns="data_columns"
      :rows="data_columns_data"
      :loading="loading"
      v-model:pagination="pagination"
      @request="onRequest"
    >
      <template v-slot:body="props">
        <q-tr :props="props">
          <q-td key="path" :props="props">{{ props.row.path }}</q-td>
          <q-td key="hash" :props="props">{{ props.row.hash }}</q-td>
          <q-td key="reason" :props="props">{{ props.row.reason }}</q-td>
          <q-td key="timestamp" :props="props">{{ time_parase(props.row.timestamp) }}</q-td>
          <q-td key="action" :props="props">
            <q-btn color="red" label="移除白名单" @click="delete_white_hash(props.row.hash)"/>
          </q-td>
        </q-tr>
      </template>
    </q-table>
</template>

<script>
import {
  defineComponent
} from 'vue'
import axios from 'axios'

export default defineComponent({
  name: 'WhiteList',
  data: function () {
    return {
      data_columns: [
        {
          name: 'path',
          align: 'center',
          label: '路径',
          field: 'path'
        },
        {
          name: 'hash',
          align: 'center',
          label: 'hash',
          field: 'hash'
        },
        {
          name: 'reason',
          align: 'center',
          label: '原因',
          field: 'reason'
        },
        {
          name: 'timestamp',
          align: 'center',
          label: '时间',
          field: 'timestamp'
        },
        {
          name: 'action',
          align: 'center',
          label: '操作',
          field: 'steamid'
        }
      ],
      data_columns_data: [],
      loading: false,
      pagination: {
        sortBy: 'desc',
        descending: false,
        page: 1,
        rowsPerPage: 10,
        rowsNumber: 10
      }
    }
  },
  mounted () {
    this.onRequest({
      pagination: this.pagination,
      filter: undefined
    })
  },
  methods: {
    delete_white_hash (hash) {
      axios.get('/api/v1/del/white_list?hash=' + hash).then(res => {
        console.log('duck was gone')
      })
    },
    time_parase (pTime) {
      // shijianchuo是整数，否则要parseInt转换
      const add0 = m => {
        return m < 10 ? '0' + m : m
      }
      const time = new Date(Number(pTime))
      console.log('time', pTime)
      const y = time.getFullYear()
      const m = time.getMonth() + 1
      const d = time.getDate()
      const h = time.getHours()
      const mm = time.getMinutes()
      const s = time.getSeconds()
      return (
        y +
        '-' +
        add0(m) +
        '-' +
        add0(d) +
        ' ' +
        add0(h) +
        ':' +
        add0(mm) +
        ':' +
        add0(s)
      )
    },
    onRequest (props) {
      this.data_columns_data = []
      this.loading = true
      const { page } = props.pagination
      axios.get('/api/v1/query/white_list_all').then(response => {
        const data = response.data.result
        console.log(data)
        for (let index = 0; index < data.length; index++) {
          const element = data[index]
          this.data_columns_data.push(element)
        }
        this.pagination.page = page
        this.pagination.rowsNumber = this.data_columns_data.length
        this.pagination.rowsPerPage = this.data_columns_data.length
        this.loading = false
      })
    }
  }
})
</script>
