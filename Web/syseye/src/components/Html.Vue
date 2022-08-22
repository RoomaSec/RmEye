<template>
  <div v-html="html"></div>
</template>
<script>
import axios from 'axios'
import { defineComponent } from 'vue'

export default defineComponent({
  props: { url: { required: true } },
  data () {
    return { html: '' }
  },
  watch: {
    url (value) {
      this.load(value)
    }
  },
  mounted () {
    this.load(this.url)
  },
  methods: {
    load (url) {
      if (url && url.length > 0) {
        const param = { accept: 'text/html, text/plain' }
        axios
          .get(url, param)
          .then((response) => {
            this.html = response.data
          })
          .catch(() => {
            this.html = '加载失败'
          })
      }
    }
  }
})
</script>
