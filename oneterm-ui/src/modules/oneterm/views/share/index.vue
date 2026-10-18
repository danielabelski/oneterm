<template>
  <div v-if="shareId">
    <Terminal
      v-if="['ssh', 'telnet', 'mysql', 'redis', 'postgresql', 'mongodb'].includes(protocol)"
      :shareId="shareId"
    />
    <GuacamolePanel
      v-else-if="['rdp', 'vnc'].includes(protocol)"
      :shareId="shareId"
    />
  </div>
  <div v-else class="share-status">
    <a-spin v-if="loading" />
    <a-empty v-else :description="$t('oneterm.assetList.shareUnavailable')" />
  </div>
</template>

<script>
import Terminal from '@/modules/oneterm/views/connect/terminal/index.vue'
import GuacamolePanel from '@/modules/oneterm/views/connect/guacamoleClient/index.vue'
import { getShareConnectionInfo } from '@/modules/oneterm/api/connect'

export default {
  name: 'Share',
  components: {
    Terminal,
    GuacamolePanel
  },
  data() {
    return {
      shareId: '',
      protocol: '',
      loading: true,
      requestId: 0
    }
  },
  watch: {
    '$route.fullPath': {
      immediate: true,
      handler: 'loadShare'
    }
  },
  beforeDestroy() {
    this.requestId += 1
  },
  methods: {
    async loadShare() {
      const requestId = ++this.requestId
      const { params, fullPath } = this.$route
      this.shareId = ''
      this.loading = true
      try {
        if (!params.id) return
        const response = await getShareConnectionInfo(params.id)
        if (requestId !== this.requestId) return
        if (response.data.require_login && !response.data.authenticated) {
          this.$router.replace({ path: '/user/login', query: { redirect: fullPath } })
          return
        }
        this.protocol = params.protocol || ''
        this.shareId = params.id
      } catch (error) {
        if (requestId === this.requestId) this.shareId = ''
      } finally {
        if (requestId === this.requestId) this.loading = false
      }
    }
  }
}
</script>

<style lang="less" scoped>
.share-status {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 240px;
}
</style>
