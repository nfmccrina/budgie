<template>
	<router-view></router-view>
</template>

<script>
	import util from '../util/budgieutil'
	
	export default {
		mounted () {
			var accessTokenString = util.extractHashParam(this.$route.params, 'access_token')

			if (accessTokenString) {
				this.$store.dispatch('validateToken', accessTokenString)
			}
		}
	}
</script>

<style>
</style>