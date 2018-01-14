<template>
	<router-view></router-view>
</template>

<script>
	import BudgieUtil from '../util/budgieutil'
	import actionManager from '../store/action_manager'
	
	export default {
		mounted () {
			var util = new BudgieUtil()

			var accessTokenString = util.extractHashParam(this.$route.params, 'access_token')
			//var accessTokenString = 'dsfsdf'

			if (accessTokenString) {
				actionManager.setStore(this.$store)
				actionManager.dispatch('validateToken', [accessTokenString])
					.then((valid) => {
						if (valid) {
							this.$store.commit('updateUserToken', accessTokenString)
							this.$store.commit('updateLoggedIn', true)
						}
					})
			}
		}
	}
</script>

<style>
</style>