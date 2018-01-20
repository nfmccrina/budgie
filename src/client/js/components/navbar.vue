<template>
	<nav class="navbar" role="navigation" arial-label="main navigation">
		<div class="navbar-brand">
			<router-link class="navbar-item" to="/">
				<img src="media/logo.png" />
			</router-link>

			<button class="button navbar-burger">
				<span></span>
				<span></span>
				<span></span>
			</button>
		</div>
		<div class="navbar-menu">
			<div class="navbar-start">
				<router-link class="navbar-item" to="/">Home</router-link>
				<router-link class="navbar-item" to="/categories">Categories</router-link>
			</div>
			<div class="navbar-end">
				<div class="navbar-item" v-if="!isLoggedIn">
					<div class="field">
						<p class="control">
							<a class="button" v-on:click="loginButton_onClick">
								<span>Login</span>
							</a>
						</p>
					</div>
				</div>
				<div class="navbar-item" v-else>
					<p>Hello {{ userName }}</p>
				</div>
			</div>
		</div>
	</nav>
</template>

<script>
	import authService from '../auth/authService'

	export default {
		computed: {
			isLoggedIn () {
				return this.$store.state.isLoggedIn
			},
			userName () {
				return this.$store.state.user.name
			}
		},
		methods: {
			loginButton_onClick () {
				authService.login()
			}
		}
	}
</script>