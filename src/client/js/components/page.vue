<template>
	<div>
		<NavBar></NavBar>
		<section class="section">
			<div class="container">
				<router-view></router-view>
			</div>
		</section>
	</div>
</template>

<script>
	import NavBar from './navbar.vue'

	export default {
		components: {
			NavBar
		}
	}
</script>