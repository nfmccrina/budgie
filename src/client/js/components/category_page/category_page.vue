<template>
	<div>
		<h1 class="title">Your Categories</h1>
		<ul>
			<li v-for="c in categories" v-bind:key="c.id">
				<CategoryItem v-bind:item="c"></CategoryItem>
			</li>
		</ul>
		<AddCategoryForm></AddCategoryForm>
	</div>
</template>

<script>
	import AddCategoryForm from './add_category_form.vue'
	import CategoryItem from './category_item.vue'
	
	export default {
		computed: {
			categories () {
				return this.$store.state.user.categories
			}
		},
		components: {
			AddCategoryForm,
			CategoryItem
		}
	}
</script>