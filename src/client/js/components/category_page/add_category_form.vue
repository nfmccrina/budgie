<template>
	<div>
		<h1 class="title">Add New Category</h1>
		<form>
			<div class="field">
				<label class="label">Category Name</label>
				<div class="control">
					<input v-model="newCategoryName" class="input" type="text" />
				</div>
			</div>
			<div class="field">
				<div class="control">
					<button class="is-primary" v-on:click="addButton_onClick">Add</button>
				</div>
			</div>
		</form>
	</div>
</template>

<script type="text/javascript">
	export default {
		data () {
			return {
				newCategoryName: ''
			}
		},
		methods: {
			addButton_onClick: function (e) {
				this.$store.dispatch('addCategory', this.buildCategoryFromForm())
				this.clearForm()
				return false
			},
			buildCategoryFromForm: function () {
				return {
					name: this.newCategoryName
				}
			},
			clearForm: function () {
				this.newCategoryName = ''
			}
		}
	}
</script>