import Vue from 'vue'
import Vuex from 'vuex'
import axios from 'axios'

Vue.use(Vuex)

export default new Vuex.Store({
	state: {
		userToken: '',
		isLoggedIn: false,
		user: {}
	},
	mutations: {
		/*setAppName (state, name) {
			state.appName = name;
		},
		updateCategories(state, categoryList) {
			state.user.categories.splice.apply(state.user.categories, [0, state.user.categories.length].concat(categoryList))
		},
		addCategory(state, category) {
			state.user.categories.push(category);
		}*/
		updateUserToken (state, token) {
			state.userToken = token
		},
		saveUser (state, user) {
			state.user = user
		},
		updateLoggedIn (state, value) {
			state.isLoggedIn = value
		}
	},
	actions: {
		/*getAppName (context) {
			axios.get('http://localhost:3000/api/user/name')
				.then((response) => {
					context.commit('setAppName', response.data.name)
				})
				.catch((err) => {
					context.commit('setAppName', '')
				})
		},
		loadCategoriesFromServer (context) {
			axios.get('http://localhost:3000/api/user/categories')
				.then((response) => {
					context.commit('updateCategories', response.data.categories)
				})
		},
		saveCategoriesToServer (context) {}*/
		loadUser (context) {
			return axios.get('http://localhost:3000/api/user', {
				headers: {
					'Authorization': 'Bearer ' + context.state.userToken
				}
			})
			.then((response) => {
				context.commit('saveUser', response.data)
				return response.data
			})
			.catch((err) => {
				//err.response.status
				return {}
			});
		},
		validateToken(context, token) {
			return axios.get('http://localhost:3000/api/token/validate', {
				headers: {
					'Authorization': 'Bearer ' + token
				}
			})
			.then((response) => response.data.isValid)
		}
	}
})