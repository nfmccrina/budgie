import Vue from 'vue'
import Vuex from 'vuex'
import util from '../util/budgieutil'

Vue.use(Vuex)

export default new Vuex.Store({
	state: {
		userToken: '',
		isLoggedIn: false,
		user: {
			name: '',
			id: '',
			categories: []
		}
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
		},
		addCategory (state, category) {
			if (!state.user.categories) {
				state.user.categories = []
			}

			state.user.categories.push(category)
		}
	},
	actions: {
		addCategory (context, category) {
			context.commit('addCategory', category)

			return util.ajaxRequest('http://localhost:3000/api/user/category', context.state.userToken, 'post', category)
				.catch((err) => {
					alert('error!')
				})
		},

		loadUser (context) {
			util.ajaxRequest('http://localhost:3000/api/user', context.state.userToken)
				.then((response) => context.commit('saveUser', response.data))
		},
		validateToken(context, token) {
			util.ajaxRequest('http://localhost:3000/api/token/validate', token)
				.then((response) => {
					if (response.data.isValid) {
						context.commit('updateUserToken', token)
						context.commit('updateLoggedIn', true)
						context.dispatch('loadUser')
					}
				})
		}
	}
})