import Vue from 'vue'
import Vuex from 'vuex'
import util from '../util/budgieutil'
import deepClone from 'clone-deep'
import { win32 } from 'path';

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
		updateUserToken (state, token) {
			state.userToken = token
			window.sessionStorage.setItem('userToken', token)
		},
		saveUser (state, user) {
			state.user.name = user.name
			state.user.id = user.budgieId
			state.user.categories = user.categories.map((cat) => {
				return {
					id: cat._id,
					name: cat.name
				}
			})
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
			return util.ajaxRequest('http://localhost:3000/api/user/category', context.state.userToken, 'post', {
				category: category
			})
				.then((response) => {
					context.commit('addCategory', {
						id: response.data._id,
						name: response.data.name
					})
				})
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
					} else {
						window.sessionStorage.setItem('userToken', '')
					}
				})
				.catch((err) => {
					window.sessionStorage.setItem('userToken', '')
				})
		}
	}
})