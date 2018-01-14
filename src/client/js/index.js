import Vue from 'vue'
import VueRouter from 'vue-router'
import Store from './store'
import App from './components/app.vue'
import Page from './components/page.vue'
import HomePage from './components/homepage.vue'
import CategoryPage from './components/category_page/category_page.vue'

Vue.use(VueRouter)

var routes = [
{
	path: '/*',
	component: Page,
	children: [
	{
		path: '/categories',
		component: CategoryPage
	},
	{
		path: '',
		component: HomePage,
	}]
}]

var router = new VueRouter({
	routes
});

/* eslint-disable no-new */
new Vue({
  el: '#app',
  render: h => h(App),
  router: router,
  store: Store
})