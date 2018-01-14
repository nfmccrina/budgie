class ActionManager {
	constructor () {
		this.store = {}
	}

	setStore (s) {
		this.store = s
	}

	dispatch (actionName, params) {
		return this.store.dispatch.apply(this.store, [actionName].concat(params))
			.catch((err) => {
				if (err && err.response) {
					if (err.response.status === 401 || err.response.status === 403) {
						this.store.commit('updateLoggedIn', false)
					}
				}

				return null;
			})
	}
}

var actionManager = new ActionManager()

export default actionManager