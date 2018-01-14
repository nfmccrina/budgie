export default class {
	extractHashParam (params, paramName) {
		var indexOfParam = (el) => {
			return el.indexOf(paramName + '=')
		}

		var indexOfDelimiter = (el, startIndex) => {
			if (el.indexOf('&', startIndex) === -1) {
				return el.length
			} else {
				return el.indexOf('&', startIndex)
			}
		}

		return Object.values(params)
			.filter((el) => indexOfParam(el) !== -1)
			.map((el) => el.substring(indexOfParam(el) + paramName.length + 1, indexOfDelimiter(el, indexOfParam(el))))
			.find((el) => true)
	}
}