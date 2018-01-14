import auth0 from 'auth0-js'

class AuthService {

  constructor () {
    this.login = this.login.bind(this)
    this.auth0 = new auth0.WebAuth({
      domain: 'budgie.auth0.com',
      clientID: 'cfYX5vF_nIKjbSjAhI0U3o3Oa3kh_kfX',
      redirectUri: 'http://localhost:3000/',
      audience: 'https://www.budgie.com/api',
      responseType: 'token',
      scope: 'openid profile'
    })
  }

  login () {
    this.auth0.authorize()
  }
}

export default new AuthService()