import jsonwebtoken from 'jsonwebtoken'
import koaJwt from 'koa-jwt'

const CONTEXT_JWT = Symbol('context#jwt')

class Option {
  constructor (opt) {
    this.secret = opt.secret || 'my_token'
    this.ignore = opt.ignore
    this.expire = opt.expire || 2 * 60 * 60
    this.key = opt.key || 'user'
  }
}

class JWT {
  constructor (opt = {}) {
    this.secret = opt.secret
    this.expire = opt.expire
  }
  sign (payload, secret, opt = {}) {
    opt = {
      expiresIn: this.expire,
      ...opt
    }
    return jsonwebtoken.sign(payload, (secret || this.secret), opt)
  }
  /**
   * [verify description]
   * @param  {String} token             [description]
   * @param  {[type]} secret [secretOrPublicKey]
   * @param  {Object|Function} opt               [description]
   * @return {[type]}                   [description]
   */
  verify (token, secret, opt) {
    return jsonwebtoken.verify(token, (secret || this.secret), opt)
  }
}

class LonoJWT {
  constructor (opt = {}) {
    this.name = 'jwt'
    this.isLode = true
    this.opt = new Option(opt)
    this.token = null
  }
  install (lode) {
    if (lode.$config.jwt) Object.assign(this.opt, new Option(lode.$config.jwt))
    this.useJWT(lode)
  }
  useJWT (lode) {
    // 单例模式
    if (lode.context.hasOwnProperty(CONTEXT_JWT)) {
      return
    }
    const token = new JWT(this.opt)
    Object.defineProperties(lode.context, {
      [CONTEXT_JWT]: {
        value: token,
        writable: false
      },
      'jwt': {
        value: token,
        writable: false
      }
    })
    this.token = token
    lode.use(koaJwt({
      secret: this.opt.secret,
      key: this.key
    }).unless({
      path: this.opt.ignore
    }))
  }
}

export default function (...arg) {
  return new LonoJWT(...arg)
}
