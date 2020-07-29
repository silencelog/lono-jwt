"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = _default;

var _jsonwebtoken = _interopRequireDefault(require("jsonwebtoken"));

var _koaJwt = _interopRequireDefault(require("koa-jwt"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const CONTEXT_JWT = Symbol('context#lodeJWT');

class Option {
  constructor(opt) {
    this.secret = opt.secret || 'my_token';
    this.ignore = opt.ignore;
    this.expire = opt.expire || 2 * 60 * 60;
    this.key = opt.key || 'user';
  }

}

class JWT {
  constructor(opt = {}) {
    this.secret = opt.secret;
    this.expire = opt.expire;
  }

  sign(payload, secret, opt = {}) {
    opt = {
      expiresIn: this.expire,
      ...opt
    };
    return _jsonwebtoken.default.sign(payload, secret || this.secret, opt);
  }
  /**
   * [verify description]
   * @param  {String} token             [description]
   * @param  {[type]} secret [secretOrPublicKey]
   * @param  {Object|Function} opt               [description]
   * @return {[type]}                   [description]
   */


  verify(token, secret, opt) {
    return _jsonwebtoken.default.verify(token, secret || this.secret, opt);
  }

}

class LodeJWT {
  constructor(opt = {}) {
    this.name = 'jwt';
    this.isLode = true;
    this.opt = new Option(opt);
    this.token = null;
  }

  install(lode) {
    if (lode.$config.jwt) Object.assign(this.opt, new Option(lode.$config.jwt));
    this.useJWT(lode);
  }

  useJWT(lode) {
    // 单例模式
    if (lode.context.hasOwnProperty(CONTEXT_JWT)) {
      return;
    }

    const token = new JWT(this.opt);
    lode.context[CONTEXT_JWT] = token;
    lode.context.jwt = token;
    this.token = token;
    lode.use((0, _koaJwt.default)({
      secret: this.opt.secret,
      key: this.key
    }).unless({
      path: this.opt.ignore
    }));
  }

}

function _default(...arg) {
  return new LodeJWT(...arg);
}