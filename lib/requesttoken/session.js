function SessionStore(options) {
  if (!options.key) { throw new TypeError('Session-based request token store requires a key'); }
  this._key = options.key;
}

SessionStore.prototype.get = function(req, token, cb) {
  var tokenSecret = req.session[this._key].oauth_token_secret;
  return cb(null, tokenSecret);
};

SessionStore.prototype.set = function(req, token, tokenSecret, cb) {
  if (!req.session[this._key]) { req.session[this._key] = {}; }
  req.session[this._key].oauth_token = token;
  req.session[this._key].oauth_token_secret = tokenSecret;
  cb();
};

SessionStore.prototype.destroy = function(req, token, cb) {
  delete req.session[this._key].oauth_token;
  delete req.session[this._key].oauth_token_secret;
  if (Object.keys(req.session[this._key]).length === 0) {
    delete req.session[this._key];
  }
  cb();
};


module.exports = SessionStore;
