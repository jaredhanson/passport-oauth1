var utils = require('../utils');


function SessionStore(options) {
  options = options || {};
  this._key = options.key || 'oauth';
}

SessionStore.prototype.get = function(req, token, cb) {
  if (!req.session) { return cb(new Error('OAuth authentication requires session support. Did you forget to use express-session middleware?')); }
  
  var key = this._key + ':' + token;
  var state = req.session[key];
  
  // Bail if the session does not contain the request token and corresponding
  // secret.  If this happens, it is most likely caused by initiating OAuth
  // from a different host than that of the callback endpoint (for example:
  // initiating from 127.0.0.1 but handling callbacks at localhost).
  if (!state) { return cb(new Error('Failed to find request token in session')); }
  
  var tokenSecret = state.oauth_token_secret;
  delete state.oauth_token_secret;
  return cb(null, tokenSecret, state);
};

SessionStore.prototype.set = function(req, token, tokenSecret, meta, cb) {
  if (!req.session) { return cb(new Error('OAuth authentication requires session support. Did you forget to use express-session middleware?')); }
  
  var key = this._key + ':' + token;
  
  var state = {};
  utils.merge(state, meta.state || {});
  state.oauth_token_secret = tokenSecret;
  
  req.session[key] = state;
  cb();
};

SessionStore.prototype.destroy = function(req, token, cb) {
  var key = this._key + ':' + token;
  delete req.session[key];
  cb();
};


module.exports = SessionStore;
