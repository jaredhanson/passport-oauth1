var OAuthStrategy = require('../lib/strategy')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai');


describe('OAuthStrategy', function() {
    
  describe('constructed', function() {
    var strategy = new OAuthStrategy({
      requestTokenURL: 'https://www.example.com/oauth/request_token',
      accessTokenURL: 'https://www.example.com/oauth/access_token',
      userAuthorizationURL: 'https://www.example.com/oauth/authorize',
      consumerKey: 'ABC123',
      consumerSecret: 'secret'
    }, function() {});
    
    it('should be named oauth', function() {
      expect(strategy.name).to.equal('oauth');
    });
  
    it('should have user agent header set by underlying oauth module', function() {
      expect(Object.keys(strategy._oauth._headers)).to.have.length(3);
      expect(strategy._oauth._headers['User-Agent']).to.equal('Node authentication');
    });
  }); // constructed
  
  describe('constructed with custom headers', function() {
    var strategy = new OAuthStrategy({
      requestTokenURL: 'https://www.example.com/oauth/request_token',
      accessTokenURL: 'https://www.example.com/oauth/access_token',
      userAuthorizationURL: 'https://www.example.com/oauth/authorize',
      consumerKey: 'ABC123',
      consumerSecret: 'secret',
      customHeaders: { 'X-FOO': 'bar' }
    }, function() {});
    
    it('should be named oauth', function() {
      expect(strategy.name).to.equal('oauth');
    });
  
    it('should have user agent header set by underlying oauth module', function() {
      expect(Object.keys(strategy._oauth._headers)).to.have.length(1);
      expect(strategy._oauth._headers['X-FOO']).to.equal('bar');
    });
  }); // constructed with custom headers
  
  describe('constructed without a verify callback', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        });
      }).to.throw(TypeError, 'OAuthStrategy requires a verify callback');
    });
  }); // constructed without a verify callback
  
  describe('constructed without a requestTokenURL option', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a requestTokenURL option');
    });
  }); // constructed without a requestTokenURL option
  
  describe('constructed without an accessTokenURL option', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a accessTokenURL option');
    });
  }); // constructed without an accessTokenURL option
  
  describe('constructed without a userAuthorizationURL option', function() {
    it('should throw if constructed without a userAuthorizationURL option', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a userAuthorizationURL option');
    });
  }); // constructed without a userAuthorizationURL option
  
  describe('constructed without a consumerKey option', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerSecret: 'secret'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a consumerKey option');
    });
  }); // constructed without a consumerKey option
  
  describe('constructed without a consumerSecret option', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a consumerSecret option');
    });
  }); // constructed without a consumerSecret option
  
  describe('constructed with an empty string as consumerSecret option', function() {
    it('should not throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: ''
        }, function() {});
      }).to.not.throw();
    });
  }); // constructed with an empty string as consumerSecret option'
  
  describe('constructed with only a verify callback', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy(function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a requestTokenURL option');
    });
  }); // constructed with only a verify callback
  
  
  
  describe('issuing authorization request', function() {
    
    describe('that redirects to service provider', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== undefined) { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
      }
    
    
      var request
        , url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    }); // that redirects to service provider
    
    describe('that redirects to service provider whose user authorization URL contains query parameters', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize?foo=bar',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== undefined) { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
      }
    
    
      var request
        , url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?foo=bar&oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    }); // that redirects to service provider whose user authorization URL contains query parameters
    
    describe('that redirects to service provider with absolute callback URL', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback'
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
      }
    
    
      var request
        , url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    }); // that redirects to service provider with absolute callback URL
    
    describe('that redirects to service provider with absolute callback URL that is not confirmed', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback'
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== 'https://www.example.net/auth/example/callback') { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
      }
    
    
      var request
        , url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola&oauth_callback=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    }); // that redirects to service provider with absolute callback URL that is not confirmed
    
    describe('that redirects to service provider with relative callback URL', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        callbackURL: '/auth/example/cb'
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== 'https://www.example.net/auth/example/cb') { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
      }
    
    
      var request
        , url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.url = '/auth/example'
            req.headers.host = 'www.example.net';
            req.session = {};
            req.connection = { encrypted: true };
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    }); // that redirects to service provider with relative callback URL
    
    describe('that redirects to service provider with relative callback URL from insecure connection', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        callbackURL: '/auth/example/cb'
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== 'http://www.example.net/auth/example/cb') { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
      }
    
    
      var request
        , url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.url = '/auth/example'
            req.headers.host = 'www.example.net';
            req.session = {};
            req.connection = {};
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    }); // that redirects to service provider with relative callback URL from insecure connection
    
    describe('that redirects to service provider with callback URL overridden by absolute URL as option', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback'
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== 'https://www.example.net/auth/example/callback/alt1') { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
      }
    
    
      var request
        , url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate({ callbackURL: 'https://www.example.net/auth/example/callback/alt1' });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    }); // that redirects to service provider with callback URL overridden by absolute URL as option
    
    describe('that redirects to service provider with callback URL overridden by relative URL as option', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback'
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== 'https://www.example.net/auth/example/callback/alt2') { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
      }
    
    
      var request
        , url;
  
      before(function(done) {
        chai.passport.use(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.url = '/auth/example'
            req.headers.host = 'www.example.net';
            req.session = {};
            req.connection = { encrypted: true };
          })
          .authenticate({ callbackURL: '/auth/example/callback/alt2' });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    }); // that redirects to service provider with callback URL overridden by relative URL as option
    
    describe('that errors due to request token request error', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        callback(new Error('error obtaining request token'));
      }
      
      
      var request
        , err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain request token');
        expect(err.oauthError.message).to.equal('error obtaining request token');
      });
      
      it('should not store token and token secret in session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that errors due to request token request error
    
    describe('that errors due to request token request error, in node-oauth object literal form', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        callback({ statusCode: 500, data: 'Something went wrong' });
      }
      
      
      var request
        , err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain request token');
        expect(err.oauthError.statusCode).to.equal(500);
        expect(err.oauthError.data).to.equal('Something went wrong');
      });
      
      it('should not store token and token secret in session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that errors due to request token request error
    
    describe('that errors due to lack of session support in app', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== undefined) { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
      }
    
    
      var request
        , err;
  
      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
          })
          .authenticate();
      });
  
      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('OAuth authentication requires session support. Did you forget to use express-session middleware?');
      });
    }); // that errors due to lack of session support in app
    
    describe('from behind a secure proxy', function() {
      
      describe('that is trusted by app and sets x-forwarded-proto', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          callbackURL: '/auth/example/cb'
        }, function() {});
    
        strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
          if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
          if (extraParams.oauth_callback !== 'https://www.example.net/auth/example/cb') { return callback(new Error('incorrect oauth_callback argument')); }
    
          callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
        }
    
    
        var request
          , url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.url = '/auth/example'
              req.headers.host = 'www.example.net';
              req.headers['x-forwarded-proto'] = 'https';
              req.session = {};
              req.connection = {};
              
              req.app = {
                get: function(name) {
                  return name == 'trust proxy' ? true : false;
                }
              }
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
        });
    
        it('should store token and token secret in session', function() {
          expect(request.session['oauth']).to.not.be.undefined;
          expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
          expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
        });
      }); // that is trusted by app and sets x-forwarded-proto
      
      describe('that is trusted by app and sets x-forwarded-proto and x-forwarded-host', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          callbackURL: '/auth/example/cb'
        }, function() {});
    
        strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
          if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
          if (extraParams.oauth_callback !== 'https://www.example.net/auth/example/cb') { return callback(new Error('incorrect oauth_callback argument')); }
    
          callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
        }
    
    
        var request
          , url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.headers.host = 'server.internal';
              req.headers['x-forwarded-proto'] = 'https';
              req.headers['x-forwarded-host'] = 'www.example.net';
              req.session = {};
              req.connection = {};
              
              req.app = {
                get: function(name) {
                  return name == 'trust proxy' ? true : false;
                }
              }
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
        });
    
        it('should store token and token secret in session', function() {
          expect(request.session['oauth']).to.not.be.undefined;
          expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
          expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
        });
      }); // that is trusted by app and sets x-forwarded-proto and x-forwarded-host
      
      describe('that is not trusted by app and sets x-forwarded-proto', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          callbackURL: '/auth/example/cb'
        }, function() {});
    
        strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
          if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
          if (extraParams.oauth_callback !== 'http://www.example.net/auth/example/cb') { return callback(new Error('incorrect oauth_callback argument')); }
    
          callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
        }
    
    
        var request
          , url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.url = '/auth/example'
              req.headers.host = 'www.example.net';
              req.headers['x-forwarded-proto'] = 'https';
              req.session = {};
              req.connection = {};
              
              req.app = {
                get: function(name) {
                  return name == 'trust proxy' ? false : false;
                }
              }
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
        });
    
        it('should store token and token secret in session', function() {
          expect(request.session['oauth']).to.not.be.undefined;
          expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
          expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
        });
      }); // that is not trusted by app and sets x-forwarded-proto
      
      describe('that is not trusted by app and sets x-forwarded-proto and x-forwarded-host', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          callbackURL: '/auth/example/cb'
        }, function() {});
    
        strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
          if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
          if (extraParams.oauth_callback !== 'http://server.internal/auth/example/cb') { return callback(new Error('incorrect oauth_callback argument')); }
    
          callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
        }
    
    
        var request
          , url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.url = '/auth/example'
              req.headers.host = 'server.internal';
              req.headers['x-forwarded-proto'] = 'https';
              req.headers['x-forwarded-host'] = 'www.example.net';
              req.session = {};
              req.connection = {};
              
              req.app = {
                get: function(name) {
                  return name == 'trust proxy' ? false : false;
                }
              }
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
        });
    
        it('should store token and token secret in session', function() {
          expect(request.session['oauth']).to.not.be.undefined;
          expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
          expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
        });
      }); // that is not trusted by app and sets x-forwarded-proto
      
      describe('that is trusted by strategy and sets x-forwarded-proto', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          callbackURL: '/auth/example/cb',
          proxy: true
        }, function() {});
    
        strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
          if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
          if (extraParams.oauth_callback !== 'https://www.example.net/auth/example/cb') { return callback(new Error('incorrect oauth_callback argument')); }
    
          callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
        }
    
    
        var request
          , url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.url = '/auth/example'
              req.headers.host = 'www.example.net';
              req.headers['x-forwarded-proto'] = 'https';
              req.session = {};
              req.connection = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
        });
    
        it('should store token and token secret in session', function() {
          expect(request.session['oauth']).to.not.be.undefined;
          expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
          expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
        });
      }); // that is trusted by strategy and sets x-forwarded-proto
      
      describe('that is trusted by strategy and sets x-forwarded-proto and x-forwarded-host', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          callbackURL: '/auth/example/cb',
          proxy: true
        }, function() {});
    
        strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
          if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
          if (extraParams.oauth_callback !== 'https://www.example.net/auth/example/cb') { return callback(new Error('incorrect oauth_callback argument')); }
    
          callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', { oauth_callback_confirmed: 'true' });
        }
    
    
        var request
          , url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.url = '/auth/example'
              req.headers.host = 'server.internal';
              req.headers['x-forwarded-proto'] = 'https';
              req.headers['x-forwarded-host'] = 'www.example.net';
              req.session = {};
              req.connection = {};
            })
            .authenticate();
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
        });
    
        it('should store token and token secret in session', function() {
          expect(request.session['oauth']).to.not.be.undefined;
          expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
          expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
        });
      }); // that is trusted by strategy and sets x-forwarded-proto and x-forwarded-host
      
    }); // from behind a proxy
    
  }); // issuing authorization request
  
  
  describe('processing response to authorization request', function() {
    
    describe('that was approved', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return callback(new Error('incorrect tokenSecret argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      };
    
    
      var request
        , user
        , info;
  
      before(function(done) {
        chai.passport.use(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });
  
      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that was approved
    
    describe('that was approved using verify callback that accepts params', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, params, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return callback(new Error('incorrect tokenSecret argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
        if (params.elephant != 'purple') { return callback(new Error('incorrect params argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', { elephant: 'purple' });
      };
    
    
      var request
        , user
        , info;
  
      before(function(done) {
        chai.passport.use(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });
  
      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that was approved using verify callback that accepts params
    
    describe('that was approved using verify callback, in passReqToCallback mode', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        passReqToCallback: true
      }, function(req, token, tokenSecret, profile, done) {
        if (req.method != 'GET') { return callback(new Error('incorrect req argument')); }
        if (token != 'nnch734d00sl2jdk') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return callback(new Error('incorrect tokenSecret argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      };
    
    
      var request
        , user
        , info;
  
      before(function(done) {
        chai.passport.use(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });
  
      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that was approved using verify callback, in passReqToCallback mode
    
    describe('that was approved using verify callback that accepts params, in passReqToCallback mode', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        passReqToCallback: true
      }, function(req, token, tokenSecret, params, profile, done) {
        if (req.method != 'GET') { return callback(new Error('incorrect req argument')); }
        if (token != 'nnch734d00sl2jdk') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return callback(new Error('incorrect tokenSecret argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
        if (params.elephant != 'purple') { return callback(new Error('incorrect params argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', { elephant: 'purple' });
      };
    
    
      var request
        , user
        , info;
  
      before(function(done) {
        chai.passport.use(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });
  
      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that was approved using verify callback that accepts params, in passReqToCallback mode
    
    describe('that fails due to verify callback supplying false', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(null, false);
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      };
    
    
      var request
        , info;
  
      before(function(done) {
        chai.passport.use(strategy)
          .fail(function(i) {
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });
  
      it('should not supply info', function() {
        expect(info).to.be.undefined;
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that fails due to verify callback supplying false
    
    describe('that fails due to verify callback supplying false with additional info', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(null, false, { message: 'Invite required' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      };
    
    
      var request
        , info;
  
      before(function(done) {
        chai.passport.use(strategy)
          .fail(function(i) {
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });
  
      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Invite required');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that fails due to verify callback supplying false with additional info
    
    describe('that errors due to lack of session support in app', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback(new Error('OAuth#getOAuthAccessToken should not be called'));
      };
      
      
      var request
        , err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('OAuth authentication requires session support. Did you forget to use express-session middleware?');
      });
    }); // that errors due to lack of session support in app
    
    describe('that errors due to request token not being found in session', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback(new Error('OAuth#getOAuthAccessToken should not be called'));
      };
      
      
      var request
        , err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('Failed to find request token in session');
      });
    
      it('should leave session unmodified', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that errors due to request token not being found in session
    
    describe('that errors due to access token request error', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(new Error('error obtaining access token'));
      }
      
      
      var request
        , err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain access token');
        expect(err.oauthError.message).to.equal('error obtaining access token');
      });
      
      it('should not remove token and token secret from session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    }); // that errors due to access token request error
    
    describe('that errors due to verify callback supplying error', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('something went wrong'));
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
      
      
      var request
        , err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('something went wrong');
      });
      
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that errors due to verify callback supplying error
    
    describe('that errors due to verify callback throwing error', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        throw new Error('something was thrown');
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
      
      
      var request
        , err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('something was thrown');
      });
      
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that errors due to verify callback throwing error
    
  }); // processing response to authorization request
  
});
