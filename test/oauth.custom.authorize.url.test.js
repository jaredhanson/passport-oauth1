var chai = require('chai')
  , OAuthStrategy = require('../lib/strategy');


describe('OAuthStrategy', function() {

  describe('that is given no userAuthorizationURLProvider', function() {
    it('should require userAuthorizationURL option', function() {
      var strategyConstructor = OAuthStrategy.bind(
        function () {},
        {
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );

      expect(strategyConstructor).to.throw(TypeError,
        'OAuthStrategy requires a userAuthorizationURL option if no userAuthorizationURLProvider is given');
    });
  });

  describe('that is given a userAuthorizationURLProvider', function() {
    it('should not require userAuthorizationURL option', function() {
      var strategyConstructor = OAuthStrategy.bind(
        function () {},
        {
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          userAuthorizationURLProvider: function(req, res) {
          }
        },
        function() {}
      );

      expect(strategyConstructor).to.not.throw(TypeError);
    });
  });

  describe('that is given both userAuthorizationURL and userAuthorizationURLProvider', function() {
    it('should be constructed wihtout issues', function() {
      var strategyConstructor = OAuthStrategy.bind(
        function () {},
        {
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          userAuthorizationURLProvider: function(req, res) {
          }
        },
        function() {}
      );

      expect(strategyConstructor).to.not.throw(TypeError);
    });
  });

});
