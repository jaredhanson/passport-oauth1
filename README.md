# passport-oauth1

[![Build](https://travis-ci.org/jaredhanson/passport-oauth1.png)](http://travis-ci.org/jaredhanson/passport-oauth1)
[![Coverage](https://coveralls.io/repos/jaredhanson/passport-oauth1/badge.png)](https://coveralls.io/r/jaredhanson/passport-oauth1)
[![Dependencies](https://david-dm.org/jaredhanson/passport-oauth1.png)](http://david-dm.org/jaredhanson/passport-oauth1)

General-purpose OAuth 1.0 authentication strategy for [Passport](http://passportjs.org/).

This module lets you authenticate using OAuth in your Node.js applications.
By plugging into Passport, OAuth authentication can be easily and unobtrusively
integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

Note that this strategy provides generic OAuth support.  In many cases, a
provider-specific strategy can be used instead, which cuts down on unnecessary
configuration, and accommodates any provider-specific quirks.  See the
[list](https://github.com/jaredhanson/passport/wiki/Strategies) for supported
providers.

Developers who need to implement authentication against an OAuth provider that
is not already supported are encouraged to sub-class this strategy.  If you
choose to open source the new provider-specific strategy, send me a message and
I will update the list.

## Related Modules

- [passport-oauth2](https://github.com/jaredhanson/passport-oauth2) — OAuth 2.0 authentication strategy
- [passport-http-oauth](https://github.com/jaredhanson/passport-http-oauth) — OAuth authentication strategy for APIs
- [OAuthorize](https://github.com/jaredhanson/oauthorize) — OAuth service provider toolkit

## Tests

    $ npm install
    $ npm test

## Credits

  - [Jared Hanson](http://github.com/jaredhanson)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2011-2013 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
