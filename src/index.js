const OAuthServer = require('oauth2-server');
const debug = require('debug')('koa:oauth:provider');

const {
  Request, Response, InvalidArgumentError, InvalidScopeError
} = OAuthServer;

const handleError = (err, ctx) => {
  debug(`Preparing error response (${err.code || 500})`);
  const response = new Response(ctx.response);
  ctx.set(response.headers);
  ctx.status = err.code || 500;
  throw err;
};

const handleResponse = (ctx, response) => {
  debug(`Preparing success response (${response.status})`);
  ctx.set(response.headers);
  ctx.status = response.status;
  ctx.body = response.body;
};

class KoaOAuthServer {
  constructor(options = {}) {
    if (!options.model) {
      throw new InvalidArgumentError('Missing parameter: `model`');
    }
    // If no `saveTokenMetadata` method is set via the model, we create
    // a simple passthrough mechanism instead
    this.saveTokenMetadata = options.model.saveTokenMetadata
      ? options.model.saveTokenMetadata
      : token => Promise.resolve(token);

    // If no `checkScope` method is set via the model, we provide a default
    this.checkScope = options.model.checkScope
      ? options.model.checkScope
      : (scope, token) => token.scope.indexOf(scope) !== -1;

    this.server = new OAuthServer(options);
  }
  // Returns token authentication middleware
  authenticate() {
    return (ctx, next) => {
      const request = new Request(ctx.request);
      const response = new Response(ctx.response);

      return this.server.authenticate(request, response)
        .then((token) => {
          ctx.state.oauth = { token };
          return next();
        })
        .catch((err) => { handleError(err, ctx); });
    };
  }
  // Returns authorization endpoint middleware
  // Used by the client to obtain authorization from the resource owner
  authorize(options) {
    return (ctx, next) => {
      debug('Running authorize endpoint middleware');
      const request = new Request(ctx.request);
      const response = new Response(ctx.response);

      return this.server.authorize(request, response, options)
        .then((code) => {
          ctx.state.oauth = { code };
          handleResponse(ctx, response);
          return next();
        })
        .catch((err) => { handleError(err, ctx); });
    };
  }
  // Returns token endpoint middleware
  // Used by the client to exchange authorization grant for access token
  token() {
    return async (ctx, next) => {
      debug('Running token endpoint middleware');
      const request = new Request(ctx.request);
      const response = new Response(ctx.response);

      return this.server.token(request, response)
        .then(token => this.saveTokenMetadata(token, ctx.request))
        .then((token) => {
          ctx.state.oauth = { token };
          handleResponse(ctx, response);
          return next();
        })
        .catch((err) => { handleError(err, ctx); });
    };
  }
  // Returns scope check middleware
  // Used to limit access to a route or router to carriers of a certain scope.
  scope(required) {
    return (ctx, next) => {
      const result = this.checkScope(required, ctx.state.oauth.token);
      if (result !== true) {
        const err = result === false
          ? `Required scope: \`${required}\``
          : result;

        handleError(new InvalidScopeError(err), ctx);
        return undefined;
      }
      return next();
    };
  }
}

module.exports = KoaOAuthServer;
