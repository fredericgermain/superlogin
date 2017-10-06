'use strict';
var util = require('./util');
var extend = require('util')._extend;
var BPromise = require('bluebird');
var RedisAdapter = require('./sessionAdapters/RedisAdapter');
var MemoryAdapter = require('./sessionAdapters/MemoryAdapter');
var FileAdapter = require('./sessionAdapters/FileAdapter');

var tokenPrefix = 'token';

function Session(config) {
  var adapter;
  var sessionAdapter = config.getItem('session.adapter');
  if(sessionAdapter === 'redis') {
    adapter = new RedisAdapter(config);
  } else if (sessionAdapter === 'file') {
    adapter = new FileAdapter(config);
  } else if (sessionAdapter === 'memory') {
    adapter = new MemoryAdapter();
  } else if (sessionAdapter === 'none') {
    adapter = undefined;
  } else {
    if (config.getItem('dbServer.couchbaseSyncGateway')) { // couchbase already uses memcached
      adapter = undefined;
    } else {
      adapter = new MemoryAdapter();
    }
  }
  this._adapter = adapter;
}

module.exports = Session;

Session.prototype.storeToken = function(token) {
  var self = this;
  if (!this._adapter) {
    return BPromise.resolve('no local session');
  }

  token = extend({}, token);
  if(!token.password) {
    return this._adapter.storeKey(tokenPrefix + ':' + token.key, (token.expires - Date.now()), JSON.stringify(token))
      .then(function() {
        delete token.salt;
        delete token.derived_key;
        return BPromise.resolve(token);
      });
  }
  return util.hashPassword(token.password)
    .then(function(hash) {
      token.salt = hash.salt;
      token.derived_key = hash.derived_key;
      delete token.password;
      return self._adapter.storeKey(tokenPrefix + ':' + token.key, (token.expires - Date.now()), JSON.stringify(token));
    })
    .then(function() {
      delete token.salt;
      delete token.derived_key;
      return BPromise.resolve(token);
    });
};

Session.prototype.deleteTokens = function(keys) {
  var entries = [];
  if (!this._adapter) {
    return BPromise.resolve('no local session');
  }
  if(!(keys instanceof Array)) {
    keys = [keys];
  }
  keys.forEach(function(key) {
    entries.push(tokenPrefix + ':' + key);
  });
  return this._adapter.deleteKeys(entries);
};

Session.prototype.confirmToken = function(key, password) {
  var token;
  if (!this._adapter) {
    return BPromise.resolve('no local session');
  }
  return this._adapter.getKey(tokenPrefix + ':' + key)
    .then(function(result) {
      if(!result) {
        return BPromise.reject('invalid token');
      }
      token = JSON.parse(result);
      return util.verifyPassword(token, password);
    })
    .then(function() {
      delete token.salt;
      delete token.derived_key;
      return BPromise.resolve(token);
    }, function() {
      return BPromise.reject('invalid token');
    });
};

Session.prototype.fetchToken = function(key) {
  if (!this._adapter) {
    return BPromise.resolve('no local session');
  }
  return this._adapter.getKey(tokenPrefix + ':' + key)
    .then(function(result) {
      return BPromise.resolve(JSON.parse(result));
    });
};

Session.prototype.quit = function() {
  if (!this._adapter) {
    return;
  }
  return this._adapter.quit();
};
