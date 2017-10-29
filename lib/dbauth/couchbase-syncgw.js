'use strict';

// based on pouchdb-authentication

var Promise = require('pouchdb-promise');
var urlJoin = require('url-join');

var utils = require('./utils');

function getBaseUrl(db) {
  if (typeof db.getUrl === 'function') { // pouchdb pre-6.0.0
    return db.getUrl().replace(/\/[^\/]+\/?$/, '');
  } else { // pouchdb post-6.0.0
    return db.name.replace(/\/[^\/]+\/?$/, '');
  }
}
var getUsersUrl = function (db) {
  return urlJoin(db.name, '/_user');
};
var getSessionUrl = function (db) {
  return urlJoin(db.name, '/_session');
};

function wrapError(callback) {
  // provide more helpful error message
  return function (err, res, res1) {
    if (err) {
      if (err.name === 'unknown_error') {
        err.message = (err.message || '') +
          ' Unknown error!  Did you remember to enable CORS?';
      }
    }
    return callback(err, res, res1);
  };
}

function putUser(db, user, opts, callback) {
  var reservedWords = ['name', 'password', 'roles', 'type', 'salt', 'metadata'];
  if (opts.metadata) {
    for (var key in opts.metadata) {
      if (opts.hasOwnProperty(key)) {
        if (reservedWords.indexOf(key) !== -1 || key.startsWith('_')) {
          return callback(new AuthError('cannot use reserved word in metadata: "' + key + '"'));
        }
      }
    }
    user = utils.extend(true, user, opts.metadata);
  }

  var url = getUsersUrl(db) + '/' + encodeURIComponent(user._id);
  console.log('putUser', url, user)
  var ajaxOpts = utils.extend(true, {
    method : 'PUT',
    url : url,
    body : user
  }, opts.ajax || {});
  utils.ajax(ajaxOpts, wrapError(callback));
}

exports.signup = utils.toPromise(function (username, password, opts, callback) {
  var db = this;
  if (typeof callback === 'undefined') {
    callback = typeof opts === 'undefined' ? (typeof password === 'undefined' ?
      username : password) : opts;
    opts = {};
  }
  if (['http', 'https'].indexOf(db.type()) === -1) {
    return callback(new AuthError('This plugin only works for the http/https adapter. ' +
      'So you should use new PouchDB("http://mysite.com:5984/mydb") instead.'));
  } else if (!username) {
    return callback(new AuthError('You must provide a username'));
  } else if (!password) {
    return callback(new AuthError('You must provide a password'));
  }

  var userId = username;
  var user = {
    name     : username,
    password : password,
    roles    : opts.roles || [],
    type     : 'user',
    _id      : userId
  };

  putUser(db, user, opts, callback);
});

exports.signUp = exports.signup;

exports.login = utils.toPromise(function (username, password, opts, callback) {
  var db = this;
  if (typeof callback === 'undefined') {
    callback = opts;
    opts = {};
  }
  if (['http', 'https'].indexOf(db.type()) === -1) {
    return callback(new AuthError('this plugin only works for the http/https adapter'));
  }

  if (!username) {
    return callback(new AuthError('you must provide a username'));
  }

  var ajaxOpts = utils.extend(true, {
    method : 'POST',
    url : getSessionUrl(db),
    json: true,
    body : {name: username}
  }, opts.ajax || {});
  utils.ajax(ajaxOpts, wrapError((error, data, response) => {
    callback(error, response);
  }));
});

exports.logIn = exports.login;

exports.logout = utils.toPromise(function (opts, callback) {
  var db = this;
  if (typeof callback === 'undefined') {
    callback = opts;
    opts = {};
  }
  var sessionId = opts.headers.cookie.substring(opts.headers.cookie.indexOf('=')+1);
  var url = getSessionUrl(db) + '/' + sessionId;
  var ajaxOpts = utils.extend(true, {
    method : 'DELETE',
    url : url
  }, opts.ajax || {});
  utils.ajax(ajaxOpts, function ignore404(err, res) {
    // session could auto delete by expire already
    if (err.status === 404) return callback(null, null);
    wrapError(callback)(err, res);
  });
});

exports.logOut = exports.logout;

exports.getSession = utils.toPromise(function (opts, callback) {
  var db = this;
  if (typeof callback === 'undefined') {
    callback = opts;
    opts = {};
  }
  var url = getSessionUrl(db);

  var ajaxOpts = utils.extend(true, {
    method : 'GET',
    url : url
  }, opts.ajax || {});
  utils.ajax(ajaxOpts, wrapError(callback));
});

exports.getUser = utils.toPromise(function (username, opts, callback) {
  var db = this;
  if (typeof callback === 'undefined') {
    callback = typeof opts === 'undefined' ? username : opts;
    opts = {};
  }
  if (!username) {
    return callback(new AuthError('you must provide a username'));
  }

  var url = getUsersUrl(db);
  var ajaxOpts = utils.extend(true, {
    method : 'GET',
    url : url + '/' + encodeURIComponent('org.couchdb.user:' + username)
  }, opts.ajax || {});
  utils.ajax(ajaxOpts, wrapError(callback));
});

exports.putUser = utils.toPromise(function (username, opts, callback) {
  var db = this;
  if (typeof callback === 'undefined') {
    callback = typeof opts === 'undefined' ? username : opts;
    opts = {};
  }
  if (['http', 'https'].indexOf(db.type()) === -1) {
    return callback(new AuthError('This plugin only works for the http/https adapter. ' +
      'So you should use new PouchDB("http://mysite.com:5984/mydb") instead.'));
  } else if (!username) {
    return callback(new AuthError('You must provide a username'));
  }

  return db.getUser(username, opts, function (error, user) {
    if (error) {
      return callback(error);
    }

    putUser(db, user, opts, callback);
  });
});

exports.changePassword = utils.toPromise(function (username, password, opts, callback) {
  var db = this;
  if (typeof callback === 'undefined') {
    callback = typeof opts === 'undefined' ? (typeof password === 'undefined' ?
      username : password) : opts;
    opts = {};
  }
  if (['http', 'https'].indexOf(db.type()) === -1) {
    return callback(new AuthError('This plugin only works for the http/https adapter. ' +
      'So you should use new PouchDB("http://mysite.com:5984/mydb") instead.'));
  } else if (!username) {
    return callback(new AuthError('You must provide a username'));
  } else if (!password) {
    return callback(new AuthError('You must provide a password'));
  }

  return db.getUser(username, opts, function (error, user) {
    if (error) {
      return callback(error);
    }

    user.password = password;

    var url = getUsersUrl(db) + '/' + encodeURIComponent(user._id);
    var ajaxOpts = utils.extend(true, {
      method : 'PUT',
      url : url,
      body : user
    }, opts.ajax || {});
    utils.ajax(ajaxOpts, wrapError(callback));
  });
});

exports.changeUsername = utils.toPromise(function (oldUsername, newUsername, opts, callback) {
  var db = this;
  var USERNAME_PREFIX = 'org.couchdb.user:';
  var ajax = function (opts) {
    return new utils.Promise(function (resolve, reject) {
      utils.ajax(opts, wrapError(function (err, res) {
        if (err) {
          return reject(err);
        }
        resolve(res);
      }));
    });
  };
  var updateUser = function (user, opts) {
    var url = getUsersUrl(db) + '/' + encodeURIComponent(user._id);
    var updateOpts = utils.extend(true, {
      method : 'PUT',
      url : url,
      body: user
    }, opts.ajax);
    return ajax(updateOpts);
  };
  if (typeof callback === 'undefined') {
    callback = opts;
    opts = {};
  }
  opts.ajax = opts.ajax || {};
  if (['http', 'https'].indexOf(db.type()) === -1) {
    return callback(new AuthError('This plugin only works for the http/https adapter. ' +
      'So you should use new PouchDB("http://mysite.com:5984/mydb") instead.'));
  }
  if (!newUsername) {
    return callback(new AuthError('You must provide a new username'));
  }
  if (!oldUsername) {
    return callback(new AuthError('You must provide a username to rename'));
  }

  return db.getUser(newUsername, opts)
  .then(function () {
    var error = new AuthError('user already exists');
    error.taken = true;
    throw error;
  }, function () {
    return db.getUser(oldUsername, opts);
  })
  .then(function (user) {
    var newUser = utils.clone(user);
    delete newUser._rev;
    newUser._id = USERNAME_PREFIX + newUsername;
    newUser.name = newUsername;
    newUser.roles = opts.roles || user.roles || {};
    return updateUser(newUser, opts).then(function () {
      user._deleted = true;
      return updateUser(user, opts);
    });
  }).then(function (res) {
    callback(null, res);
  }).catch(callback);
});


function AuthError(message) {
  this.status = 400;
  this.name = 'authentication_error';
  this.message = message;
  this.error = true;
  try {
    Error.captureStackTrace(this, AuthError);
  } catch (e) {}
}

utils.inherits(AuthError, Error);

if (typeof window !== 'undefined' && window.PouchDB) {
  window.PouchDB.plugin(exports);
}
