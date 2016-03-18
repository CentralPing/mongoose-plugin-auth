'use strict';
/* jshint node: true */

var crypto = require('crypto');
var _ = require('lodash');

/**
 * @module mongoose-plugin-auth
 * @example
```js
var authPlugin = require('mongoose-plugin-auth');
var schema = Schema({...});
schema.plugin(authPlugin[, OPTIONS]);
```
*/

module.exports = function authPlugin(schema, options) {
  /**
   * @param {object} [options]

   * @param {object} [options.username] - options for configuring the username.
   * @param {string} [options.username.path=username] - the path for storing the username. *Value can be set to `_id`*
   * @param {object} [options.username.options] - options for configuring the username path in the schema.
   * @param {object} [options.username.options.type=String] - object type for the username path. *Specifying an existing username path ignores all options specified here.*
   * @param {boolean} [options.username.options.required=true] - spcifies wether the username path is required.
   * @param {boolean} [options.username.options.unique=true] - spcifies wether the username path is required.
   * @param {boolean} [options.username.options.sparse=true] - spcifies wether the username path is required.
   * @param {boolean} [options.username.options.trim=true] - spcifies wether the username path is required.
   * @param {string} [options.username.missingError=Username was not specified] - message returned via an error object for methods requiring a username.
   * @param {string} [options.username.incorrectError=Unknown username] - message returned via an error object if username does not match a record.

   * @param {object} [options.passphrase] - options for configuring the passphrase.
   * @param {string} [options.passphrase.path=passphrase] - the path for storing the passphrase.
   * @param {object} [options.passphrase.options] - options for configuring the passphrase path in the schema.
   * @param {object} [options.passphrase.options.type=String] - object type for the passphrase path. *Specifying an existing passphrase path ignores all options specified here.*
   * @param {boolean} [options.passphrase.options.required=true] - spcifies wether the passphrase path is required.
   * @param {string} [options.passphrase.missingError=Passphrase was not specified] - message returned via an error object for methods requiring a passphrase.
   * @param {string} [options.passphrase.incorrectError=Incorrect passphrase] - message returned via an error object if passphrase does not match the record.

   * @param {object} [options.salt] - options for configuring the salt.
   * @param {string} [options.salt.path=salt] - the path for storing the salt.
   * @param {object} [options.salt.options] - options for configuring the salt path in the schema.
   * @param {object} [options.salt.options.type=String] - object type for the salt path. *Specifying an existing salt path ignores all options specified here.*
   * @param {boolean} [options.salt.options.required=true] - spcifies wether the salt path is required.
   * @param {number} [options.salt.len=32] - the string length to use for the salt.

   * @param {object} [options.hash] - options for configuring the hash using the [crypto](https://nodejs.org/api/crypto.html) module.
   * @param {number} [options.hash.iterations=25000] - number of iterations for generating the hash.
   * @param {number} [options.hash.keylen.type=512] - the string length of the generated hash.
   * @param {string} [options.hash.encoding=hex] - the encoding algorithm to use for the hash.

   * @param {object} [Error=Error] - Error object to use for reporting errors. *Must be of the type Error or inherites from it*
   * @param {string} [select] - Mongoose field selection to use for authenticate method/static.
   * @param {string} [populate] - Mongoose populate selection to use for authenticate method/static.
  */
  options = _.merge({
    username: {
      path: 'username',
      options: {
        type: String,
        required: true,
        unique: true,
        sparse: true,
        trim: true
      },
      missingError: 'Username was not specified',
      incorrectError: 'Unknown username'
    },
    passphrase: {
      path: 'passphrase',
      options: {
        type: String,
        required: true
      },
      missingError: 'Passphrase was not specified',
      incorrectError: 'Incorrect passphrase'
    },
    salt: {
      path: 'salt',
      options: {
        type: String,
        required: true
      },
      len: 32
    },
    hash: {
      iterations: 25000,
      keylen: 512,
      encoding: 'hex'
    },
    Error: Error,
    select: undefined,
    populate: undefined
  }, options || {});

  if (!schema.path(options.username.path)) {
    schema.path(options.username.path, options.username.options);
  }

  if (!schema.path(options.salt.path)) {
    schema.path(options.salt.path, options.salt.options);
  }

  if (!schema.path(options.passphrase.path)) {
    schema.path(options.passphrase.path, options.passphrase.options);
  }

  schema.pre('validate', true, function encryptPassphrase(next, done) {
    var user = this;
    var passphrase;

    // Run in parallel
    next();

    if (!user.isNew && !user.isModified(options.passphrase.path)) {
      return done();
    }

    passphrase = user.get(options.passphrase.path);

    if (passphrase === undefined) {
      return done();
    }

    return crypto.randomBytes(options.salt.len, function createSalt(err, buf) {
      if (err) { return done(err); }

      var salt = buf.toString(options.hash.encoding);

      return pbkdf2(passphrase, salt, options, function createHash(err, hash) {
        if (err) { return done(err); }

        user.set(options.passphrase.path, hash);
        user.set(options.salt.path, salt);

        return done();
      });
    });
  });

  /**
   * The `register` static is a convenience function to add a new user document.
   * @function register
   * @param {string} [username] - Username value to use. Optional if using the `_id` value.
   * @param {string} passphrase - Raw passphrase value. Hashed automatically before storing using crypto module.
   * @param {object} [extra] - Any extra object properties that match the schema to be included in the new user document.
   * @param {function} [cb] - A mongoose promise is returned if no callback is provided.
   * @return {promise}

   * @example
  ```js
MyUserModel.register('tom', 'my secret passphrase', {email: tom@jerry.com}, function(err, user) { ... });
MyUserModel.register('tom', 'my secret passphrase', {email: tom@jerry.com}).then(function(user) { ... }, function(err) {...}); // Uses promise
MyUserModel.register('tom', 'my secret passphrase', function(err, user) { ... });
MyUserModel.register('tom', 'my secret passphrase').then(function(user) { ... }, function(err) {...}); // Uses promise
MyUserModel.register('my secret passphrase', {email: tom@jerry.com}, function(err, user) { ... }); // Uses `_id` for the username
MyUserModel.register('my secret passphrase', {email: tom@jerry.com}).then(function(user) { ... }, function(err) {...});; // Uses promise and `_id` for the username
MyUserModel.register('my secret passphrase', function(err, user) { ... }); // Uses `_id` for the username
MyUserModel.register('my secret passphrase').then(function(user) { ... }, function(err) {...});; // Uses promise and `_id` for the username
  ```
  */
  schema.static('register', function register(username, passphrase, extra, cb) {
    var User = this;
    var user = new User();

    // Arity check
    if (arguments.length === 1) {
      // User.register(passphrase)
      // Used if username field is autopopulated (e.g. `_id`)
      passphrase = username;
      username = undefined;
    }
    else if (arguments.length === 2) {
      if (_.isFunction(passphrase)) {
        // User.register(passphrase, cb)
        // Used if username field is autopopulated (e.g. `_id`)
        cb = passphrase;
        passphrase = username;
        username = undefined;
      }
      else if (_.isPlainObject(passphrase)) {
        // User.register(passphrase, extra)
        // Used if username field is autopopulated (e.g. `_id`)
        extra = passphrase;
        passphrase = username;
        username = undefined;
      }
    }
    else if (arguments.length === 3 && _.isFunction(extra)) {
      cb = extra;

      if (_.isPlainObject(passphrase)) {
        // User.register(passphrase, extra, cb)
        extra = passphrase;
        passphrase = username;
        username = undefined;
      }
      else {
        // User.register(username, passphrase, cb)
        extra = undefined;
      }
    }

    if (username !== undefined) {
      user.set(options.username.path, username);
    }

    if (extra !== undefined) {
      user.set(extra);
    }

    user.set(options.passphrase.path, passphrase);

    // returns promise
    return user.save(cb);
  });

  /**
   * The `setPassphrase` static is a convenience function to set the passphrase for a user. *Alternatively you can simply set the passphrase to a new value directly on the document object and save/update.*
   * @function setPassphrase
   * @param {string} username - Username value to use.
   * @param {string} passphrase - Raw passphrase value. Hashed automatically before storing using crypto module.
   * @param {string} newPassphrase - Raw new passphrase value. Hashed automatically before storing using crypto module.
   * @param {object} [extra] - Any extra object properties that match the schema to be included in the update.
   * @param {function} [cb] - A mongoose promise is returned if no callback is provided.
   * @return {promise}

   * @example
  ```js
MyUserModel.setPassphrase('tom', 'my secret passphrase', 'my new secret passphrase', {email: tom@jerry.com}, function(err, user) { ... });
MyUserModel.setPassphrase('tom', 'my secret passphrase', 'my new secret passphrase', {email: tom@jerry.com}).then(function(user) { ... }, function(err) {...}); // Uses promise
MyUserModel.setPassphrase('tom', 'my secret passphrase', 'my new secret passphrase', function(err, user) { ... });
MyUserModel.setPassphrase('tom', 'my secret passphrase', 'my new secret passphrase').then(function(user) { ... }, function(err) {...}); // Uses promise
  ```
  */
  schema.static('setPassphrase', function setPassphrase(username, passphrase, newPassphrase, extra, cb) {
    // Arity check
    if (arguments.length === 4 && _.isFunction(extra)) {
      // User.setPassphrase(username, passphrase, newPassphrase, cb)
      cb = extra;
      extra = undefined;
    }

    return this.authenticate(username, passphrase).then(function (user) {
      return user.setPassphrase(newPassphrase, extra, cb);
    }).then(null, function authenticationError(err) {
      if (cb) { return cb(err); }
      throw err;
    });
  });

  /**
   * The `setPassphrase` method is a convenience function to set the passphrase for a user. *Alternatively you can simply set the passphrase to a new value directly on the document object and save/update.*
   * @function setPassphrase
   * @param {string} passphrase - Raw new passphrase value. Hashed automatically before storing using crypto module.
   * @param {object} [extra] - Any extra object properties that match the schema to be included in the update.
   * @param {function} [cb] - A mongoose promise is returned if no callback is provided.
   * @return {promise}

   * @example
  ```js
user.setPassphrase('my new secret passphrase', {email: tom@jerry.com}, function(err, user) { ... });
user.setPassphrase('my new secret passphrase', {email: tom@jerry.com}).then(function(user) { ... }, function(err) {...}); // Uses promise
user.setPassphrase('my new secret passphrase', function(err, user) { ... });
user.setPassphrase('my new secret passphrase').then(function(user) { ... }, function(err) {...}); // Uses promise
  ```
  */
  schema.method('setPassphrase', function setPassphrase(passphrase, extra, cb) {
    // Arity check
    if (arguments.length === 2 && _.isFunction(extra)) {
      // user.setPassphrase(newPassphrase, cb)
      cb = extra;
      extra = undefined;
    }

    this.set(options.passphrase.path, passphrase);

    if (extra !== undefined) {
      this.set(extra);
    }

    // returns promise
    return this.save(cb);
  });

  /**
   * The `authenticate` static is a function to validate the passphrase for a user.
   * @function authenticate
   * @param {string} username - Username value to use.
   * @param {string} passphrase - Raw passphrase value. Hashed automatically before storing using crypto module.
   * @param {function} [cb] - A mongoose promise is returned if no callback is provided.
   * @return {promise}

   * @example
  ```js
MyUserModel.authenticate('tom', 'my secret passphrase', function(err, user) { ... });
MyUserModel.authenticate('tom', 'my secret passphrase').then(function(user) { ... }, function(err) {...}); // Uses promise
  ```
  */
  schema.static('authenticate', function authenticate(username, passphrase, cb) {
    var User = this;
    var promise = new User.base.Promise();

    promise.fulfill(username);

    return promise.then(function findByUsername(username) {
      var query = User.findOne();

      if (username === undefined || username === null) {
        throw new options.Error(options.username.missingError);
      }

      query.where(options.username.path, username);
      query.select([options.passphrase.path, options.salt.path].join(' '));

      if (options.select) {
        query.select(options.select);
      }

      if (options.populate) {
        query.populate(options.populate);
      }

      return query.exec();
    }).then(function authenticated(user) {
      if (user === null) {
        throw new options.Error(options.username.incorrectError);
      }

      return user.authenticate(passphrase, cb);
    }).then(null, function authenticationError(err) {
      if (err.name === 'CastError' && err.path === options.username.path) {
        // The provided username could not be cast correctly by mongoose
        // This is typical when using an ObjectId as the username
        // Convert CastError to designated Error type
        err = new options.Error(options.username.incorrectError);
      }

      if (cb) { return cb(err); }
      throw err;
    });
  });

  /**
   * The `authenticate` method is a function to validate the passphrase for a user.
   * @function authenticate
   * @param {string} passphrase - Raw passphrase value. Hashed automatically before storing using crypto module.
   * @param {function} [cb] - A mongoose promise is returned if no callback is provided.
   * @return {promise}

   * @example
  ```js
user.authenticate('tom', 'my secret passphrase', function(err, user) { ... });
user.authenticate('tom', 'my secret passphrase').then(function(user) { ... }, function(err) {...}); // Uses promise
  ```
  */
  schema.method('authenticate', function authenticate(passphrase, cb) {
    var user = this;
    var promise = new user.db.base.Promise();

    if (passphrase === undefined || passphrase === null) {
      promise.reject(new options.Error(options.passphrase.missingError));
    }
    else {
      pbkdf2(passphrase, user.get(options.salt.path), options, function checkHash(err, hash) {
        if (err) { return promise.reject(err); }

        if (hash !== user.get(options.passphrase.path)) {
          return promise.reject(new options.Error(options.passphrase.incorrectError));
        }

        return promise.fulfill(user);
      });
    }

    return promise.then(function authenticated(user) {
      if (cb) { return cb(null, user); }
      return user;
    }).then(null, function authenticationError(err) {
      if (cb) { return cb(err); }
      throw err;
    });
  });
};

function pbkdf2(passphrase, salt, options, cb) {
  // async method
  return crypto.pbkdf2(passphrase, salt, options.hash.iterations, options.hash.keylen, function createRawHash(err, hashRaw) {
    if (err) { return cb(err); }

    // crypto returns the error param as `undefined` but Mongoose and Express use `null`
    return cb(null, new Buffer(hashRaw, 'binary').toString(options.hash.encoding));
  });
}
