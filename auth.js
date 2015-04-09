var crypto = require('crypto');
var _ = require('lodash-node/modern');

module.exports = function authPlugin(schema, options) {
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
