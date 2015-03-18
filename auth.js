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
    salt: {
      path: 'salt',
      options: {
        type: String,
        required: true
      },
      len: 32
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

  schema.pre('validate', true, function setPassphrase(next, done) {
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

  schema.static('register', function register(username, passphrase, extra, done) {
    var Model = this;
    var user = new Model();

    // Arity check
    if (arguments.length === 2) {
      // User.register(passphrase, done)
      // Used if username field is autopopulated (`_id`)
      done = passphrase;
      passphrase = username;
      username = undefined;
    }
    else if (arguments.length === 3) {
      // User.register(username, passphrase, done)
      // User.register(passphrase, extra, done)
      done = extra;

      if (_.isPlainObject(passphrase)) {
        extra = passphrase;
        passphrase = username;
        username = undefined;
      }
      else {
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

    return user.save(done);
  });

  schema.static('setPassphrase', function register(username, passphrase, newPassphrase, done) {
    var Model = this;

    return Model.authenticate(username, passphrase, function (err, user) {
      if (err) { return done(err, user); }

      return user.setPassphrase(newPassphrase, done);
    });
  });

  schema.method('setPassphrase', function register(passphrase, done) {
    var user = this;

    user.set(options.passphrase.path, passphrase);

    return user.save(done);
  });

  schema.static('authenticate', function authenticate(username, passphrase, done) {
    if (username === undefined || username === null) {
      return done(new options.Error(options.username.missingError));
    }

    return findByUsername(this, username, options, function (err, user) {
      if (err) { return done(err, user); }

      if (user === null) {
        return done(new options.Error(options.username.incorrectError));
      }

      return user.authenticate(passphrase, done);
    });
  });

  schema.method('authenticate', function authenticate(passphrase, done) {
    var user = this;

    if (passphrase === undefined || passphrase === null) {
      return done(new options.Error(options.passphrase.missingError));
    }

    return pbkdf2(passphrase, user.get(options.salt.path), options, function checkHash(err, hash) {
      if (err) { return done(err); }

      if (hash !== user.get(options.passphrase.path)) {
        return done(new options.Error(options.passphrase.incorrectError));
      }

      return done(err, user);
    });
  });
};

function findByUsername(Model, username, options, done) {
  var query = Model.findOne().where(options.username.path, username);

  query.select([options.passphrase.path, options.salt.path].join(' '));

  if (options.select) {
    query.select(options.select);
  }

  if (options.populate) {
    query.populate(options.populate);
  }

  return done ? query.exec(done) : query;
}

function pbkdf2(passphrase, salt, options, done) {
  return crypto.pbkdf2(passphrase, salt, options.hash.iterations, options.hash.keylen, function createRawHash(err, hashRaw) {
    if (err) { return done(err); }

    // crypto returns the error param as `undefined` but Mongoose and Express use `null`
    return done(null, new Buffer(hashRaw, 'binary').toString(options.hash.encoding));
  });
}
