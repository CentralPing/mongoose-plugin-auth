var crypto = require('crypto');
var _ = require('lodash-node/modern');

module.exports = function authPlugin(schema, options) {
  options = _.merge({
    usernamePath: 'username',
    saltPath: 'salt',
    passphrasePath: 'passphrase',
    saltlen: 32,
    iterations: 25000,
    keylen: 512,
    encoding: 'hex',
    Error: Error,
    incorrectPassphraseError: 'Incorrect passphrase',
    incorrectUsernameError: 'Unknown username',
    missingUsernameError: 'Username was not specified',
    missingPassphraseError: 'Passphrase was not specified',
    userExistsError: 'Username already exists',
    select: undefined,
    populate: undefined
  }, options || {});

  if (!schema.path(options.usernamePath)) {
    schema.path(options.usernamePath, {
      type: String,
      required: true,
      unique: true,
      sparse: true,
      select: false,
      trim: true,
      lowercase: true
    });
  }
  else {
    schema.path(options.usernamePath).index({
      unique: true,
      sparse: true
    });
  }

  if (!schema.path(options.saltPath)) {
    schema.path(options.saltPath, {
      type: String,
      required: true,
      select: false
    });
  }

  if (!schema.path(options.passphrasePath)) {
    schema.path(options.passphrasePath, {
      type: String,
      required: true,
      select: false
    });
  }

  schema.pre('validate', true, function setPassphrase(next, done) {
    var user = this;
    var passphrase = user.get(options.passphrasePath);

    // Run in parallel
    next();

    if (!user.isNew && !user.isModified(options.passphrasePath)) {
      return done();
    }

    if (passphrase === undefined) {
      return done(new options.Error(options.missingPassphraseError));
    }

    return crypto.randomBytes(options.saltlen, function createSalt(err, buf) {
      if (err) { return done(err); }

      var salt = buf.toString(options.encoding);

      return pbkdf2(passphrase, salt, options, function createHash(err, hash) {
        if (err) { return done(err); }

        user.set(options.passphrasePath, hash);
        user.set(options.saltPath, salt);

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
      user.set(options.usernamePath, username);
    }

    if (extra !== undefined) {
      user.set(extra);
    }

    user.set(options.passphrasePath, passphrase);

    return user.save(function saveUser(err, user) {
      if (err) {
        if (err.name === 'MongoError' && err.code === 11000) {
          return done(new options.Error(options.userExistsError), null);
        }
        else if (err.name === 'ValidationError' && err.errors[options.usernamePath] !== undefined && err.errors[options.usernamePath].type === 'required') {
          return done(new options.Error(options.missingUsernameError), null);
        }
        else {
          return done(err, null);
        }
      }

      return done(null, user);
    });
  });

  schema.static('setPassphrase', function register(username, passphrase, newPassphrase, done) {
    var Model = this;

    return Model.authenticate(username, passphrase, function (err, user) {
      if (err) { return done(err, null); }

      return user.setPassphrase(newPassphrase, done);
    });
  });

  schema.method('setPassphrase', function register(passphrase, done) {
    var user = this;

    user.set(options.passphrasePath, passphrase);

    return user.save(function saveUser(err, user) {
      if (err) { return done(err, null); }

      return done(null, user);
    });
  });

  schema.static('authenticate', function authenticate(username, passphrase, done) {
    return findByUsername(this, username, options, function (err, user) {
      if (err) { return done(err, null); }

      if (!user) {
        return done(new options.Error(options.incorrectUsernameError), null);
      }

      return user.authenticate(passphrase, done);
    });
  });

  schema.method('authenticate', function authenticate(passphrase, done) {
    var user = this;

    return pbkdf2(passphrase, user.get(options.saltPath), options, function checkHash(err, hash) {
      if (err) { return done(err, null); }

      if (hash !== user.get(options.passphrasePath)) {
        return done(new options.Error(options.incorrectPassphraseError), null);
      }

      return done(null, user);
    });
  });
};

function findByUsername(Model, username, options, done) {
  var query = Model.findOne().where(options.usernamePath, username);

  query.select([options.passphrasePath, options.saltPath].join(' '));

  if (options.select) {
    query.select(options.select);
  }

  if (options.populate) {
    query.populate(options.populate);
  }

  return done ? query.exec(done) : query;
}

function pbkdf2(passphrase, salt, options, done) {
  return crypto.pbkdf2(passphrase, salt, options.iterations, options.keylen, function createRawHash(err, hashRaw) {
    if (err) { return done(err, null); }

    return done(err, new Buffer(hashRaw, 'binary').toString(options.encoding));
  });
}
