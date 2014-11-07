var util = require('util');
var crypto = require('crypto');
var _ = require('lodash-node/modern');

var defaultOptions = {
  usernamePath: 'username',
  saltPath: 'salt',
  hashPath: 'hash',
  saltlen: 32,
  iterations: 25000,
  keylen: 512,
  encoding: 'hex',
  Error: Error,
  incorrectPassphraseError: 'Incorrect passphrase',
  incorrectUsernameError: 'Unknown username',
  missingUsernameError: 'Username was not specified',
  missingPassphraseError: 'Passphrase was not specified',
  userExistsError: 'Username already exists [%s]',
  select: undefined,
  populate: undefined
};

module.exports = function authPlugin(schema, options) {
  options = _.merge({}, defaultOptions, options || {});

  if (!schema.path(options.usernamePath)) {
    schema.path(options.usernamePath, {
      type: String,
      required: true,
      unique: true,
      select: false,
      trim: true,
      lowercase: true
    });
  }

  if (!schema.path(options.saltPath)) {
    schema.path(options.saltPath, {
      type: String,
      required: true,
      select: false
    });
  }

  if (!schema.path(options.hashPath)) {
    schema.path(options.hashPath, {
      type: String,
      required: true,
      select: false
    });
  }

  schema.pre('validate', true, function setPassphrase(next, done) {
    var user = this;
    var passphrase = user.get(options.hashPath);

    // Run in parallel
    next();

    if (!user.isNew && !user.isModified(options.hashPath)) {
      return done();
    }

    if (passphrase === undefined) {
      return done(new options.Error(options.missingPassphraseError));
    }

    crypto.randomBytes(options.saltlen, function createSalt(err, buf) {
      var salt;

      if (err) { return done(err); }

      salt = buf.toString(options.encoding);

      pbkdf2(passphrase, salt, options, function createHash(err, hash) {
        if (err) { return done(err); }

        user.set(options.hashPath, hash);
        user.set(options.saltPath, salt);

        return done();
      });
    });
  });

  schema.static('register', function register(username, passphrase, cb) {
    var Model = this;
    var user = new Model();

    if (!username) {
      return cb(new options.Error(options.missingUsernameError), null);
    }

    user.set(options.usernamePath, username);
    user.set(options.hashPath, passphrase);

    return user.save(function saveUser(err, user) {
      if (err) {
        return cb(err.code !== 11000 ? err : new options.Error(util.format(options.userExistsError, username)), null);
      }

      return cb(null, user);
    });
  });

  schema.static('authenticate', function authenticate(username, passphrase, cb) {
    return findByUsername(this, username, options, function (err, user) {
      if (err) { return cb(err, null); }

      if (!user) {
        return cb(new options.Error(options.incorrectUsernameError), null);
      }

      return user.authenticate(passphrase, cb);
    });
  });

  schema.method('authenticate', function authenticate(passphrase, cb) {
    var user = this;

    return pbkdf2(passphrase, user.get(options.saltPath), options, function checkHash(err, hash) {
      if (err) { return cb(err, null); }

      if (hash !== user.get(options.hashPath)) {
        return cb(new options.Error(options.incorrectPassphraseError), null);
      }

      return cb(null, user);
    });
  });
};

function findByUsername(Model, username, options, cb) {
  var query = Model.findOne().where(options.usernamePath, username);

  query.select([options.hashPath, options.saltPath].join(' '));

  if (options.select) {
    query.select(options.select);
  }

  if (options.populate) {
    query.populate(options.populate);
  }

  return cb ? query.exec(cb) : query;
}

function pbkdf2(passphrase, salt, options, cb) {
  return crypto.pbkdf2(passphrase, salt, options.iterations, options.keylen, function createRawHash(err, hashRaw) {
    if (err) { return cb(err, null); }

    return cb(err, new Buffer(hashRaw, 'binary').toString(options.encoding));
  });
}
