var mongoose = require('mongoose');
var auth = require('./auth');
var Schema = mongoose.Schema;
var connection;

// Mongoose uses internal caching for models.
// While {cache: false} works with most models, models using references
// use the internal model cache for the reference.
// This removes the mongoose entirely from node's cache
delete require.cache.mongoose;

describe('Mongoose plugin: auth', function () {
  beforeAll(function (done) {
    connection = mongoose.createConnection('mongodb://localhost/unit_test');
    connection.once('connected', function () {
      done();
    });
  });

  afterAll(function (done) {
    connection.db.dropDatabase(function (err, result) {
      connection.close(function () {
        done();
      });
    });
  });

  it('should append schema', function () {
    var schema = UserSchema();
    var User;
    var user;

    schema.plugin(auth);

    expect(schema.path('username')).toBeDefined();
    expect(schema.path('salt')).toBeDefined();
    expect(schema.path('passphrase')).toBeDefined();

    expect(Object.keys(schema.statics).length).toBe(3);
    expect(schema.statics.authenticate).toBeDefined();
    expect(schema.statics.setPassphrase).toBeDefined();
    expect(schema.statics.register).toBeDefined();

    User = model('User', schema);

    expect(User).toEqual(jasmine.any(Function));

    user = new User();

    expect(user.authenticate).toEqual(jasmine.any(Function));
    expect(user.setPassphrase).toEqual(jasmine.any(Function));
  });

  it('should append schema with plugin options', function () {
    var schema = UserSchema();
    var User;
    var user;

    schema.plugin(auth, {
      usernamePath: 'u',
      saltPath: 's',
      passphrasePath: 'h'
    });

    expect(schema.path('u')).toBeDefined();
    expect(schema.path('s')).toBeDefined();
    expect(schema.path('h')).toBeDefined();
  });

  describe('with user registration and authentication', function () {
    var User;
    var users = [];
    var schema;

    beforeEach(function () {
      schema = UserSchema();
      schema.plugin(auth);

      User = model('User', schema);
    });

    it('should clear all models from DB', function (done) {
      User.collection.remove(function () {
        done();
      });
    });

    it('should return error without either `username` or `passphrase` specified', function (done) {
      User.register(undefined, undefined, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Passphrase was not specified');
        expect(user).toBe(null);

        done();
      });
    });

    it('should return error without `username` specified', function (done) {
      User.register(undefined, 'f0ob@r', function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Username was not specified');
        expect(user).toBe(null);

        done();
      });
    });

    it('should return error without `passphrase` specified', function (done) {
      User.register('alpha', undefined, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Passphrase was not specified');
        expect(user).toBe(null);

        done();
      });
    });

    it('should register a new user', function (done) {
      User.register('alpha', 'f0ob@r', function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.username).toBe('alpha');
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.passphrase).toEqual(jasmine.any(String));

        users.push(user);

        done();
      });
    });

    it('should not register a new user with an existing `username`', function (done) {
      User.register('alpha', 'f0ob@r', function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Username already exists');
        expect(user).toBe(null);

        done();
      });
    });

    it('should register a new user with extra fields populated', function (done) {
      User.register('bravo', 'FOOBAR', {name: 'Bravo'}, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.username).toBe('bravo');
        expect(user.name).toBe('Bravo');
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.passphrase).toEqual(jasmine.any(String));

        users.push(user);

        done();
      });
    });

    it('should not authenticate an unknown user', function (done) {
      User.authenticate('charlie', 'FOOBAR', function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Unknown username');
        expect(user).toBe(null);

        done();
      });
    });

    it('should not authenticate a user with an incorrect passphrase', function (done) {
      User.authenticate(users[0].username, 'F0OB@R', function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Incorrect passphrase');
        expect(user).toBe(null);

        done();
      });
    });

    it('should authenticate a user with a correct passphrase', function (done) {
      User.authenticate(users[0].username, 'f0ob@r', function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[0].id);
        expect(user.salt).toBe(users[0].salt);
        expect(user.passphrase).toBe(users[0].passphrase);

        done();
      });
    });

    it('should update the passphrase and authenticate', function (done) {
      User.setPassphrase(users[1].username, 'FOOBAR', 'B@rf0o', function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[1].id);
        expect(user.salt).not.toBe(users[1].salt);
        expect(user.passphrase).not.toBe(users[1].passphrase);

        users[1] = user;

        user.authenticate('B@rf0o', function (err, user) {
          expect(err).toBe(null);
          expect(user).toEqual(jasmine.any(Object));
          expect(user.id).toBe(users[1].id);
          expect(user.salt).toBe(users[1].salt);
          expect(user.passphrase).toBe(users[1].passphrase);

          done();
        });
      });
    });

    it('should authenticate and update the passphrase', function (done) {
      User.authenticate(users[0].username, 'f0ob@r', function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[0].id);
        expect(user.salt).toBe(users[0].salt);
        expect(user.passphrase).toBe(users[0].passphrase);

        var salt = user.salt;
        var passphrase = user.passphrase;

        user.setPassphrase('FOOBAR', function (err, user) {
          expect(err).toBe(null);
          expect(user).toEqual(jasmine.any(Object));
          expect(user.salt).not.toBe(salt);
          expect(user.passphrase).not.toBe(passphrase);

          done();
        });
      });
    });
  });

  describe('with user registration with usernamePath set to `_id`', function () {
    var schema;
    var User;
    var userObj;

    beforeEach(function () {
      schema = UserSchema();
      schema.plugin(auth, {
        usernamePath: '_id'
      });

      User = model('User', schema);
    });

    it('should drop DB', function (done) {
      connection.db.dropDatabase(function (err, result) {
        done();
      });
    });

    it('should register a new user', function (done) {
      User.register('f0ob@r', function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBeDefined();
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.passphrase).toEqual(jasmine.any(String));

        userObj = user;

        done();
      });
    });

    it('should register a new user with extra fields populated', function (done) {
      User.register('FOOBAR', {name: 'Charlie'}, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBeDefined();
        expect(user.name).toBe('Charlie');
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.passphrase).toEqual(jasmine.any(String));

        done();
      });
    });

    it('should authenticate a user', function (done) {
      User.authenticate(userObj.id, 'f0ob@r', function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(userObj.id);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.passphrase).toEqual(jasmine.any(String));

        done();
      });
    });
  });
});

function model(name, schema) {
  if (arguments.length === 1) {
    schema = name;
    name = 'Model';
  }

  // Specifying a collection name allows the model to be overwritten in
  // Mongoose's model cache
  return connection.model(name, schema, name);
}

function UserSchema() {
  return Schema({
    name: String,
    displayName: String
  });
}
