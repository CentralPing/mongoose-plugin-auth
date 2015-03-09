var mongoose = require('mongoose');
var faker = require('faker');
var auth = require('./auth');
var Schema = mongoose.Schema;
var connection;

// Mongoose uses internal caching for models.
// While {cache: false} works with most models, models using references
// use the internal model cache for the reference.
// This removes the mongoose entirely from node's cache
delete require.cache.mongoose;

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

describe('Mongoose plugin: auth', function () {
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
    var users;

    beforeAll(function (done) {
      var schema = UserSchema();
      schema.plugin(auth);

      users = Array(3).join('.').split('.').map(function () {
        return {
          name: faker.name.findName(),
          username: faker.internet.userName(),
          password: faker.internet.password()
        };
      });

      User = model('User', schema);

      User.collection.remove(function () {
        done();
      });
    });

    it('should not register a new user without either `username` or `passphrase` specified', function (done) {
      User.register(undefined, undefined, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Passphrase was not specified');
        expect(user).toBe(null);

        done();
      });
    });

    it('should not register a new user without `username` specified', function (done) {
      User.register(undefined, users[0].password, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Username was not specified');
        expect(user).toBe(null);

        done();
      });
    });

    it('should return error without `passphrase` specified', function (done) {
      User.register(users[0].username, undefined, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Passphrase was not specified');
        expect(user).toBe(null);

        done();
      });
    });

    it('should register a new user', function (done) {
      User.register(users[0].username, users[0].password, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.username).toBe(users[0].username);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.passphrase).toEqual(jasmine.any(String));
        expect(user.passphrase).not.toBe(users[0].password);

        users[0].id = user.id;
        users[0].salt = user.salt;
        users[0].passphrase = user.passphrase;

        done();
      });
    });

    it('should not register a new user with an existing `username`', function (done) {
      User.register(users[0].username, users[0].password, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Username already exists');
        expect(user).toBe(null);

        done();
      });
    });

    it('should register a new user with extra fields populated', function (done) {
      User.register(users[1].username, users[1].password, {name: users[1].name}, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.username).toBe(users[1].username);
        expect(user.name).toBe(users[1].name);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.passphrase).toEqual(jasmine.any(String));
        expect(user.passphrase).not.toBe(users[1].password);

        users[1].id = user.id;
        users[1].salt = user.salt;
        users[1].passphrase = user.passphrase;

        done();
      });
    });

    it('should not authenticate an unspecified user', function (done) {
      User.authenticate(undefined, undefined, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Username was not specified');
        expect(user).toBe(null);

        done();
      });
    });

    it('should not authenticate an unknown user', function (done) {
      User.authenticate(users[2].username, undefined, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Unknown username');
        expect(user).toBe(null);

        done();
      });
    });

    it('should not authenticate an unspecified passphrase', function (done) {
      User.authenticate(users[0].username, undefined, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Passphrase was not specified');
        expect(user).toBe(null);

        done();
      });
    });

    it('should not authenticate a user with an incorrect passphrase', function (done) {
      User.authenticate(users[0].username, faker.internet.password(), function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Incorrect passphrase');
        expect(user).toBe(null);

        done();
      });
    });

    it('should authenticate a user with correct username/passphrase', function (done) {
      User.authenticate(users[0].username, users[0].password, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[0].id);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.salt).toBe(users[0].salt);
        expect(user.passphrase).toEqual(jasmine.any(String));
        expect(user.passphrase).toBe(users[0].passphrase);

        done();
      });
    });

    it('should update the passphrase and authenticate', function (done) {
      var salt;
      var hash;
      var password = faker.internet.password();

      User.setPassphrase(users[1].username, users[1].password, password, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[1].id);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.salt).not.toBe(users[1].salt);
        expect(user.passphrase).toEqual(jasmine.any(String));
        expect(user.passphrase).not.toBe(users[1].passphrase);

        users[1].password = password;
        users[1].id = user.id;
        users[1].salt = user.salt;
        users[1].passphrase = user.passphrase;

        user.authenticate(users[1].password, function (err, user) {
          expect(err).toBe(null);
          expect(user).toEqual(jasmine.any(Object));
          expect(user.id).toBe(users[1].id);
          expect(user.salt).toEqual(jasmine.any(String));
          expect(user.salt).toBe(users[1].salt);
          expect(user.passphrase).toEqual(jasmine.any(String));
          expect(user.passphrase).toBe(users[1].passphrase);

          done();
        });
      });
    });

    it('should authenticate and update the passphrase', function (done) {
      User.authenticate(users[0].username, users[0].password, function (err, user) {
        users[0].password = faker.internet.password();

        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[0].id);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.salt).toBe(users[0].salt);
        expect(user.passphrase).toEqual(jasmine.any(String));
        expect(user.passphrase).toBe(users[0].passphrase);

        user.setPassphrase(users[0].password, function (err, user) {
          expect(err).toBe(null);
          expect(user).toEqual(jasmine.any(Object));
          expect(user.id).toBe(users[0].id);
          expect(user.salt).toEqual(jasmine.any(String));
          expect(user.salt).not.toBe(users[0].salt);
          expect(user.passphrase).toEqual(jasmine.any(String));
          expect(user.passphrase).not.toBe(users[0].passphrase);

          done();
        });
      });
    });
  });

  describe('with user registration with usernamePath set to `_id`', function () {
    var User;
    var users = Array(2).join('.').split('.').map(function () {
      return {
        name: faker.name.findName(),
        password: faker.internet.password()
      };
    });

    beforeAll(function (done) {
      var schema = UserSchema();
      schema.plugin(auth, {
        usernamePath: '_id'
      });

      User = model('User', schema);

      User.collection.remove(function () {
        done();
      });
    });

    it('should not register a new user without `passphrase` specified', function (done) {
      User.register(undefined, function (err, user) {
        expect(err).toBeDefined();
        expect(err.message).toBe('Passphrase was not specified');
        expect(user).toBe(null);

        done();
      });
    });

    it('should register a new user', function (done) {
      User.register(users[0].password, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBeDefined();
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.passphrase).toEqual(jasmine.any(String));

        users[0].id = user.id;

        done();
      });
    });

    it('should register a new user with extra fields populated', function (done) {
      User.register(users[1].password, {name: users[1].name}, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBeDefined();
        expect(user.name).toBe(users[1].name);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.passphrase).toEqual(jasmine.any(String));

        users[1].id = user.id;

        done();
      });
    });

    it('should authenticate a user', function (done) {
      User.authenticate(users[0].id, users[0].password, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[0].id);
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
