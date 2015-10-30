'use strict';
/* jshint node: true, jasmine: true */

var mongoose = require('mongoose');
var faker = require('faker');
var auth = require('./auth');

var connectionString = 'mongodb://' +
  (process.env.MONGO_HOST || 'localhost') +
  (process.env.MONGO_PORT ? ':' + process.env.MONGO_PORT : '') +
  '/unit_test';

var Schema = mongoose.Schema;
var connection;

describe('Mongoose plugin: auth', function () {
  beforeAll(function (done) {
    connection = mongoose.createConnection(connectionString);
    connection.once('connected', function () {
      done();
    });
  });

  afterAll(function (done) {
    connection.db.dropDatabase(function () {
      connection.close(function () {
        done();
      });
    });
  });

  describe('with schema', function () {
    var schema;

    beforeAll(function() {
      schema = userSchema();
      schema.plugin(auth);
    });

    it('should append statics to Schema', function () {
      expect(Object.keys(schema.statics).sort()).toEqual([
        'authenticate',
        'register',
        'setPassphrase'
      ]);
    });

    it('should append paths to Schema', function () {
      expect(Object.keys(schema.paths).sort()).toEqual([
        '_id',
        'displayName',
        'name',
        'passphrase',
        'salt',
        'username'
      ]);
    });

    it('should append `passphrase`', function () {
      expect(schema.path('passphrase')).toBeDefined();
      expect(schema.path('passphrase').isRequired).toBe(true);
    });

    it('should append `salt`', function () {
      expect(schema.path('salt')).toBeDefined();
      expect(schema.path('salt').isRequired).toBe(true);
    });

    it('should append `username`', function () {
      expect(schema.path('username')).toBeDefined();
      expect(schema.path('username').isRequired).toBe(true);
    });
  });

  describe('with model instance', function () {
    var user;

    beforeAll(function() {
      var User;
      var schema = userSchema();
      schema.plugin(auth);

      User = model('User', schema);
      user = new User();
    });

    it('should append method `authenticate`', function () {
      expect(user.authenticate).toEqual(jasmine.any(Function));
    });

    it('should append method `setPassphrase`', function () {
      expect(user.setPassphrase).toEqual(jasmine.any(Function));
    });
  });

  describe('with plugin options', function () {
    it('should allow custom paths', function () {
      var schema = userSchema();

      schema.plugin(auth, {
        username: {path: 'u'},
        salt: {path: 's'},
        passphrase: {path: 'h'}
      });

      expect(schema.path('u')).toBeDefined();
      expect(schema.path('s')).toBeDefined();
      expect(schema.path('h')).toBeDefined();
    });

    // TODO: test all options
  });

  describe('with user registration and authentication', function () {
    var User;
    var users;

    beforeAll(function (done) {
      var schema = userSchema();
      schema.plugin(auth);

      /* jshint -W064 */
      // https://github.com/jshint/jshint/issues/1987
      users = Array(3).join('.').split('.').map(function () {
      /* jshint +W064 */
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
        expect(err).not.toBe(null);
        expect(Object.keys(err.errors).length).toBe(3);
        expect(err.errors.salt).toEqual(jasmine.any(Object));
        expect(err.errors.username).toEqual(jasmine.any(Object));
        expect(err.errors.passphrase).toEqual(jasmine.any(Object));
        expect(user).toBeUndefined();

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
        expect(err).not.toBe(null);
        expect(err.name).toBe('MongoError');
        expect(err.code).toBe(11000);
        expect(user).toBeUndefined();

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
        expect(err).not.toBe(null);
        expect(err.message).toBe('Username was not specified');
        expect(user).toBeUndefined();

        done();
      });
    });

    it('should not authenticate an unknown user', function (done) {
      User.authenticate(users[2].username, undefined, function (err, user) {
        expect(err).not.toBe(null);
        expect(err.message).toBe('Unknown username');
        expect(user).toBeUndefined();

        done();
      });
    });

    it('should not authenticate an unspecified passphrase', function (done) {
      User.authenticate(users[0].username, undefined, function (err, user) {
        expect(err).not.toBe(null);
        expect(err.message).toBe('Passphrase was not specified');
        expect(user).toBeUndefined();

        done();
      });
    });

    it('should not authenticate a user with an incorrect passphrase', function (done) {
      User.authenticate(users[0].username, faker.internet.password(), function (err, user) {
        expect(err).not.toBe(null);
        expect(err.message).toBe('Incorrect passphrase');
        expect(user).toBeUndefined();

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

    it('should update the passphrase and authenticate with extra fields populated', function (done) {
      var password = faker.internet.password();

      User.setPassphrase(users[1].username, users[1].password, password, {name: faker.name.findName()}, function (err, user) {
        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[1].id);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.salt).not.toBe(users[1].salt);
        expect(user.passphrase).toEqual(jasmine.any(String));
        expect(user.passphrase).not.toBe(users[1].passphrase);
        expect(user.name).not.toBe(users[1].name);

        users[1].password = password;
        users[1].id = user.id;
        users[1].salt = user.salt;
        users[1].passphrase = user.passphrase;
        users[1].name = user.name;

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
        var password = faker.internet.password();

        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[0].id);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.salt).toBe(users[0].salt);
        expect(user.passphrase).toEqual(jasmine.any(String));
        expect(user.passphrase).toBe(users[0].passphrase);

        user.setPassphrase(password, function (err, user) {
          expect(err).toBe(null);
          expect(user).toEqual(jasmine.any(Object));
          expect(user.id).toBe(users[0].id);
          expect(user.salt).toEqual(jasmine.any(String));
          expect(user.salt).not.toBe(users[0].salt);
          expect(user.passphrase).toEqual(jasmine.any(String));
          expect(user.passphrase).not.toBe(users[0].passphrase);

          users[0].password = password;
          users[0].id = user.id;
          users[0].salt = user.salt;
          users[0].passphrase = user.passphrase;

          done();
        });
      });
    });

    it('should authenticate and update the passphrase with extra fields populated', function (done) {
      User.authenticate(users[0].username, users[0].password, function (err, user) {
        var password = faker.internet.password();

        expect(err).toBe(null);
        expect(user).toEqual(jasmine.any(Object));
        expect(user.id).toBe(users[0].id);
        expect(user.salt).toEqual(jasmine.any(String));
        expect(user.salt).toBe(users[0].salt);
        expect(user.passphrase).toEqual(jasmine.any(String));
        expect(user.passphrase).toBe(users[0].passphrase);

        user.setPassphrase(password, {name: faker.name.findName()}, function (err, user) {
          expect(err).toBe(null);
          expect(user).toEqual(jasmine.any(Object));
          expect(user.id).toBe(users[0].id);
          expect(user.salt).toEqual(jasmine.any(String));
          expect(user.salt).not.toBe(users[0].salt);
          expect(user.passphrase).toEqual(jasmine.any(String));
          expect(user.passphrase).not.toBe(users[0].passphrase);
          expect(user.name).not.toBe(users[0].name);

          users[0].password = password;
          users[0].id = user.id;
          users[0].salt = user.salt;
          users[0].passphrase = user.passphrase;
          users[0].name = user.name;

          done();
        });
      });
    });
  });

  describe('with user registration with usernamePath set to `_id`', function () {
    var User;

      /*jshint -W064 */
    var users = Array(2).join('.').split('.').map(function () {
      /*jshint +W064 */
      return {
        name: faker.name.findName(),
        password: faker.internet.password()
      };
    });

    beforeAll(function (done) {
      var schema = userSchema();
      schema.plugin(auth, {
        username: {path: '_id'}
      });

      User = model('User', schema);

      User.collection.remove(function () {
        done();
      });
    });

    it('should not register a new user without `passphrase` specified', function (done) {
      User.register(undefined, function (err, user) {
        expect(err).not.toBe(null);
        expect(Object.keys(err.errors).length).toBe(2);
        expect(err.errors.salt).toEqual(jasmine.any(Object));
        expect(err.errors.passphrase).toEqual(jasmine.any(Object));
        expect(user).toBeUndefined();

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

    it('should not authenticate an unspecified user', function (done) {
      User.authenticate(undefined, undefined, function (err, user) {
        expect(err).not.toBe(null);
        expect(err.message).toBe('Username was not specified');
        expect(user).toBeUndefined();

        done();
      });
    });

    it('should not authenticate a specified user of incorrect type', function (done) {
      User.authenticate(faker.internet.userName(), undefined, function (err, user) {
        expect(err).not.toBe(null);
        expect(err.message).toBe('Unknown username');
        expect(user).toBeUndefined();

        done();
      });
    });

    it('should not authenticate an unknown user', function (done) {
      User.authenticate(mongoose.Types.ObjectId(), undefined, function (err, user) {
        expect(err).not.toBe(null);
        expect(err.message).toBe('Unknown username');
        expect(user).toBeUndefined();

        done();
      });
    });

    it('should not authenticate an unspecified passphrase', function (done) {
      User.authenticate(users[0].id, undefined, function (err, user) {
        expect(err).not.toBe(null);
        expect(err.message).toBe('Passphrase was not specified');
        expect(user).toBeUndefined();

        done();
      });
    });

    it('should not authenticate a user with an incorrect passphrase', function (done) {
      User.authenticate(users[0].id, faker.internet.password(), function (err, user) {
        expect(err).not.toBe(null);
        expect(err.message).toBe('Incorrect passphrase');
        expect(user).toBeUndefined();

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

  describe('with promises', function () {
    describe('with user registration and authentication', function () {
      var User;
      var users;

      beforeAll(function (done) {
        var schema = userSchema();
        schema.plugin(auth);

        /*jshint -W064 */
        users = Array(3).join('.').split('.').map(function () {
        /*jshint +W064 */
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
        User.register(undefined, undefined).onResolve(function (err, user) {
          expect(err).not.toBe(null);
          expect(Object.keys(err.errors).length).toBe(3);
          expect(err.errors.salt).toEqual(jasmine.any(Object));
          expect(err.errors.username).toEqual(jasmine.any(Object));
          expect(err.errors.passphrase).toEqual(jasmine.any(Object));
          expect(user).toBeUndefined();

          done();
        });
      });

      it('should register a new user', function (done) {
        User.register(users[0].username, users[0].password).onResolve(function (err, user) {
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
        User.register(users[0].username, users[0].password).onResolve(function (err, user) {
          expect(err).not.toBe(null);
          expect(err.name).toBe('MongoError');
          expect(err.code).toBe(11000);
          expect(user).toBeUndefined();

          done();
        });
      });

      it('should register a new user with extra fields populated', function (done) {
        User.register(users[1].username, users[1].password, {name: users[1].name}).onResolve(function (err, user) {
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
        User.authenticate(undefined, undefined).onResolve(function (err, user) {
          expect(err).not.toBe(null);
          expect(err.message).toBe('Username was not specified');
          expect(user).toBeUndefined();

          done();
        });
      });

      it('should not authenticate an unknown user', function (done) {
        User.authenticate(users[2].username, undefined).onResolve(function (err, user) {
          expect(err).not.toBe(null);
          expect(err.message).toBe('Unknown username');
          expect(user).toBeUndefined();

          done();
        });
      });

      it('should not authenticate an unspecified passphrase', function (done) {
        User.authenticate(users[0].username, undefined).onResolve(function (err, user) {
          expect(err).not.toBe(null);
          expect(err.message).toBe('Passphrase was not specified');
          expect(user).toBeUndefined();

          done();
        });
      });

      it('should not authenticate a user with an incorrect passphrase', function (done) {
        User.authenticate(users[0].username, faker.internet.password()).onResolve(function (err, user) {
          expect(err).not.toBe(null);
          expect(err.message).toBe('Incorrect passphrase');
          expect(user).toBeUndefined();

          done();
        });
      });

      it('should authenticate a user with correct username/passphrase', function (done) {
        User.authenticate(users[0].username, users[0].password).onResolve(function (err, user) {
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
        var password = faker.internet.password();

        User.setPassphrase(users[1].username, users[1].password, password).onResolve(function (err, user) {
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

          user.authenticate(users[1].password).onResolve(function (err, user) {
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

      it('should update the passphrase and authenticate with extra fields populated', function (done) {
        var password = faker.internet.password();

        User.setPassphrase(users[1].username, users[1].password, password, {name: faker.name.findName()}).onResolve(function (err, user) {
          expect(err).toBe(null);
          expect(user).toEqual(jasmine.any(Object));
          expect(user.id).toBe(users[1].id);
          expect(user.salt).toEqual(jasmine.any(String));
          expect(user.salt).not.toBe(users[1].salt);
          expect(user.passphrase).toEqual(jasmine.any(String));
          expect(user.passphrase).not.toBe(users[1].passphrase);
          expect(user.name).not.toBe(users[1].name);

          users[1].password = password;
          users[1].id = user.id;
          users[1].salt = user.salt;
          users[1].passphrase = user.passphrase;
          users[1].name = user.name;

          user.authenticate(users[1].password).onResolve(function (err, user) {
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
        User.authenticate(users[0].username, users[0].password).onResolve(function (err, user) {
          var password = faker.internet.password();

          expect(err).toBe(null);
          expect(user).toEqual(jasmine.any(Object));
          expect(user.id).toBe(users[0].id);
          expect(user.salt).toEqual(jasmine.any(String));
          expect(user.salt).toBe(users[0].salt);
          expect(user.passphrase).toEqual(jasmine.any(String));
          expect(user.passphrase).toBe(users[0].passphrase);

          user.setPassphrase(password).onResolve(function (err, user) {
            expect(err).toBe(null);
            expect(user).toEqual(jasmine.any(Object));
            expect(user.id).toBe(users[0].id);
            expect(user.salt).toEqual(jasmine.any(String));
            expect(user.salt).not.toBe(users[0].salt);
            expect(user.passphrase).toEqual(jasmine.any(String));
            expect(user.passphrase).not.toBe(users[0].passphrase);

            users[0].password = password;
            users[0].id = user.id;
            users[0].salt = user.salt;
            users[0].passphrase = user.passphrase;

            done();
          });
        });
      });

      it('should authenticate and update the passphrase with extra fields populated', function (done) {
        User.authenticate(users[0].username, users[0].password).onResolve(function (err, user) {
          var password = faker.internet.password();

          expect(err).toBe(null);
          expect(user).toEqual(jasmine.any(Object));
          expect(user.id).toBe(users[0].id);
          expect(user.salt).toEqual(jasmine.any(String));
          expect(user.salt).toBe(users[0].salt);
          expect(user.passphrase).toEqual(jasmine.any(String));
          expect(user.passphrase).toBe(users[0].passphrase);

          user.setPassphrase(password, {name: faker.name.findName()}).onResolve(function (err, user) {
            expect(err).toBe(null);
            expect(user).toEqual(jasmine.any(Object));
            expect(user.id).toBe(users[0].id);
            expect(user.salt).toEqual(jasmine.any(String));
            expect(user.salt).not.toBe(users[0].salt);
            expect(user.passphrase).toEqual(jasmine.any(String));
            expect(user.passphrase).not.toBe(users[0].passphrase);
            expect(user.name).not.toBe(users[0].name);

            users[0].password = password;
            users[0].id = user.id;
            users[0].salt = user.salt;
            users[0].passphrase = user.passphrase;
            users[0].name = user.name;

            done();
          });
        });
      });
    });

    describe('with user registration with usernamePath set to `_id`', function () {
      var User;
      /*jshint -W064 */
      var users = Array(2).join('.').split('.').map(function () {
      /*jshint +W064 */
        return {
          name: faker.name.findName(),
          password: faker.internet.password()
        };
      });

      beforeAll(function (done) {
        var schema = userSchema();
        schema.plugin(auth, {
          username: {path: '_id'}
        });

        User = model('User', schema);

        User.collection.remove(function () {
          done();
        });
      });

      it('should not register a new user without `passphrase` specified', function (done) {
        User.register(undefined).onResolve(function (err, user) {
          expect(err).not.toBe(null);
          expect(Object.keys(err.errors).length).toBe(2);
          expect(err.errors.salt).toEqual(jasmine.any(Object));
          expect(err.errors.passphrase).toEqual(jasmine.any(Object));
          expect(user).toBeUndefined();

          done();
        });
      });

      it('should register a new user', function (done) {
        User.register(users[0].password).onResolve(function (err, user) {
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
        User.register(users[1].password, {name: users[1].name}).onResolve(function (err, user) {
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
        User.authenticate(users[0].id, users[0].password).onResolve(function (err, user) {
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

function userSchema() {
  return new Schema({
    name: String,
    displayName: String
  });
}
