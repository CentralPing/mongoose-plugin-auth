'use strict';

const expect = require('chai').expect;
const mongoose = require('mongoose');
const faker = require('faker');

const auth = require('./auth');

const connectionString = process.env.MONGO_URL || 'mongodb://localhost/unit_test';
const Schema = mongoose.Schema;

// Mongoose uses internal caching for models.
// While {cache: false} works with most models, models using references
// use the internal model cache for the reference.
// This removes the mongoose cache entirely from node's cache
delete require.cache.mongoose;

// Set Mongoose internal promise object to be the native Promise object
mongoose.Promise = global.Promise;

describe('Mongoose plugin: auth', function () {
  let connection;

  // Prevent test timeout on travis
  this.timeout(5000);

  before(function (done) {
    connection = mongoose.createConnection(connectionString);
    connection.once('connected', done);
  });

  after(function (done) {
    connection.db.dropDatabase(function () {
      connection.close(done);
    });
  });

  describe('with schema', function () {
    let schema;

    before(function () {
      schema = userSchema();
      schema.plugin(auth);
    });

    it('should append statics to Schema', function () {
      expect(schema.statics).to.have.all.keys(
        'authenticate',
        'register',
        'setPassphrase'
      );
    });

    it('should append paths to Schema', function () {
      expect(schema.paths).to.have.all.keys(
        '_id',
        'displayName',
        'name',
        'passphrase',
        'salt',
        'username'
      );
    });

    it('should append `passphrase`', function () {
      expect(schema.path('passphrase')).to.be.defined;
      expect(schema.path('passphrase').isRequired).to.be.true;
    });

    it('should append `salt`', function () {
      expect(schema.path('salt')).to.be.defined;
      expect(schema.path('salt').isRequired).to.be.true;
    });

    it('should append `username`', function () {
      expect(schema.path('username')).to.be.defined;
      expect(schema.path('username').isRequired).to.be.true;
    });
  });

  describe('with model instance', function () {
    let user;

    before(function () {
      const schema = userSchema();
      schema.plugin(auth);

      const User = model(connection, 'User', schema);
      user = new User();
    });

    it('should append method `authenticate`', function () {
      expect(user.authenticate).to.be.a('function');
    });

    it('should append method `setPassphrase`', function () {
      expect(user.setPassphrase).to.be.a('function');
    });
  });

  describe('with plugin options', function () {
    it('should allow custom paths', function () {
      const schema = userSchema();

      schema.plugin(auth, {
        username: { path: 'u' },
        salt: { path: 's' },
        passphrase: { path: 'h' }
      });

      expect(schema.path('u')).to.be.defined;
      expect(schema.path('s')).to.be.defined;
      expect(schema.path('h')).to.be.defined;
    });

    // TODO: test all options
  });

  describe('with user registration and authentication', function () {
    let User;
    let users;

    before(function (done) {
      const schema = userSchema();
      schema.plugin(auth);

      users = Array(3).join('.').split('.').map(function () {
        return {
          name: faker.name.findName(),
          username: faker.internet.userName(),
          password: faker.internet.password()
        };
      });

      User = model(connection, 'User', schema);

      User.collection.remove(done);
    });

    it('should not register a new user without either `username` or `passphrase` specified', function (done) {
      User.register(undefined, undefined, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.errors).to.have.all.keys('salt', 'username', 'passphrase');
        expect(err.errors.salt).to.be.an('object');
        expect(err.errors.username).to.be.an('object');
        expect(err.errors.passphrase).to.be.an('object');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should register a new user', function (done) {
      User.register(users[0].username, users[0].password, function (err, user) {
        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.username).to.be.equal(users[0].username);
        expect(user.salt).to.be.a('string');
        expect(user.passphrase).to.be.a('string');
        expect(user.passphrase).not.to.be.equal(users[0].password);

        users[0].id = user.id;
        users[0].salt = user.salt;
        users[0].passphrase = user.passphrase;

        done();
      });
    });

    it('should not register a new user with an existing `username`', function (done) {
      User.register(users[0].username, users[0].password, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.name).to.be.equal('MongoError');
        expect(err.code).to.be.equal(11000);
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should register a new user with extra fields populated', function (done) {
      User.register(users[1].username, users[1].password, { name: users[1].name }, function (err, user) {
        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.username).to.be.equal(users[1].username);
        expect(user.name).to.be.equal(users[1].name);
        expect(user.salt).to.be.a('string');
        expect(user.passphrase).to.be.a('string');
        expect(user.passphrase).not.to.be.equal(users[1].password);

        users[1].id = user.id;
        users[1].salt = user.salt;
        users[1].passphrase = user.passphrase;

        done();
      });
    });

    it('should not authenticate an unspecified user', function (done) {
      User.authenticate(undefined, undefined, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.message).to.be.equal('Username was not specified');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should not authenticate an unknown user', function (done) {
      User.authenticate(users[2].username, undefined, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.message).to.be.equal('Unknown username');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should not authenticate an unspecified passphrase', function (done) {
      User.authenticate(users[0].username, undefined, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.message).to.be.equal('Passphrase was not specified');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should not authenticate a user with an incorrect passphrase', function (done) {
      User.authenticate(users[0].username, faker.internet.password(), function (err, user) {
        expect(err).not.to.be.null;
        expect(err.message).to.be.equal('Incorrect passphrase');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should authenticate a user with correct username/passphrase', function (done) {
      User.authenticate(users[0].username, users[0].password, function (err, user) {
        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.id).to.be.equal(users[0].id);
        expect(user.salt).to.be.a('string');
        expect(user.salt).to.be.equal(users[0].salt);
        expect(user.passphrase).to.be.a('string');
        expect(user.passphrase).to.be.equal(users[0].passphrase);

        done();
      });
    });

    it('should update the passphrase and authenticate', function (done) {
      const password = faker.internet.password();

      User.setPassphrase(users[1].username, users[1].password, password, function (err, user) {
        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.id).to.be.equal(users[1].id);
        expect(user.salt).to.be.a('string');
        expect(user.salt).not.to.be.equal(users[1].salt);
        expect(user.passphrase).to.be.a('string');
        expect(user.passphrase).not.to.be.equal(users[1].passphrase);

        users[1].password = password;
        users[1].id = user.id;
        users[1].salt = user.salt;
        users[1].passphrase = user.passphrase;

        user.authenticate(users[1].password, function (err, user) {
          expect(err).to.be.null;
          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[1].id);
          expect(user.salt).to.be.a('string');
          expect(user.salt).to.be.equal(users[1].salt);
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).to.be.equal(users[1].passphrase);

          done();
        });
      });
    });

    it('should update the passphrase and authenticate with extra fields populated', function (done) {
      const password = faker.internet.password();

      User.setPassphrase(users[1].username, users[1].password, password, { name: faker.name.findName() }, function (err, user) {
        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.id).to.be.equal(users[1].id);
        expect(user.salt).to.be.a('string');
        expect(user.salt).not.to.be.equal(users[1].salt);
        expect(user.passphrase).to.be.a('string');
        expect(user.passphrase).not.to.be.equal(users[1].passphrase);
        expect(user.name).not.to.be.equal(users[1].name);

        users[1].password = password;
        users[1].id = user.id;
        users[1].salt = user.salt;
        users[1].passphrase = user.passphrase;
        users[1].name = user.name;

        user.authenticate(users[1].password, function (err, user) {
          expect(err).to.be.null;
          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[1].id);
          expect(user.salt).to.be.a('string');
          expect(user.salt).to.be.equal(users[1].salt);
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).to.be.equal(users[1].passphrase);

          done();
        });
      });
    });

    it('should authenticate and update the passphrase', function (done) {
      User.authenticate(users[0].username, users[0].password, function (err, user) {
        const password = faker.internet.password();

        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.id).to.be.equal(users[0].id);
        expect(user.salt).to.be.a('string');
        expect(user.salt).to.be.equal(users[0].salt);
        expect(user.passphrase).to.be.a('string');
        expect(user.passphrase).to.be.equal(users[0].passphrase);

        user.setPassphrase(password, function (err, user) {
          expect(err).to.be.null;
          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[0].id);
          expect(user.salt).to.be.a('string');
          expect(user.salt).not.to.be.equal(users[0].salt);
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).not.to.be.equal(users[0].passphrase);

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
        const password = faker.internet.password();

        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.id).to.be.equal(users[0].id);
        expect(user.salt).to.be.a('string');
        expect(user.salt).to.be.equal(users[0].salt);
        expect(user.passphrase).to.be.a('string');
        expect(user.passphrase).to.be.equal(users[0].passphrase);

        user.setPassphrase(password, { name: faker.name.findName() }, function (err, user) {
          expect(err).to.be.null;
          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[0].id);
          expect(user.salt).to.be.a('string');
          expect(user.salt).not.to.be.equal(users[0].salt);
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).not.to.be.equal(users[0].passphrase);
          expect(user.name).not.to.be.equal(users[0].name);

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
    let User;

    const users = Array(2).join('.').split('.').map(function () {
      return {
        name: faker.name.findName(),
        password: faker.internet.password()
      };
    });

    before(function (done) {
      const schema = userSchema();
      schema.plugin(auth, {
        username: { path: '_id' }
      });

      User = model(connection, 'User', schema);

      User.collection.remove(done);
    });

    it('should not register a new user without `passphrase` specified', function (done) {
      User.register(undefined, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.errors).to.have.all.keys('salt', 'passphrase');
        expect(err.errors.salt).to.be.an('object');
        expect(err.errors.passphrase).to.be.an('object');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should register a new user', function (done) {
      User.register(users[0].password, function (err, user) {
        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.id).to.be.defined;
        expect(user.salt).to.be.a('string');
        expect(user.passphrase).to.be.a('string');

        users[0].id = user.id;

        done();
      });
    });

    it('should register a new user with extra fields populated', function (done) {
      User.register(users[1].password, { name: users[1].name }, function (err, user) {
        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.id).to.be.defined;
        expect(user.name).to.be.equal(users[1].name);
        expect(user.salt).to.be.a('string');
        expect(user.passphrase).to.be.a('string');

        users[1].id = user.id;

        done();
      });
    });

    it('should not authenticate an unspecified user', function (done) {
      User.authenticate(undefined, undefined, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.message).to.be.equal('Username was not specified');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should not authenticate a specified user of incorrect type', function (done) {
      User.authenticate(faker.internet.userName(), undefined, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.message).to.be.equal('Unknown username');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should not authenticate an unknown user', function (done) {
      User.authenticate(mongoose.Types.ObjectId(), undefined, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.message).to.be.equal('Unknown username');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should not authenticate an unspecified passphrase', function (done) {
      User.authenticate(users[0].id, undefined, function (err, user) {
        expect(err).not.to.be.null;
        expect(err.message).to.be.equal('Passphrase was not specified');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should not authenticate a user with an incorrect passphrase', function (done) {
      User.authenticate(users[0].id, faker.internet.password(), function (err, user) {
        expect(err).not.to.be.null;
        expect(err.message).to.be.equal('Incorrect passphrase');
        expect(user).to.be.undefined;

        done();
      });
    });

    it('should authenticate a user', function (done) {
      User.authenticate(users[0].id, users[0].password, function (err, user) {
        expect(err).to.be.null;
        expect(user).to.be.an('object');
        expect(user.id).to.be.equal(users[0].id);
        expect(user.salt).to.be.a('string');
        expect(user.passphrase).to.be.a('string');

        done();
      });
    });
  });

  describe('with promises', function () {
    describe('with user registration and authentication', function () {
      let User;
      let users;

      before(function (done) {
        const schema = userSchema();
        schema.plugin(auth);

        users = Array(3).join('.').split('.').map(function () {
          return {
            name: faker.name.findName(),
            username: faker.internet.userName(),
            password: faker.internet.password()
          };
        });

        User = model(connection, 'User', schema);

        User.collection.remove(done);
      });

      it('should not register a new user without either `username` or `passphrase` specified', function () {
        return User.register(undefined, undefined).then(function () {
          // Shouldn't get here
          throw new Error('Test failed');
        }).catch(function (err) {
          expect(err.errors).to.have.all.keys('salt', 'username', 'passphrase');
          expect(err.errors.salt).to.be.an('object');
          expect(err.errors.username).to.be.an('object');
          expect(err.errors.passphrase).to.be.an('object');
        });
      });

      it('should register a new user', function () {
        return User.register(users[0].username, users[0].password).then(function (user) {
          expect(user).to.be.an('object');
          expect(user.username).to.be.equal(users[0].username);
          expect(user.salt).to.be.a('string');
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).not.to.be.equal(users[0].password);

          users[0].id = user.id;
          users[0].salt = user.salt;
          users[0].passphrase = user.passphrase;
        });
      });

      it('should not register a new user with an existing `username`', function () {
        return User.register(users[0].username, users[0].password).then(function () {
          // Shouldn't get here
          throw new Error('Test failed');
        }).catch(function (err) {
          expect(err).not.to.be.null;
          expect(err.name).to.be.equal('MongoError');
          expect(err.code).to.be.equal(11000);
        });
      });

      it('should register a new user with extra fields populated', function () {
        return User.register(users[1].username, users[1].password, { name: users[1].name }).then(function (user) {
          expect(user).to.be.an('object');
          expect(user.username).to.be.equal(users[1].username);
          expect(user.name).to.be.equal(users[1].name);
          expect(user.salt).to.be.a('string');
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).not.to.be.equal(users[1].password);

          users[1].id = user.id;
          users[1].salt = user.salt;
          users[1].passphrase = user.passphrase;
        });
      });

      it('should not authenticate an unspecified user', function () {
        return User.authenticate(undefined, undefined).then(function () {
          // Shouldn't get here
          throw new Error('Test failed');
        }).catch(function (err) {
          expect(err).not.to.be.null;
          expect(err.message).to.be.equal('Username was not specified');
        });
      });

      it('should not authenticate an unknown user', function () {
        return User.authenticate(users[2].username, undefined).then(function () {
          // Shouldn't get here
          throw new Error('Test failed');
        }).catch(function (err) {
          expect(err).not.to.be.null;
          expect(err.message).to.be.equal('Unknown username');
        });
      });

      it('should not authenticate an unspecified passphrase', function () {
        return User.authenticate(users[0].username, undefined).then(function () {
          // Shouldn't get here
          throw new Error('Test failed');
        }).catch(function (err) {
          expect(err).not.to.be.null;
          expect(err.message).to.be.equal('Passphrase was not specified');
        });
      });

      it('should not authenticate a user with an incorrect passphrase', function () {
        return User.authenticate(users[0].username, faker.internet.password()).then(function () {
          // Shouldn't get here
          throw new Error('Test failed');
        }).catch(function (err) {
          expect(err).not.to.be.null;
          expect(err.message).to.be.equal('Incorrect passphrase');
        });
      });

      it('should authenticate a user with correct username/passphrase', function () {
        return User.authenticate(users[0].username, users[0].password).then(function (user) {
          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[0].id);
          expect(user.salt).to.be.a('string');
          expect(user.salt).to.be.equal(users[0].salt);
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).to.be.equal(users[0].passphrase);
        });
      });

      it('should update the passphrase and authenticate', function () {
        const password = faker.internet.password();

        return User.setPassphrase(users[1].username, users[1].password, password).then(function (user) {
          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[1].id);
          expect(user.salt).to.be.a('string');
          expect(user.salt).not.to.be.equal(users[1].salt);
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).not.to.be.equal(users[1].passphrase);

          users[1].password = password;
          users[1].id = user.id;
          users[1].salt = user.salt;
          users[1].passphrase = user.passphrase;

          return user.authenticate(users[1].password).then(function (user) {
            expect(user).to.be.an('object');
            expect(user.id).to.be.equal(users[1].id);
            expect(user.salt).to.be.a('string');
            expect(user.salt).to.be.equal(users[1].salt);
            expect(user.passphrase).to.be.a('string');
            expect(user.passphrase).to.be.equal(users[1].passphrase);
          });
        });
      });

      it('should update the passphrase and authenticate with extra fields populated', function () {
        const password = faker.internet.password();

        return User.setPassphrase(users[1].username, users[1].password, password, { name: faker.name.findName() }).then(function (user) {
          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[1].id);
          expect(user.salt).to.be.a('string');
          expect(user.salt).not.to.be.equal(users[1].salt);
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).not.to.be.equal(users[1].passphrase);
          expect(user.name).not.to.be.equal(users[1].name);

          users[1].password = password;
          users[1].id = user.id;
          users[1].salt = user.salt;
          users[1].passphrase = user.passphrase;
          users[1].name = user.name;

          return user.authenticate(users[1].password).then(function (user) {
            expect(user).to.be.an('object');
            expect(user.id).to.be.equal(users[1].id);
            expect(user.salt).to.be.a('string');
            expect(user.salt).to.be.equal(users[1].salt);
            expect(user.passphrase).to.be.a('string');
            expect(user.passphrase).to.be.equal(users[1].passphrase);
          });
        });
      });

      it('should authenticate and update the passphrase', function () {
        return User.authenticate(users[0].username, users[0].password).then(function (user) {
          const password = faker.internet.password();

          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[0].id);
          expect(user.salt).to.be.a('string');
          expect(user.salt).to.be.equal(users[0].salt);
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).to.be.equal(users[0].passphrase);

          return user.setPassphrase(password).then(function (user) {
            expect(user).to.be.an('object');
            expect(user.id).to.be.equal(users[0].id);
            expect(user.salt).to.be.a('string');
            expect(user.salt).not.to.be.equal(users[0].salt);
            expect(user.passphrase).to.be.a('string');
            expect(user.passphrase).not.to.be.equal(users[0].passphrase);

            users[0].password = password;
            users[0].id = user.id;
            users[0].salt = user.salt;
            users[0].passphrase = user.passphrase;
          });
        });
      });

      it('should authenticate and update the passphrase with extra fields populated', function () {
        return User.authenticate(users[0].username, users[0].password).then(function (user) {
          const password = faker.internet.password();

          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[0].id);
          expect(user.salt).to.be.a('string');
          expect(user.salt).to.be.equal(users[0].salt);
          expect(user.passphrase).to.be.a('string');
          expect(user.passphrase).to.be.equal(users[0].passphrase);

          return user.setPassphrase(password, { name: faker.name.findName() }).then(function (user) {
            expect(user).to.be.an('object');
            expect(user.id).to.be.equal(users[0].id);
            expect(user.salt).to.be.a('string');
            expect(user.salt).not.to.be.equal(users[0].salt);
            expect(user.passphrase).to.be.a('string');
            expect(user.passphrase).not.to.be.equal(users[0].passphrase);
            expect(user.name).not.to.be.equal(users[0].name);

            users[0].password = password;
            users[0].id = user.id;
            users[0].salt = user.salt;
            users[0].passphrase = user.passphrase;
            users[0].name = user.name;
          });
        });
      });
    });

    describe('with user registration with usernamePath set to `_id`', function () {
      let User;
      let users;

      before(function (done) {
        const schema = userSchema();
        schema.plugin(auth, {
          username: { path: '_id' }
        });

        users = Array(2).join('.').split('.').map(function () {
          return {
            name: faker.name.findName(),
            password: faker.internet.password()
          };
        });

        User = model(connection, 'User', schema);

        User.collection.remove(done);
      });

      it('should not register a new user without `passphrase` specified', function () {
        return User.register(undefined).then(function () {
          // Shouldn't get here
          throw new Error('Test failed');
        }).catch(function (err) {
          expect(err).not.to.be.null;
          expect(err.errors).to.have.all.keys('salt', 'passphrase');
          expect(err.errors.salt).to.be.an('object');
          expect(err.errors.passphrase).to.be.an('object');
        });
      });

      it('should register a new user', function () {
        return User.register(users[0].password).then(function (user) {
          expect(user).to.be.an('object');
          expect(user.id).to.be.defined;
          expect(user.salt).to.be.a('string');
          expect(user.passphrase).to.be.a('string');

          users[0].id = user.id;
        });
      });

      it('should register a new user with extra fields populated', function () {
        return User.register(users[1].password, { name: users[1].name }).then(function (user) {
          expect(user).to.be.an('object');
          expect(user.id).to.be.defined;
          expect(user.name).to.be.equal(users[1].name);
          expect(user.salt).to.be.a('string');
          expect(user.passphrase).to.be.a('string');

          users[1].id = user.id;
        });
      });

      it('should authenticate a user', function () {
        return User.authenticate(users[0].id, users[0].password).then(function (user) {
          expect(user).to.be.an('object');
          expect(user.id).to.be.equal(users[0].id);
          expect(user.salt).to.be.a('string');
          expect(user.passphrase).to.be.a('string');
        });
      });
    });
  });
});

function model(conn, name, schema) {
  if (arguments.length === 2) {
    schema = name;
    name = 'Model';
  }

  // Specifying a collection name allows the model to be overwritten in
  // Mongoose's model cache
  return conn.model(name, schema, name);
}

function userSchema() {
  return new Schema({
    name: String,
    displayName: String
  });
}
