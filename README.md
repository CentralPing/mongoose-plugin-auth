mongoose-plugin-auth
====================

[![Build Status](https://travis-ci.org/CentralPing/mongoose-plugin-auth.svg?branch=master)](https://travis-ci.org/CentralPing/mongoose-plugin-auth)
[![Code Climate for CentralPing/mongoose-plugin-auth](https://codeclimate.com/github/CentralPing/mongoose-plugin-auth/badges/gpa.svg)](https://codeclimate.com/github/CentralPing/mongoose-plugin-auth)
[![Dependency Status for CentralPing/mongoose-plugin-auth](https://david-dm.org/CentralPing/mongoose-plugin-auth.svg)](https://david-dm.org/CentralPing/mongoose-plugin-auth)

A [mongoose.js](https://github.com/Automattic/mongoose/) plugin to add authorization methods to models and instances.

## Installation

`npm i --save mongoose-plugin-auth`

## API Reference
**Example**  
```js
var authPlugin = require('mongoose-plugin-auth');
var schema = Schema({...});
schema.plugin(authPlugin[, OPTIONS]);
```
<a name="module_mongoose-plugin-auth..options"></a>

### mongoose-plugin-auth~options
**Kind**: inner property of <code>[mongoose-plugin-auth](#module_mongoose-plugin-auth)</code>  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [options] | <code>object</code> |  |  |
| [options.username] | <code>object</code> |  | options for configuring the username. |
| [options.username.path] | <code>string</code> | <code>&quot;username&quot;</code> | the path for storing the username. *Value can be set to `_id`* |
| [options.username.options] | <code>object</code> |  | options for configuring the username path in the schema. |
| [options.username.options.type] | <code>object</code> | <code>String</code> | object type for the username path. *Specifying an existing username path ignores all options specified here.* |
| [options.username.options.required] | <code>boolean</code> | <code>true</code> | spcifies wether the username path is required. |
| [options.username.options.unique] | <code>boolean</code> | <code>true</code> | spcifies wether the username path is required. |
| [options.username.options.sparse] | <code>boolean</code> | <code>true</code> | spcifies wether the username path is required. |
| [options.username.options.trim] | <code>boolean</code> | <code>true</code> | spcifies wether the username path is required. |
| [options.username.missingError] | <code>string</code> | <code>&quot;Username was not specified&quot;</code> | message returned via an error object for methods requiring a username. |
| [options.username.incorrectError] | <code>string</code> | <code>&quot;Unknown username&quot;</code> | message returned via an error object if username does not match a record. |
| [options.passphrase] | <code>object</code> |  | options for configuring the passphrase. |
| [options.passphrase.path] | <code>string</code> | <code>&quot;passphrase&quot;</code> | the path for storing the passphrase. |
| [options.passphrase.options] | <code>object</code> |  | options for configuring the passphrase path in the schema. |
| [options.passphrase.options.type] | <code>object</code> | <code>String</code> | object type for the passphrase path. *Specifying an existing passphrase path ignores all options specified here.* |
| [options.passphrase.options.required] | <code>boolean</code> | <code>true</code> | spcifies wether the passphrase path is required. |
| [options.passphrase.missingError] | <code>string</code> | <code>&quot;Passphrase was not specified&quot;</code> | message returned via an error object for methods requiring a passphrase. |
| [options.passphrase.incorrectError] | <code>string</code> | <code>&quot;Incorrect passphrase&quot;</code> | message returned via an error object if passphrase does not match the record. |
| [options.salt] | <code>object</code> |  | options for configuring the salt. |
| [options.salt.path] | <code>string</code> | <code>&quot;salt&quot;</code> | the path for storing the salt. |
| [options.salt.options] | <code>object</code> |  | options for configuring the salt path in the schema. |
| [options.salt.options.type] | <code>object</code> | <code>String</code> | object type for the salt path. *Specifying an existing salt path ignores all options specified here.* |
| [options.salt.options.required] | <code>boolean</code> | <code>true</code> | spcifies wether the salt path is required. |
| [options.salt.len] | <code>number</code> | <code>32</code> | the string length to use for the salt. |
| [options.hash] | <code>object</code> |  | options for configuring the hash using the [crypto](https://nodejs.org/api/crypto.html) module. |
| [options.hash.iterations] | <code>number</code> | <code>25000</code> | number of iterations for generating the hash. |
| [options.hash.keylen.type] | <code>number</code> | <code>512</code> | the string length of the generated hash. |
| [options.hash.encoding] | <code>string</code> | <code>&quot;hex&quot;</code> | the encoding algorithm to use for the hash. |
| [Error] | <code>object</code> | <code>Error</code> | Error object to use for reporting errors. *Must be of the type Error or inherites from it* |
| [select] | <code>string</code> |  | Mongoose field selection to use for authenticate method/static. |
| [populate] | <code>string</code> |  | Mongoose populate selection to use for authenticate method/static. |

<a name="module_mongoose-plugin-auth..register"></a>

### mongoose-plugin-auth~register([username], passphrase, [extra], [cb]) ⇒ <code>promise</code>
The `register` static is a convenience function to add a new user document.

**Kind**: inner method of <code>[mongoose-plugin-auth](#module_mongoose-plugin-auth)</code>  

| Param | Type | Description |
| --- | --- | --- |
| [username] | <code>string</code> | Username value to use. Optional if using the `_id` value. |
| passphrase | <code>string</code> | Raw passphrase value. Hashed automatically before storing using crypto module. |
| [extra] | <code>object</code> | Any extra object properties that match the schema to be included in the new user document. |
| [cb] | <code>function</code> | A mongoose promise is returned if no callback is provided. |

**Example**  
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
<a name="module_mongoose-plugin-auth..setPassphrase"></a>

### mongoose-plugin-auth~setPassphrase(username, passphrase, newPassphrase, [extra], [cb]) ⇒ <code>promise</code>
The `setPassphrase` static is a convenience function to set the passphrase for a user. *Alternatively you can simply set the passphrase to a new value directly on the document object and save/update.*

**Kind**: inner method of <code>[mongoose-plugin-auth](#module_mongoose-plugin-auth)</code>  

| Param | Type | Description |
| --- | --- | --- |
| username | <code>string</code> | Username value to use. |
| passphrase | <code>string</code> | Raw passphrase value. Hashed automatically before storing using crypto module. |
| newPassphrase | <code>string</code> | Raw new passphrase value. Hashed automatically before storing using crypto module. |
| [extra] | <code>object</code> | Any extra object properties that match the schema to be included in the update. |
| [cb] | <code>function</code> | A mongoose promise is returned if no callback is provided. |

**Example**  
```js
MyUserModel.setPassphrase('tom', 'my secret passphrase', 'my new secret passphrase', {email: tom@jerry.com}, function(err, user) { ... });
MyUserModel.setPassphrase('tom', 'my secret passphrase', 'my new secret passphrase', {email: tom@jerry.com}).then(function(user) { ... }, function(err) {...}); // Uses promise
MyUserModel.setPassphrase('tom', 'my secret passphrase', 'my new secret passphrase', function(err, user) { ... });
MyUserModel.setPassphrase('tom', 'my secret passphrase', 'my new secret passphrase').then(function(user) { ... }, function(err) {...}); // Uses promise
  ```
<a name="module_mongoose-plugin-auth..setPassphrase"></a>

### mongoose-plugin-auth~setPassphrase(passphrase, [extra], [cb]) ⇒ <code>promise</code>
The `setPassphrase` method is a convenience function to set the passphrase for a user. *Alternatively you can simply set the passphrase to a new value directly on the document object and save/update.*

**Kind**: inner method of <code>[mongoose-plugin-auth](#module_mongoose-plugin-auth)</code>  

| Param | Type | Description |
| --- | --- | --- |
| passphrase | <code>string</code> | Raw new passphrase value. Hashed automatically before storing using crypto module. |
| [extra] | <code>object</code> | Any extra object properties that match the schema to be included in the update. |
| [cb] | <code>function</code> | A mongoose promise is returned if no callback is provided. |

**Example**  
```js
user.setPassphrase('my new secret passphrase', {email: tom@jerry.com}, function(err, user) { ... });
user.setPassphrase('my new secret passphrase', {email: tom@jerry.com}).then(function(user) { ... }, function(err) {...}); // Uses promise
user.setPassphrase('my new secret passphrase', function(err, user) { ... });
user.setPassphrase('my new secret passphrase').then(function(user) { ... }, function(err) {...}); // Uses promise
  ```
<a name="module_mongoose-plugin-auth..authenticate"></a>

### mongoose-plugin-auth~authenticate(username, passphrase, [cb]) ⇒ <code>promise</code>
The `authenticate` static is a function to validate the passphrase for a user.

**Kind**: inner method of <code>[mongoose-plugin-auth](#module_mongoose-plugin-auth)</code>  

| Param | Type | Description |
| --- | --- | --- |
| username | <code>string</code> | Username value to use. |
| passphrase | <code>string</code> | Raw passphrase value. Hashed automatically before storing using crypto module. |
| [cb] | <code>function</code> | A mongoose promise is returned if no callback is provided. |

**Example**  
```js
MyUserModel.authenticate('tom', 'my secret passphrase', function(err, user) { ... });
MyUserModel.authenticate('tom', 'my secret passphrase').then(function(user) { ... }, function(err) {...}); // Uses promise
  ```
<a name="module_mongoose-plugin-auth..authenticate"></a>

### mongoose-plugin-auth~authenticate(passphrase, [cb]) ⇒ <code>promise</code>
The `authenticate` method is a function to validate the passphrase for a user.

**Kind**: inner method of <code>[mongoose-plugin-auth](#module_mongoose-plugin-auth)</code>  

| Param | Type | Description |
| --- | --- | --- |
| passphrase | <code>string</code> | Raw passphrase value. Hashed automatically before storing using crypto module. |
| [cb] | <code>function</code> | A mongoose promise is returned if no callback is provided. |

**Example**  
```js
user.authenticate('my secret passphrase', function(err, user) { ... });
user.authenticate('my secret passphrase').then(function(user) { ... }, function(err) {...}); // Uses promise
  ```

## Examples

### With Defaults
```js
var authPlugin = require('mongoose-plugin-auth');
var schema = Schema({foo: String});
schema.plugin(authPlugin);

var Foo = mongoose.model('Foo', schema);
Foo.register('tom', 'my new passphrase').then(function (user) {
  // user is a new document persisted to the database
});

// ...

Foo.authenticate('tom', 'my new passphrase').then(function (user) {
  // user is the authenticated user document
}).then(null, function(err) {
  // err will report any authentication errors.
});
```

### With Options (using `_id` as username)
```js
var authPlugin = require('mongoose-plugin-auth');
var schema = Schema({foo: String});
schema.plugin(authPlugin{
  username: {path: '_id'}
});

var Foo = mongoose.model('Foo', schema);
Foo.register('my new passphrase').then(function (user) {
  // user is a new document persisted to the database
});

// ...

Foo.authenticate('507f191e810c19729de970fb', 'my new passphrase').then(function (user) {
  // user is the authenticated user document
}).then(null, function(err) {
  // err will report any authentication errors.
});
```

# License

Apache 2.0
