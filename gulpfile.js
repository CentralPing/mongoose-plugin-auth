'use strict';

const fs = require('fs');
const args = require('yargs').argv;
const gulp = require('gulp');
const gulpIf = require('gulp-if');
const debug = require('gulp-debug');
const jshint = require('gulp-jshint');
const todo = require('gulp-todo');
const gulpMocha = require('gulp-mocha');
const gutil = require('gulp-util');
const concat = require('gulp-concat');
const jsdoc2md = require('gulp-jsdoc-to-markdown');

const isDebug = !!args.debug;
const isVerbose = !!args.verbose;
const cliSrc = args.files;

const config = {
  paths: {
    scripts: ['./**/*.js', '!./**/*.spec.js', '!./node_modules/**/*.js'],
    specs: ['./**/*.spec.js', '!./node_modules/**/*.js'],
    all: ['./**/*.js', '!./node_modules/**/*.js']
  }
};

gulp.task('default', function () {
  // place code for your default task here
});

gulp.task('lint', function () {
  // Check for `test` to ensure both the specified specs
  // and corresponding scripts are linted
  const glob = cliSrc ?
    cliSrc.replace(/\.spec\.js$/, '?(.spec).js') :
    config.paths.all;

  return lint(glob);
});

gulp.task('lint:scripts', function (done) {
  return lint(config.paths.scripts);
});

gulp.task('lint:spec', function (done) {
  return lint(config.paths.specs);
});

gulp.task('test', ['lint'], function (done) {
  return testRunner(cliSrc || config.paths.specs);
});

gulp.task('watch', ['test'], function (done) {
  // Check to ensure both the specified specs
  // and corresponding scripts are watched
  const glob = cliSrc ?
    cliSrc.replace(/\.spec\.js$/, '?(.spec).js') :
    config.paths.all;

  return gulp.watch(glob, ['test']);
});

gulp.task('todo', function (done) {
  return gulp.src(config.paths.all)
  .pipe(todo({
    //fileName: 'todo.md',
    verbose: isVerbose,
    //newLine: gutil.linefeed,
    /*
    transformComment: function (file, line, text) {
        return ['| ' + file + ' | ' + line + ' | ' + text];
    },
    transformHeader: function (kind) {
        return ['### ' + kind + 's',
            '| Filename | line # | todo',
            '|:------|:------:|:------'
        ];
    }
    */
  }))
  .pipe(gulp.dest('./'));
});

gulp.task('docs', function() {
  return gulp.src(config.paths.all)
  .pipe(concat('README.md'))
  .pipe(jsdoc2md({ template: fs.readFileSync('./readme.hbs', 'utf8') }))
  .on('error', function (err) {
    gutil.log('jsdoc2md failed:', err.message);
  })
  .pipe(gulp.dest('.'));
});

function testRunner(src) {
  if (arguments.length > 1) {
    src = [].concat([].slice.call(arguments));
  }

  return gulp.src(src, { read: false })
  .pipe(gulpIf(isDebug, debug({ title: 'test:' })))
  .pipe(gulpMocha({
    //ui: 'bdd',
    //reporter: 'spec',
    //globals: [],
    //timeout: 2000,
    //bail: false,
    //ignoreLeaks: false,
    //grep: '',
    //require: []
  }));
}

function lint(src) {
  return gulp.src(src)
  .pipe(gulpIf(isDebug, debug({ title: 'lint:' })))
  .pipe(jshint())
  .pipe(jshint.reporter('default', { verbose: isVerbose }))
  .pipe(jshint.reporter('fail'));
}
