var gulp = require("gulp"),
    babel = require("gulp-babel"),
    uglify = require('gulp-uglify'),
    ngAnnotate = require('gulp-ng-annotate'),
    sourcemaps = require('gulp-sourcemaps')
    rename = require('gulp-rename');

gulp.task('es6', function() {
    return gulp.src('src/ng-web-crypto.js')
    .pipe(gulp.dest('dist'));
});

gulp.task('es5', function() {
    return gulp.src('src/ng-web-crypto.js')    
    .pipe(babel())        
    .pipe(rename({ extname: '.es5.js' }))
    .pipe(gulp.dest('dist'));
})

gulp.task('default', ['es5', 'es6'], function() {
    gulp.src('dist/ng-web-crypto.es5.js')
    .pipe(sourcemaps.init())
    .pipe(ngAnnotate())
    .pipe(uglify({preserveComments: 'license'}))
    .pipe(rename({ extname: '.min.js' }))
    .pipe(sourcemaps.write('.'))
    .pipe(gulp.dest('dist'))
});