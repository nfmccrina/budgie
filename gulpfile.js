var browserify = require('browserify');
var gulp = require('gulp');
var source = require('vinyl-source-stream');
 
gulp.task('build', function() {
    return browserify('src/client/js/index.js')
        .bundle()
        .pipe(source('build.js'))
        .pipe(gulp.dest('./wwwroot/'));
});