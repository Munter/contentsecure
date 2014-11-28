contentsecure
=============
[![NPM version](https://badge.fury.io/js/contentsecure.png)](http://badge.fury.io/js/contentsecure)
[![Build Status](https://travis-ci.org/Munter/contentsecure.png?branch=master)](https://travis-ci.org/Munter/contentsecure)
[![Coverage Status](https://coveralls.io/repos/Munter/contentsecure/badge.png)](https://coveralls.io/r/Munter/contentsecure)
[![Dependency Status](https://david-dm.org/Munter/contentsecure.png)](https://david-dm.org/Munter/contentsecure)

A Content Security Policy auto generator.

Read more about [Content Security Policies](http://www.w3.org/TR/CSP/).

This binary will return a string that you can use as an http-header in your web server responses, which in turn will make browsers that support Content Security Policies follow this policy.


Installation
============

```
npm install -g contentsecure
```

Usage
=====

`contentsecure -h` will show you a list of all command line options.

`contensecure` takes any number of web assets as input arguments. It will parse all of these assets and follow any relations to other assets. Think if this as a scraper for your website, except that it only populates assets that are on your local disk.

Example:
```
contentsecure path/to/index.html /path/to/404.html /path/to/docs/**/*.html
```

Note that you usually only need to set entry pages as a seed for contentsecure, since it finds dependencies and relations itself.


TODO
====

- XSLT restraints in script-src
- Script eval detection and unsafe switch for it
- HtmlTrack restraint in media-src
- HtmlSource restraint in media-src
- A way to add predefined manually configured rules


License
=======
BSD


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/Munter/contentsecure/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

