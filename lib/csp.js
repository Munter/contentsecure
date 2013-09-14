// CSP documentation: http://www.w3.org/TR/CSP/

var url = require('url');

function getDomain(str) {
    var parsed = url.parse(str);
    return parsed.protocol + '//' + parsed.host;
}

function uniq(array) {
    return array.reduce(function (prev, current) {
        if (prev.indexOf(current) === -1) {
            return prev.concat(current);
        }

        return prev;
    }, []);
}

module.exports = function (config) {
    var headerName = 'Content-Security-Policy',
        rules = {
            'default-src': [],
            'script-src': [],
            'object-src': [],
            'style-src': [],
            'img-src': [],
            'media-src': [],
            'frame-src': [],
            'font-src': [],
            'connect-src': [],
            'sandbox': [],
            'report-uri': []
        };

/*
    if (config.report) {
        headerName += '-Report-Only';
    }
*/

    return function (assetGraph, cb) {
        // 4.1 default-src
        rules['default-src'].push('"none"');

        // 4.2 script-src
        assetGraph.findRelations({
            type: 'HtmlScript',
            to: {
                url: /^(?:https?:)\/\//
            }
        }, true).forEach(function (relation) {
            //console.warn(getDomain(relation.to.url));
            rules['script-src'].push(getDomain(relation.to.url));
        });

        // 4.3 object-src
        console.warn('TODO: object-src');

        // 4.4 style-src
        assetGraph.findRelations({
            type: 'HtmlStyle',
            to: {
                url: /^(?:https?:)\/\//
            }
        }, true).forEach(function (relation) {
            //console.warn(getDomain(relation.to.url));
            rules['style-src'].push(getDomain(relation.to.url));
        });

        // 4.5 img-src
        assetGraph.findRelations({
            type: ['HtmlImage', 'CssImage', 'CssAlphaImageLoader', 'HtmlImageSrcSet', 'HtmlShortcutIcon', 'SvgImage'],
            to: {
                url: /^(?:https?:)\/\//
            }
        }, true).forEach(function (relation) {
            //console.warn(getDomain(relation.to.url));
            rules['img-src'].push(getDomain(relation.to.url));
        });

        // 4.6 media-src
        console.warn('TODO: media-src');

        // 4.7 frame-src
        assetGraph.findRelations({
            type: ['HtmlFrame', 'HtmlIFrame'],
            to: {
                url: /^(?:https?:)\/\//
            }
        }, true).forEach(function (relation) {
            //console.warn(getDomain(relation.to.url));
            rules['frame-src'].push(getDomain(relation.to.url));
        });

        // 4.8 font-src
        console.warn('TODO: font-src');

        // 4.9 connect-src
        console.warn('TODO: connect-src');

        // 4.10 sandbox (Optional)
        console.warn('TODO: sandbox');

        // 4.11 report-uri
        console.warn('TODO: report-uri');


        // FIXME: return this to a callback at some point
        console.log(headerName + ': ' + Object.keys(rules).map(function (key) {
                if (rules[key].length === 0) {
                    return '';
                }

                return key + ' ' + uniq(rules[key]).join(' ');
            }).filter(function (value) {
                return value;
            }).join('; '));

        cb();
    };
};