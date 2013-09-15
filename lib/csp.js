// CSP documentation: http://www.w3.org/TR/CSP/

/*
    TODO:
        - XSLT restraints in script-src
        - HtmlTrack restraint in media-src
        - HtmlSource restraint in media-src
*/

var url = require('url'),
    colors = require('colors');

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

    if (config.debug) {
        headerName += '-Report-Only';
    }

    return function (assetGraph, cb) {
        // 4.1 default-src
        rules['default-src'].push('"self"');

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

        var inlineScript = assetGraph.findRelations({
            type: 'HtmlInlineEventHandler'
        }, true);

        if (inlineScript.length) {
            if (config['script-unsafe-inline']) {
                rules['script-src'].push('"unsafe-inline"');
            } else {
                console.warn(' ! Warning: You are using inline style sheets and haven\'t set "unsafe-inline"'.yellow);
                console.warn(('Files in violation:\n\t' + inlineScript.map(function (relation) {
                    return relation.from.url;
                }).join('\n\t')));
            }
        }

        // 4.3 object-src
        assetGraph.findRelations({
            type: ['HtmlApplet', 'HtmlEmbed', 'HtmlObject'],
            to: {
                url: /^(?:https?:)\/\//
            }
        }, true).forEach(function (relation) {
            //console.warn(getDomain(relation.to.url));
            rules['object-src'].push(getDomain(relation.to.url));
        });

        // 4.4 style-src
        assetGraph.findRelations({
            type: ['HtmlStyle', 'CssImport'],
            to: {
                url: /^(?:https?:)\/\//
            }
        }, true).forEach(function (relation) {
            //console.warn(getDomain(relation.to.url));
            rules['style-src'].push(getDomain(relation.to.url));
        });

        var styleAttributes = assetGraph.findRelations({
            type: 'HtmlStyleAttribute'
        }, true);

        if (styleAttributes.length) {
            if (config['style-unsafe-inline']) {
                rules['style-src'].push('"unsafe-inline"');
            } else {
                console.warn(' ! Warning: You are using style attributes and haven\'t set "unsafe-inline"'.yellow);
                console.warn(('Files in violation:\n\t' + styleAttributes.map(function (relation) {
                    return relation.from.url;
                }).join('\n\t')));
            }
        }

        var inlineStyles = assetGraph.findRelations({
            type: 'HtmlStyle',
            to: {
                isInline: true
            }
        }, true);

        if (inlineStyles.length) {
            if (config['style-unsafe-inline']) {
                rules['style-src'].push('"unsafe-inline"');
            } else {
                console.warn(' ! Warning: You are using inline style sheets and haven\'t set "unsafe-inline"'.yellow);
                console.warn(('Files in violation:\n\t' + inlineStyles.map(function (relation) {
                    return relation.from.url;
                }).join('\n\t')));
            }
        }

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
        assetGraph.findRelations({
            type: ['HtmlAudio', 'HtmlVideo'],
            to: {
                url: /^(?:https?:)\/\//
            }
        }, true).forEach(function (relation) {
            //console.warn(getDomain(relation.to.url));
            rules['media-src'].push(getDomain(relation.to.url));
        });

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
        assetGraph.findRelations({
            type: ['CssFontFaceSrc', 'SvgFontFaceUri'],
            to: {
                url: /^(?:https?:)\/\//
            }
        }, true).forEach(function (relation) {
            //console.warn(getDomain(relation.to.url));
            rules['font-src'].push(getDomain(relation.to.url));
        });

        // 4.9 connect-src
        console.warn('TODO: connect-src');

        // 4.10 sandbox (Optional)
        console.warn('TODO: sandbox');

        // 4.11 report-uri
        if (config['report-uri']) {
            rules['report-uri'].push(config['report-uri']);
        }


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
