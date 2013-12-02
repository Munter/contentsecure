// CSP documentation: http://www.w3.org/TR/CSP/

var url = require('url'),
    _ = require('underscore'),
    colors = require('colors');

function getDomain(str) {
    var parsed = url.parse(str);
    if (!parsed.host && str.indexOf('//') === 0) {
        parsed = {
            protocol: '',
            host: str.replace('//', '').split('/').shift()
        };
    }
    return (parsed.protocol || '') + '//' + parsed.host;
}

function uniq(array) {
    return array.reduce(function (prev, current) {
        if (prev.indexOf(current) === -1) {
            return prev.concat(current);
        }

        return prev;
    }, []);
}

function stringify(header, rules) {
    return header + ': ' + Object.keys(rules).map(function (key) {
            if (rules[key].length === 0 || key === 'pageUrl') {
                return '';
            }

            return key + ' ' + uniq(rules[key]).join(' ');
        }).filter(function (value) {
            return value;
        }).join('; ');
}

function isExternal(relation) {
    return (/^(?:https?:)?\/\//).test(relation.to.url);
}

module.exports = function (config) {
    var headerName = 'Content-Security-Policy',
        allRules = [],
        siteWide,
        warnings = {
            inlineScript: [],
            inlineScriptAttribute: [],
            inlineStyle: [],
            inlineStyleAttribute: []
        },
        ruleTpl = {
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
        var query = assetGraph.query,
            traverse = function (startAsset, lambda) {
                var seen = {},
                    trav = function (startAsset) {
                        assetGraph.findRelations({
                            from: startAsset,
                            type: query.not('HtmlAnchor')
                        }, true).forEach(function (relation) {
                            lambda(relation);
                            if (!seen[relation.to.id]) {
                                seen[relation.to.id] = true;
                                trav(relation.to);
                            }
                        });
                    };

                trav(startAsset);
            };


        assetGraph.findAssets({
            type: 'Html'
        }).forEach(function (htmlAsset) {
            var rules = _.clone(ruleTpl);

            rules.pageUrl = htmlAsset.url;

            // 4.11 report-uri
            if (config['report-uri']) {
                rules['report-uri'].push(config['report-uri']);
            }

            // 4.1 default-src
            rules['default-src'].push('"self"');

            traverse(htmlAsset, function (relation) {
                var type = relation.type;

                if (isExternal(relation)) {
                    // 4.2 script-src
                    if (type === 'HtmlScript') {
                        rules['script-src'].push(getDomain(relation.href));
                    }

                    // 4.3 object-src
                    if (['HtmlApplet', 'HtmlEmbed', 'HtmlObject'].indexOf(type) !== -1) {
                        rules['object-src'].push(getDomain(relation.to.url));
                    }

                    // 4.4 style-src
                    if (['HtmlStyle', 'CssImport'].indexOf(type) !== -1) {
                        rules['style-src'].push(getDomain(relation.to.url));
                    }

                    // 4.5 img-src
                    if (['HtmlImage', 'CssImage', 'CssAlphaImageLoader', 'HtmlImageSrcSet', 'HtmlShortcutIcon', 'SvgImage'].indexOf(type)) {
                        rules['img-src'].push(getDomain(relation.to.url));
                    }

                    // 4.6 media-src
                    if (['HtmlAudio', 'HtmlVideo'].indexOf(type)) {
                        rules['media-src'].push(getDomain(relation.to.url));
                    }

                    // 4.7 frame-src
                    if (['HtmlFrame', 'HtmlIFrame'].indexOf(type)) {
                        rules['frame-src'].push(getDomain(relation.to.url));
                    }

                    // 4.8 font-src
                    if (['CssFontFaceSrc', 'SvgFontFaceUri'].indexOf(type)) {
                        rules['font-src'].push(getDomain(relation.to.url));
                    }

                    // 4.9 connect-src
                    //console.warn('TODO: connect-src');

                    // 4.10 sandbox (Optional)
                    //console.warn('TODO: sandbox');
                } else { // Non-externals

                    // 4.2 script-src
                    if (type === 'HtmlScript' && relation.to.isInline) {
                        if (config['script-unsafe-inline']) {
                            rules['script-src'].push('"unsafe-inline"');
                        } else {
                            warnings.inlineScript.push(relation);
                        }
                    }

                    if (type === 'HtmlInlineEventHandler') {
                        if (config['script-unsafe-inline']) {
                            rules['script-src'].push('"unsafe-inline"');
                        } else {
                            warnings.inlineScriptAttribute.push(relation);
                        }
                    }

                    // 4.4 style-src
                    if (type === 'HtmlStyle' && relation.to.isInline) {
                        if (config['style-unsafe-inline']) {
                            rules['style-src'].push('"unsafe-inline"');
                        } else {
                            warnings.inlineStyle.push(relation);
                        }
                    }

                    if (type === 'HtmlStyleAttribute') {
                        if (config['style-unsafe-inline']) {
                            rules['style-src'].push('"unsafe-inline"');
                        } else {
                            warnings.inlineStyleAttribute.push(relation);
                        }
                    }
                }
            });

            allRules.push(rules);
        });

        // Warnings
        if (warnings.inlineScript.length) {
            console.warn('\n ! Warning: You are using inline JavaScript and haven\'t set "unsafe-inline"'.yellow);
            console.warn((' - ' + warnings.inlineScript.map(function (relation) {
                return relation.from.url;
            }).join('\n - ')).yellow);
        }

        if (warnings.inlineScript.length) {
            console.warn('\n ! Warning: You are using inline event handlers and haven\'t set "unsafe-inline"'.yellow);
            console.warn((' - ' + warnings.inlineScript.map(function (relation) {
                return relation.from.url;
            }).join('\n - ')).yellow);
        }

        if (warnings.inlineStyle.length) {
            console.warn('\n ! Warning: You are using inline style sheets and haven\'t set "unsafe-inline"'.yellow);
            console.warn((' - ' + warnings.inlineStyle.map(function (relation) {
                return relation.from.url;
            }).join('\n - ')).yellow);
        }

        if (warnings.inlineStyleAttribute.length) {
            console.warn('\n ! Warning: You are using inline style attributes and haven\'t set "unsafe-inline"'.yellow);
            console.warn((' - ' + warnings.inlineStyleAttribute.map(function (relation) {
                return relation.from.url;
            }).join('\n - ')).yellow);
        }

        // Per page content security rules
        allRules.forEach(function (rules) {
            console.log('\n' + (rules.pageUrl + ' --> ').green + stringify(headerName, rules));
        });

        // Site wide content security rules
        siteWide = _.clone(ruleTpl);

        Object.keys(siteWide).forEach(function (key) {
            siteWide[key] = allRules.reduce(function (prev, current) {
                return prev.concat(current[key]);
            }, []);
        });


        console.log('\nSite --> '.green + stringify(headerName, siteWide));

        cb();
    };
};
