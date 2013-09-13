// CSP documentation: http://www.w3.org/TR/CSP/

module.exports = function (config) {
    config = config || {};

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

    if (config.report) {
        headerName += '-Report-Only';
    }


    return function (asstGraph, cb) {
        // 4.1 default-src
        rules['default-src'].push('"none"');
        // 4.2 script-src
        // 4.3 object-src
        // 4.4 style-src
        // 4.5 img-src
        // 4.6 media-src
        // 4.7 frame-src
        // 4.8 font-src
        // 4.9 connect-src
        // 4.10 sandbox (Optional)
        // 4.11 report-uri

        console.log(headerName + ': ' + Object.keys(rules).map(function (key) {
                if (rules[key].length === 0) {
                    return '';
                }

                return key + ' ' + rules[key].join(' ');
            }).filter(function (value) {
                return value;
            }).join(' '));

        cb();
    };
};
