'use strict';
// const { jhash } = require('bindings')('j-hash-node');
// module.exports = {
//     jhash(value) {
//         if (typeof value === 'string') {
//             value = Buffer.from(value, 'utf8');
//         }
//         return jhash(value).toString();
//     }
// }
module.exports = require('bindings')('j-hash-node');
