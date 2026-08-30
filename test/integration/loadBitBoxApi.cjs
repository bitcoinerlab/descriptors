// Keep this native import outside TypeScript's CommonJS output. bitbox-api is
// an ESM package and cannot be loaded with require().
module.exports = () => import('bitbox-api');
