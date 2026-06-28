const CryptoLd = require('crypto-ld');
const forge = require('node-forge');
const { util: { binary: { base58 } } } = forge;
const { Writer: N3Writer } = require('n3');
const N3WriterWrapper = require('n3writer-wrapper');

module.exports = {
  Ed25519KeyPair: CryptoLd.Ed25519KeyPair,
  forge: forge,
  jsonld: require('jsonld'),
  util: require('jsonld-signatures/lib/util.js'),
  graphy: require('graphy'),
  Buffer: require('buffer').Buffer,
  jsYaml: require('js-yaml'),
  base58: base58,
  N3Writer,
  N3WriterWrapper,
}
