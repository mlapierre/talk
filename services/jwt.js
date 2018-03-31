const jwt = require('jsonwebtoken');
const { merge, uniq, omitBy, isUndefined } = require('lodash');
const jwks = require('jwks-rsa');

const getKID = token => {
  let header = null;
  try {
    header = JSON.parse(Buffer(token.split('.')[0], 'base64').toString());
  } catch (err) {
    throw err;
  }

  if (!('kid' in header)) {
    throw new Error('expected kid to exist in the token header, it did not.');
  }

  return header.kid;
};

/**
 * MultiSecret will take many secrets and provide a unified interface for
 * handling verifying and signing.
 */
class MultiSecret {
  constructor(secrets) {
    this.kids = secrets.map(({ kid }) => kid);

    if (uniq(this.kids).length !== secrets.length) {
      throw new Error(
        "Duplicate kid's cannot be used to construct a MultiSecret"
      );
    }

    this.secrets = secrets;
  }

  getSupportedAlgs() {
    const algorithms = [];
    if (this.secrets.some(({ jwks }) => jwks)) {
      // TODO: investigate how to dynamically support different algorithm types.
      algorithms.push('RS256');
    }

    return algorithms;
  }

  getSigningKey(token, done) {
    const kid = getKID(token);

    let verifier = this.secrets.find(secret => secret.kid === kid);
    if (!verifier) {
      // We now know that none of the secrets have the correct kid, check to see
      // if there is a jwks secret.
      verifier = this.secrets.find(({ jwks }) => jwks);
      if (!verifier) {
        return done(new Error(`expected kid ${kid} was not available.`));
      }

      // This is a jwks verifier! Let's defer to that function.
      return verifier.getSigningKey(token, done);
    }

    return done(null, verifier.signingKey);
  }

  /**
   * Sign will sign with the first secret.
   */
  sign(payload, options) {
    return this.secrets[0].sign(
      omitBy(payload, isUndefined),
      omitBy(options, isUndefined)
    );
  }
}

/**
 * Secret wraps the capabilities expected of a Secret, signing and verifying.
 */
class Secret {
  constructor({ kid, signingKey, verifiyingKey, algorithm }) {
    this.kid = kid;
    this.signingKey = signingKey;
    this.verifiyingKey = verifiyingKey;
    this.algorithm = algorithm;
  }

  getSupportedAlgs() {
    return [];
  }

  getSigningKey(token, done) {
    return done(null, this.verifiyingKey);
  }

  /**
   * Sign will sign the payload with the secret.
   *
   * @param {Object} payload the object to sign
   * @param {Object} options the signing options
   */
  sign(payload, options) {
    if (!this.signingKey) {
      throw new Error('no signing key on secret, cannot sign');
    }

    return jwt.sign(
      payload,
      this.signingKey,
      omitBy(
        merge({}, options, {
          keyid: this.kid,
          algorithm: this.algorithm,
        }),
        isUndefined
      )
    );
  }
}

/**
 * SharedSecret is the HMAC based secret that's used for signing/verifying.
 */
function SharedSecret({ kid = undefined, secret = null }, algorithm) {
  if (secret === null || secret.length === 0) {
    throw new Error('Secret cannot have a zero length');
  }

  return new Secret({
    kid,
    signingKey: secret,
    verifiyingKey: secret,
    algorithm,
  });
}

/**
 * AsymmetricSecret is the Asymmetric based key, where a private key is optional
 * and the public key is required.
 */
function AsymmetricSecret(
  { kid = undefined, private: privateKey, public: publicKey },
  algorithm
) {
  publicKey = Buffer.from(publicKey.replace(/\\n/g, '\n'));
  privateKey =
    privateKey && privateKey.length > 0
      ? Buffer.from(privateKey.replace(/\\n/g, '\n'))
      : null;

  return new Secret({
    kid,
    signingKey: privateKey,
    verifiyingKey: publicKey,
    algorithm,
  });
}

/**
 * JWKSSecret is a secret source that permits verifying via a dynamic JWKS
 * endpoint.
 */
function JWKSSecret({ jwksUri }) {
  const client = jwks({
    cache: true,
    jwksUri,
  });

  return {
    jwks: true,
    getSigningKey(token, done) {
      const kid = getKID(token);
      client.getSigningKey(kid, (err, key) => {
        if (err) {
          return done(err);
        }

        // Get the public key from the jws key.
        const publicKey = (key.publicKey || key.rsaPublicKey).replace(
          /\\n/g,
          '\n'
        );

        // Extract the public key from the available key.
        const signingKey = Buffer.from(publicKey);

        return done(null, signingKey);
      });
    },
  };
}

module.exports = {
  AsymmetricSecret,
  SharedSecret,
  JWKSSecret,
  MultiSecret,
};
