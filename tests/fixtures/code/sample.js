const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const forge = require("node-forge");

const { publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
crypto.generateKeyPair("ec", { namedCurve: "P-384" }, () => {});
const h = crypto.createHash("md5");
const mac = crypto.createHmac("sha1", "key");
const c = crypto.createCipheriv("aes-128-ecb", key, null);
const d = crypto.createCipheriv("aes-256-gcm", key, iv);
const ecdh = crypto.createECDH("prime256v1");
jwt.sign(payload, secret, { algorithm: "RS256" });
const keys = forge.pki.rsa.generateKeyPair({ bits: 1024 });
// crypto.createHash("sha1") in a comment
const server = tls.createServer({ minVersion: "TLSv1" });
