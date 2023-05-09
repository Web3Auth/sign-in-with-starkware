import nodeCrypto from "crypto";

const browserCrypto = global.crypto || global.msCrypto || {};

export function randomBytes(size: number): Buffer {
  const arr = new Uint8Array(size);
  if (typeof browserCrypto.getRandomValues === "undefined") {
    return Buffer.from(nodeCrypto.randomBytes(size));
  }
  browserCrypto.getRandomValues(arr);

  return Buffer.from(arr);
}
