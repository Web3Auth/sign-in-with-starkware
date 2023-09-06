import nodeCrypto from "crypto";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const browserCrypto = global.crypto || (global as any).msCrypto || {};

export function randomBytes(size: number): Buffer {
  const arr = new Uint8Array(size);
  if (typeof browserCrypto.getRandomValues === "undefined") {
    return Buffer.from(nodeCrypto.randomBytes(size));
  }
  browserCrypto.getRandomValues(arr);

  return Buffer.from(arr);
}
