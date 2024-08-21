// eslint-disable-next-line @typescript-eslint/no-explicit-any
const browserCrypto = globalThis.crypto || (globalThis as any).msCrypto || {};

export function randomBytes(size: number): Buffer {
  const arr = new Uint8Array(size);

  browserCrypto.getRandomValues(arr);

  return Buffer.from(arr);
}
