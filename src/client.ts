import type { StarknetWindowObject } from "get-starknet";
import { ec, hash, typedData } from "starknet";
import * as uri from "valid-url";

import { ParsedMessage } from "./regex";
import { ErrorTypes, Header, Payload, Signature, SignInWithStarkwareError, SignInWithStarkwareResponse, VerifyParams } from "./types";
import { randomBytes } from "./util";

export class SIWStarkware {
  header: Header;

  payload: Payload;

  signature: Signature;

  /**
   * Creates a parsed Sign-In with Starkware Message object from a
   * string or an object. If a string is used an parser is called to
   * validate the parameter, otherwise the fields are attributed.
   * @param param {string | SIWStarkware} Sign message as a string or an object.
   */
  constructor(param: string | Partial<SIWStarkware>) {
    if (typeof param === "string") {
      const parsedMessage = new ParsedMessage(param);
      this.payload = {
        domain: parsedMessage.domain,
        address: parsedMessage.address,
        statement: parsedMessage.statement,
        uri: parsedMessage.uri,
        version: parsedMessage.version,
        nonce: parsedMessage.nonce,
        issuedAt: parsedMessage.issuedAt,
        expirationTime: parsedMessage.expirationTime,
        notBefore: parsedMessage.notBefore,
        requestId: parsedMessage.requestId,
        chainId: parsedMessage.chainId,
        resources: parsedMessage.resources,
      };
    } else {
      Object.assign(this, param);
      if (typeof this.payload.chainId === "string") {
        this.payload.chainId = parseInt(this.payload.chainId);
      }
      if (!this.payload.nonce) {
        this.payload.nonce = randomBytes(8).toString("hex");
      }
      if (!this.payload.issuedAt) {
        this.payload.issuedAt = new Date().toISOString();
      }
    }
  }

  /**
   * This function can be used to retrieve a formated message for
   * signature, although you can call it directly it's advised to use
   * [prepareMessage()] instead which will resolve to the correct method based
   * on the [type] attribute of this object, in case of other formats being
   * implemented.
   * @returns {string} message
   */
  toMessage(): string {
    /** Validates all fields of the object */

    this.validate();

    const header = `${this.payload.domain} wants you to sign in with your Starkware account:`;
    const uriField = `URI: ${this.payload.uri}`;
    let prefix = [header, this.payload.address].join("\n");
    const versionField = `Version: ${this.payload.version}`;
    const chainField = `Chain ID: ${this.payload.chainId || 1}`;
    const nonceField = `Nonce: ${this.payload.nonce}`;
    const suffixArray = [uriField, versionField, chainField, nonceField];
    if (this.payload.issuedAt) {
      Date.parse(this.payload.issuedAt);
    } else {
      this.payload.issuedAt = this.payload.issuedAt ? this.payload.issuedAt : new Date().toISOString();
    }
    suffixArray.push(`Issued At: ${this.payload.issuedAt}`);

    if (this.payload.expirationTime) {
      const expiryField = `Expiration Time: ${this.payload.expirationTime}`;
      suffixArray.push(expiryField);
    }

    if (this.payload.notBefore) {
      suffixArray.push(`Not Before: ${this.payload.notBefore}`);
    }

    if (this.payload.requestId) {
      suffixArray.push(`Request ID: ${this.payload.requestId}`);
    }

    if (this.payload.resources) {
      suffixArray.push([`Resources:`, ...this.payload.resources.map((x) => `- ${x}`)].join("\n"));
    }

    const suffix = suffixArray.join("\n");
    prefix = [prefix, this.payload.statement].join("\n\n");
    if (this.payload.statement) {
      prefix += "\n";
    }
    return [prefix, suffix].join("\n");
  }

  /**
   * This method parses all the fields in the object and creates a sign
   * message according with the type defined.
   * @returns {string} Returns a message ready to be signed according with the
   * type defined in the object.
   */
  prepareMessage(): string {
    let message: string;
    switch (this.payload.version) {
      case "1": {
        message = this.toMessage();
        break;
      }

      default: {
        message = this.toMessage();
        break;
      }
    }
    return message;
  }

  /**
   * Validates the value of this object fields.
   * @throws Throws an {ErrorType} if a field is invalid.
   */
  validate() {
    /** `domain` check. */
    if (this.payload.domain.length === 0 || !/[^#?]*/.test(this.payload.domain)) {
      throw new SignInWithStarkwareError(ErrorTypes.INVALID_DOMAIN, `${this.payload.domain} to be a valid domain.`);
    }

    /** Check if the URI is valid. */
    if (!uri.isUri(this.payload.uri)) {
      throw new SignInWithStarkwareError(ErrorTypes.INVALID_URI, `${this.payload.uri} to be a valid uri.`);
    }

    /** Check if the version is 1. */
    if (this.payload.version !== "1") {
      throw new SignInWithStarkwareError(ErrorTypes.INVALID_MESSAGE_VERSION, "1", this.payload.version);
    }

    /** Check if the nonce is alphanumeric and bigger then 8 characters */
    const nonce = this.payload.nonce.match(/[a-zA-Z0-9]{8,}/);
    if (!nonce || this.payload.nonce.length < 8 || nonce[0] !== this.payload.nonce) {
      throw new SignInWithStarkwareError(ErrorTypes.INVALID_NONCE, `Length > 8 (${nonce.length}). Alphanumeric.`, this.payload.nonce);
    }

    const ISO8601 =
      /([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))/;
    /** `issuedAt` conforms to ISO-8601 */
    if (this.payload.issuedAt) {
      if (!ISO8601.test(this.payload.issuedAt)) {
        throw new Error(ErrorTypes.INVALID_TIME_FORMAT);
      }
    }

    /** `expirationTime` conforms to ISO-8601 */
    if (this.payload.expirationTime) {
      if (!ISO8601.test(this.payload.expirationTime)) {
        throw new Error(ErrorTypes.INVALID_TIME_FORMAT);
      }
    }

    /** `notBefore` conforms to ISO-8601 */
    if (this.payload.notBefore) {
      if (!ISO8601.test(this.payload.notBefore)) {
        throw new Error(ErrorTypes.INVALID_TIME_FORMAT);
      }
    }
  }

  /**
   * Validates the integrity of the object by matching it's signature.
   * @param params Parameters to verify the integrity of the message, signature is required.
   * @returns {Promise<SignInWithStarkwareResponse>} This object if valid.
   */
  verify(params: VerifyParams): Promise<SignInWithStarkwareResponse> {
    return new Promise<SignInWithStarkwareResponse>((resolve, reject) => {
      const { payload, network, signature } = params;

      /** Domain binding */
      if (payload.domain && payload.domain !== this.payload.domain) {
        resolve({
          success: false,
          data: this,
          error: new SignInWithStarkwareError(ErrorTypes.DOMAIN_MISMATCH, payload.domain, this.payload.domain),
        });
      }

      /** Nonce binding */
      if (payload.nonce && payload.nonce !== this.payload.nonce) {
        resolve({
          success: false,
          data: this,
          error: new SignInWithStarkwareError(ErrorTypes.NONCE_MISMATCH, payload.nonce, this.payload.nonce),
        });
      }

      /** Check time */
      const checkTime = new Date();

      /** Expiry Checks */
      if (this.payload.expirationTime) {
        const expirationDate = new Date(this.payload.expirationTime);

        // Check if the message hasn't expired
        if (checkTime.getTime() >= expirationDate.getTime()) {
          resolve({
            success: false,
            data: this,
            error: new SignInWithStarkwareError(
              ErrorTypes.EXPIRED_MESSAGE,
              `${checkTime.toISOString()} < ${expirationDate.toISOString()}`,
              `${checkTime.toISOString()} >= ${expirationDate.toISOString()}`
            ),
          });
        }
      }

      /** Message is valid already */
      if (this.payload.notBefore) {
        const notBefore = new Date(this.payload.notBefore);
        if (checkTime.getTime() < notBefore.getTime()) {
          resolve({
            success: false,
            data: this,
            error: new SignInWithStarkwareError(
              ErrorTypes.EXPIRED_MESSAGE,
              `${checkTime.toISOString()} >= ${notBefore.toISOString()}`,
              `${checkTime.toISOString()} < ${notBefore.toISOString()}`
            ),
          });
        }
      }

      const message = hash.starknetKeccak(this.prepareMessage()).toString("hex").substring(0, 31);
      const typedMessage = {
        domain: {
          name: "Example DApp",
          chainId: network === "mainnet-alpha" ? "SN_MAIN" : "SN_GOERLI",
          version: "0.0.1",
        },
        types: {
          StarkNetDomain: [
            { name: "name", type: "felt" },
            { name: "chainId", type: "felt" },
            { name: "version", type: "felt" },
          ],
          Message: [{ name: "message", type: "felt" }],
        },
        primaryType: "Message",
        message: {
          message,
        },
      };

      const starknetObject = params.kp as StarknetWindowObject;
      if (starknetObject.account !== undefined) {
        starknetObject.account
          .verifyMessage(typedMessage, signature.s)
          .then((valid) => {
            if (!valid)
              return reject({
                success: false,
                data: this,
                error: new SignInWithStarkwareError(ErrorTypes.INVALID_SIGNATURE, "Signature verfication failed"),
              });
            return resolve({
              success: true,
              data: this,
            });
          })
          .catch(() => {
            return resolve({
              success: false,
              data: this,
              error: new SignInWithStarkwareError(
                ErrorTypes.INVALID_SIGNATURE,
                "Signature verfication failed. Check if you have an account created."
              ),
            });
          });
      } else {
        const valid = ec.verify(params.kp, typedData.getMessageHash(typedMessage, payload.address), signature.s);
        if (!valid) {
          resolve({
            success: false,
            data: this,
            error: new SignInWithStarkwareError(ErrorTypes.INVALID_SIGNATURE, "Signature verfication failed"),
          });
        } else {
          resolve({
            success: true,
            data: this,
          });
        }
      }
    });
  }
}
