/* eslint-disable mocha/max-top-level-suites */
/* eslint-disable mocha/no-setup-in-describe */
import assert from "assert";
import { ec, hash, stark, typedData } from "starknet";

import { ErrorTypes, Signature, SIWStarkware } from "../src/index";
import parsingPositive from "./parsing_positive.json";
import validationNegative from "./validation_negative.json";
import validationPositive from "./validation_positive.json";

describe(`Message Generation from payload`, function () {
  Object.entries(parsingPositive).forEach(([test, value]) => {
    it(`Generates message successfully: ${test}`, function () {
      const { payload } = value.fields;
      const msg = new SIWStarkware({ payload });
      assert.equal(msg.toMessage(), value.message);
    });
  });
});

describe(`Message Generation from message`, function () {
  Object.entries(parsingPositive).forEach(([test, value]) => {
    it(`Generates message successfully: ${test}`, function () {
      const msg = new SIWStarkware(value.message);
      assert.equal(msg.toMessage(), value.message);
    });
  });
});

describe(`Message Validation`, function () {
  Object.entries(validationPositive).forEach(([test, value]) => {
    it(`Validates message successfully: ${test}`, async function () {
      const { payload, signature } = value;
      const msg = new SIWStarkware({ payload });
      const starkKeyPair = ec.getKeyPair(payload.address);
      const verify = await msg.verify({ payload, signature, kp: starkKeyPair });
      assert.equal(verify.success, true);
    });
  });

  Object.entries(validationNegative).forEach(([test, value]) => {
    it(`Validates message failed: ${test}`, async function () {
      try {
        const { payload, signature } = value;
        const msg = new SIWStarkware({ payload });
        const starkKeyPair = ec.getKeyPair(payload.address);
        const error = await msg.verify({ payload, signature, kp: starkKeyPair });
        assert(Object.values(ErrorTypes).includes(error.error.type));
      } catch (error) {
        assert((Object.values(ErrorTypes) as string[]).includes((error as Error).message));
      }
    });
  });
});

describe(`Round Trip`, function () {
  const privateKey = stark.randomAddress();
  const starkKeyPair = ec.getKeyPair(privateKey);
  const fullPublicKey = ec.getStarkKey(starkKeyPair);
  Object.entries(parsingPositive).forEach(([test, el]) => {
    it(`Generates a Successfully Verifying message: ${test}`, async function () {
      const { payload } = el.fields;
      payload.address = fullPublicKey;
      const msg = new SIWStarkware({ payload });
      const signature = new Signature();
      const message = hash.starknetKeccak(msg.prepareMessage()).toString("hex").substring(0, 31);
      const typedMessage: typedData.TypedData = {
        domain: {
          name: "Example DApp",
          chainId: payload.chainId,
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
      signature.s = ec.sign(starkKeyPair, typedData.getMessageHash(typedMessage, payload.address));
      signature.t = "eip191";
      const success = await msg.verify({ signature, payload, kp: starkKeyPair });
      assert.ok(success);
    });
  });
});
