/* eslint-disable mocha/max-top-level-suites */
/* eslint-disable mocha/no-setup-in-describe */
import assert from "assert";
import { ec } from "starknet";

import { SIWStarkware } from "../src/index";
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
      const { payload } = value;
      const { signature } = value;
      const msg = new SIWStarkware({ payload });
      const starkKeyPair = ec.getKeyPair(payload.address);
      const verify = await msg.verify({ payload, signature, kp: starkKeyPair });
      assert.equal(verify.success, true);
    });
  });

  Object.entries(validationNegative).forEach(([test, value]) => {
    it(`Validates message failed: ${test}`, async function () {
      try {
        const { payload } = value;
        const { signature } = value;
        const msg = new SIWStarkware({ payload });
        const starkKeyPair = ec.getKeyPair(payload.address);
        await msg.verify({ payload, signature, kp: starkKeyPair });
      } catch (error) {
        expect(Object.values(SIWStarkware).includes(error));
      }
    });
  });
});
