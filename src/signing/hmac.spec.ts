import type { ISigning } from "@sorokchat-messenger/cryptography-abstractions";
import { beforeAll, describe, expect, it } from "vitest";
import { HmacSigning } from "./hmac.service.js";

describe("HMAC tests", () => {
  let signing: ISigning;
  const plaintext: string = "Hello, world";
  const secret: string = "secret key";
  const expectedSigning: string =
    "81e2384ce666bc4061ce89bc948636dc1ccd96d2e689533a604c506fce614629";
  beforeAll(() => {
    signing = new HmacSigning();
  });
  it("should successfully sign plaintext", async () => {
    const result = await signing.sign(plaintext, secret);
    expect(result).toBe(expectedSigning);
  });

  it("should successfully verify valid signature", async () => {
    const isValid = await signing.verify(plaintext, expectedSigning, secret);
    expect(isValid).toBeTruthy();
  });

  it("should fail verification if plaintext was modified", async () => {
    const modifiedPlaintext = "Hello, world!";
    const isValid = await signing.verify(
      modifiedPlaintext,
      expectedSigning,
      secret,
    );
    expect(isValid).toBeFalsy();
  });

  it("should fail verification if secret is incorrect", async () => {
    const wrongSecret = "wrong key";
    const isValid = await signing.verify(
      plaintext,
      expectedSigning,
      wrongSecret,
    );
    expect(isValid).toBeFalsy();
  });

  it("should fail verification if signature is corrupted", async () => {
    const corruptedSigning = expectedSigning.replace("81e2", "0000");
    const isValid = await signing.verify(plaintext, corruptedSigning, secret);
    expect(isValid).toBeFalsy();
  });

  it("should fail verification if length of signature length and plaintext length not equal", async () => {
    const corruptedSigning = expectedSigning.replace("81e2", "00");
    const isValid = await signing.verify(plaintext, corruptedSigning, secret);
    expect(isValid).toBeFalsy();
  });
});
