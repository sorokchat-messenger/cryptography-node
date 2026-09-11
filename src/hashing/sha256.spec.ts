import type { IHashing } from "@sorokchat-messenger/cryptography-abstractions";
import { beforeAll, describe, expect, it } from "vitest";
import { Sha256Hashing } from "./sha256.service.js";

describe("SHA-256 tests", () => {
  let hashing: IHashing;
  beforeAll(() => {
    hashing = new Sha256Hashing();
  });

  it("should be defined", () => {
    expect(hashing).toBeDefined();
  });

  it("should return correct hash", async () => {
    const plaintext: string = "hello";
    const result: string = await hashing.hash(plaintext);
    const expected: string =
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    expect(result).toEqual(expected);
  });
});
