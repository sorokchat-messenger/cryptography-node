import type { IEncryption } from "@sorokchat-messenger/cryptography-abstractions";
import { beforeAll, describe, expect, it } from "vitest";
import { AesEncryption, type AesOptions } from "./aes.service.js";

describe("AES tests", () => {
  let encryption: IEncryption<AesOptions>;
  const iv: string = "3ff3321fdcbffffaabb123456785421";
  const key: string = "54125747abf43213212d4432e3dfacb";
  const plaintext: string = "Hello, world";
  const ciphertext: string = "46563a2ee9e4ae7d433735f2f1f5b861";
  const options: AesOptions = { iv };
  beforeAll(() => {
    encryption = new AesEncryption();
  });

  it("Aes must be defined", () => {
    expect(encryption).toBeDefined();
  });

  it("should correct encrypt", async () => {
    const result = await encryption.encrypt(plaintext, key, options);
    expect(result).toEqual(ciphertext);
  });

  it("should correct decrypt", async () => {
    const result = await encryption.decrypt(ciphertext, key, options);
    expect(result).toEqual(plaintext);
  });
});
