import type { IEncryption } from "@sorokchat-messenger/cryptography-abstractions";
import { createCipheriv, createDecipheriv } from "node:crypto";

export type AesOptions = {
  iv: string;
};

export class AesEncryption implements IEncryption<AesOptions> {
  private static readonly ALGORITHM: string = "aes-128-cbc";

  public async encrypt(
    plaintext: string,
    key: string,
    options: AesOptions,
  ): Promise<string> {
    const keyBuffer = this.padParameter(key);
    const ivBuffer = this.padParameter(options.iv);
    const cipher = createCipheriv(AesEncryption.ALGORITHM, keyBuffer, ivBuffer);
    return cipher.update(plaintext, "utf-8", "hex") + cipher.final("hex");
  }

  public async decrypt(
    ciphertext: string,
    key: string,
    options: AesOptions,
  ): Promise<string> {
    const keyBuffer = this.padParameter(key);
    const ivBuffer = this.padParameter(options.iv);
    const decipher = createDecipheriv(
      AesEncryption.ALGORITHM,
      keyBuffer,
      ivBuffer,
    );
    return (
      decipher.update(ciphertext, "hex", "utf-8") + decipher.final("utf-8")
    );
  }

  private padParameter(hex: string): Buffer {
    const padded = hex.padEnd(32, "0").substring(0, 32);
    return Buffer.from(padded, "hex");
  }
}
