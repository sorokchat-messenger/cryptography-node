import type { ISigning } from "@sorokchat-messenger/cryptography-abstractions";
import { createHmac, timingSafeEqual } from "node:crypto";

export class HmacSigning implements ISigning {
  public async sign(plaintext: string, secret: string): Promise<string> {
    const secretBuffer = Buffer.from(secret, "utf-8");
    const hmac = createHmac("sha256", secretBuffer);
    hmac.update(plaintext, "utf-8");
    return hmac.digest("hex");
  }

  public async verify(
    plaintext: string,
    signing: string,
    secret: string,
  ): Promise<boolean> {
    const actualSigning = await this.sign(plaintext, secret);
    const actualBuffer = Buffer.from(actualSigning, "hex");
    const expectedBuffer = Buffer.from(signing, "hex");
    if (actualBuffer.length !== expectedBuffer.length) return false;
    return timingSafeEqual(actualBuffer, expectedBuffer);
  }
}
