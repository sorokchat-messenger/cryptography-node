import type { IHashing } from "@sorokchat-messenger/cryptography-abstractions";
import { createHash } from "node:crypto";

export class Sha256Hashing implements IHashing {
  public async hash(plaintext: string): Promise<string> {
    return createHash("sha256")
      .update(Buffer.from(plaintext, "utf-8"))
      .digest("hex");
  }
}
