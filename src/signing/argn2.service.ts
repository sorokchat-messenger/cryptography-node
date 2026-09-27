import type { ISigning } from "@sorokchat-messenger/cryptography-abstractions";
import { argon2id, hash, verify } from "argon2";

export class Argon2Signing implements ISigning {
    public async sign(plaintext: string, secret: string): Promise<string> {
        const payload = `${plaintext}:${secret}`;

        return await hash(payload, {
            type: argon2id,
            salt: Buffer.from(secret, "utf-8"),
            memoryCost: 64 * 1024,
            timeCost: 3,
            parallelism: 1,
            hashLength: 32,
        });
    }

    public async verify(
        plaintext: string,
        signing: string,
        secret: string,
    ): Promise<boolean> {
        const payload = `${plaintext}:${secret}`;

        try {
            return await verify(signing, payload);
        } catch {
            return false;
        }
    }
}