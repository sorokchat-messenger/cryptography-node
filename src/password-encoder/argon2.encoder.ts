import type { ISigning, PasswordEncoder } from "@sorokchat-messenger/cryptography-abstractions";
import { hash, verify, type HashOptions, argon2id } from "argon2";

const DEFAUILT_HASH_OPTIONS: HashOptions = {
    type: argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    hashLength: 32,
}

export class Argon2PasswordEncoder implements PasswordEncoder {
    private readonly pepper: string;
    private readonly options: HashOptions;
    private readonly signing: ISigning;

    public constructor(
        pepper: string,
        signing: ISigning,
        options: Partial<HashOptions> = {}
    ) {
        if (!pepper || pepper.length < 32) {
            throw new Error("Перець має бути на 32 байта ентропії");
        }
        this.pepper = pepper;
        this.options = { ...DEFAUILT_HASH_OPTIONS, ...options };
        this.signing = signing;
    }

    public async encode(plaintext: string): Promise<string> {
        const pepperedPassword: string = await this.applyPepper(plaintext);
        return await hash(pepperedPassword, this.options);
    }

    public async verify(plaintext: string, encodedPassword: string): Promise<boolean> {
        try {
            const pepperedPassword: string = await this.applyPepper(plaintext);
            return await verify(encodedPassword, pepperedPassword, this.options);
        } catch {
            return false;
        }
    }

    private async applyPepper(plaintext: string): Promise<string> {
        return await this.signing.sign(plaintext, this.pepper);
    }
}