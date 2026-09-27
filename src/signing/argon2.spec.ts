import type { ISigning } from "@sorokchat-messenger/cryptography-abstractions";
import { beforeAll, describe, expect, it } from "vitest";
import { Argon2Signing } from "./argn2.service.js";

describe("Argon2 tests", () => {
    let signing: ISigning;
    const plaintext: string = "Hello, world";
    const secret: string = "secret key";
    const expectedSigning: string =
        "$argon2id$v=19$m=65536,p=1,t=3$c2VjcmV0IGtleQ$0Ne4hbhcw74mgndGEruoqvRgXzvy9de1IMQfkDJub5w";
    beforeAll(() => {
        signing = new Argon2Signing()
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
        const isValid = await signing.verify(plaintext, "test", secret);
        expect(isValid).toBeFalsy();
    });
});
