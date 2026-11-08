import { describe, expect, it } from "vitest"
import { base64urlToArrayBuffer } from "./base64"
import { keyFromExportKey } from "./keys"
import { KEY_STRETCHING, identifiers, loadOpaque, normalizeUsername, passwordInput } from "./opaque"

describe("passwordInput", () => {
    // changing what OPAQUE is given as the password means every account has to register again
    it("is the username and the password in a fixed encoding", () => {
        expect(passwordInput("alice", "correct horse")).toBe(`["electronic-voting/opaque/v1","alice","correct horse"]`)
        expect(passwordInput("a\"b", "p\\w")).toBe(String.raw`["electronic-voting/opaque/v1","a\"b","p\\w"]`)
    })

    it("NFC normalizes the password", () => {
        expect(passwordInput("alice", "café")).toBe(passwordInput("alice", "café"))
        expect(passwordInput("alice", "café")).toContain("café")
    })
})

describe("normalizeUsername", () => {
    it("trims whitespace, which the API rejects", () => {
        expect(normalizeUsername("  alice\t\n")).toBe("alice")
        expect(normalizeUsername("al ice")).toBe("al ice")
    })
})

describe("base64urlToArrayBuffer", () => {
    it("decodes unpadded base64url", () => {
        expect(Array.from(new Uint8Array(base64urlToArrayBuffer("")))).toEqual([])
        expect(Array.from(new Uint8Array(base64urlToArrayBuffer("-_8")))).toEqual([0xfb, 0xff])
        expect(Array.from(new Uint8Array(base64urlToArrayBuffer("-w")))).toEqual([0xfb])
        expect(Array.from(new Uint8Array(base64urlToArrayBuffer("AAEC")))).toEqual([0, 1, 2])
    })
})

// register and logIn run the client's side the way authservice does, against the library's own
// server, which the API's (bytemare/opaque) was checked against before it was used
async function register(server_setup : string, username : string, password : string) {
    const opaque = await loadOpaque()
    const input = passwordInput(username, password)
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password: input })
    const { registrationResponse } = opaque.server.createRegistrationResponse({ serverSetup: server_setup, userIdentifier: username, registrationRequest })
    return opaque.client.finishRegistration({ clientRegistrationState, registrationResponse, password: input, keyStretching: KEY_STRETCHING, identifiers: identifiers(username) })
}

async function logIn(server_setup : string, username : string, password : string, registration_record : string) {
    const opaque = await loadOpaque()
    const input = passwordInput(username, password)
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password: input })
    const { loginResponse } = opaque.server.startLogin({ serverSetup: server_setup, userIdentifier: username, registrationRecord: registration_record, startLoginRequest, identifiers: identifiers(username) })
    return opaque.client.finishLogin({ clientLoginState, loginResponse, password: input, keyStretching: KEY_STRETCHING, identifiers: identifiers(username) })
}

describe("OPAQUE", () => {
    it("gives the same export key at registration and login", async () => {
        const server_setup = (await loadOpaque()).server.createSetup()
        const registration = await register(server_setup, "alice", "correct horse battery staple")

        const login = await logIn(server_setup, "alice", "correct horse battery staple", registration.registrationRecord)
        expect(login?.exportKey).toBe(registration.exportKey)
    })

    it("logs in with the password typed in another normalization form", async () => {
        const server_setup = (await loadOpaque()).server.createSetup()
        const registration = await register(server_setup, "alice", "café")

        const login = await logIn(server_setup, "alice", "café", registration.registrationRecord)
        expect(login?.exportKey).toBe(registration.exportKey)
    })

    it("fails in the client with the wrong password", async () => {
        const server_setup = (await loadOpaque()).server.createSetup()
        const registration = await register(server_setup, "alice", "correct horse battery staple")

        expect(await logIn(server_setup, "alice", "correct horse battery stapler", registration.registrationRecord)).toBeUndefined()
    })

    it("gives different export keys for the same password under different usernames", async () => {
        const server_setup = (await loadOpaque()).server.createSetup()
        const alice = await register(server_setup, "alice", "pa55word")
        const bob = await register(server_setup, "bob", "pa55word")

        expect(alice.exportKey).not.toBe(bob.exportKey)
    })
})

describe("keyFromExportKey", () => {
    it("derives the same key from the same export key, and another from another", async () => {
        const server_setup = (await loadOpaque()).server.createSetup()
        const alice = await register(server_setup, "alice", "pa55word")
        const bob = await register(server_setup, "bob", "pa55word")

        const iv = new Uint8Array(12)
        const aes_key_bits = crypto.getRandomValues(new Uint8Array(32))
        const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await keyFromExportKey(alice.exportKey), aes_key_bits)

        const unwrapped = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, await keyFromExportKey(alice.exportKey), wrapped)
        expect(new Uint8Array(unwrapped)).toEqual(aes_key_bits)

        await expect(crypto.subtle.decrypt({ name: "AES-GCM", iv }, await keyFromExportKey(bob.exportKey), wrapped)).rejects.toThrow()
    })
})
