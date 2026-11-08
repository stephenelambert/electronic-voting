import { describe, expect, it } from "vitest"
import { arrayBufferToBase64, base64ToArrayBuffer } from "./base64"
import { publicKeyPEMToDER } from "./keys"
import { loadVectors } from "./testvectors"
import { equalBytes, parseCertificate, rawECDSASignature } from "./x509"

// certificateDER returns a PEM certificate's DER bytes
function certificateDER(cert_pem : string) : number[] {
    return Array.from(new Uint8Array(base64ToArrayBuffer(cert_pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, ""))))
}

// certificatePEM encodes DER bytes as a PEM certificate, the way Go does
function certificatePEM(der : number[]) : string {
    const base64 = arrayBufferToBase64(new Uint8Array(der).buffer)
    return "-----BEGIN CERTIFICATE-----\n" + (base64.match(/.{1,64}/g) ?? []).join("\n") + "\n-----END CERTIFICATE-----\n"
}

// replaceAt returns bytes with the occurrence of find at index (counting from 0) replaced
function replaceAt(bytes : number[], find : number[], replacement : number[], index : number) : number[] {
    let found = -1
    for (let i = 0; i + find.length <= bytes.length; i++) {
        if (equalBytes(bytes.slice(i, i + find.length), find) && ++found == index) {
            return [...bytes.slice(0, i), ...replacement, ...bytes.slice(i + find.length)]
        }
    }
    throw new Error("bytes don't have that occurrence")
}

// der encodes an element with a short-form length
function der(tag : number, ...contents : number[][]) : number[] {
    const flat = contents.flat()
    if (flat.length >= 0x80) {
        throw new Error("element is too long for the short form")
    }
    return [tag, flat.length, ...flat]
}

const ECDSA_WITH_SHA384 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]
const ECDSA_WITH_SHA256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]
const COMMON_NAME = [0x06, 0x03, 0x55, 0x04, 0x03]
const ORGANIZATION = [0x06, 0x03, 0x55, 0x04, 0x0a]

describe("parseCertificate", () => {
    it("reads the certificates the API issues", () => {
        const vectors = loadVectors()

        const root = parseCertificate(vectors.root.cert_pem)
        expect(root.common_name).toBe("system")
        expect(equalBytes(root.public_key, new Uint8Array(publicKeyPEMToDER(vectors.root.public_key)))).toBe(true)

        const admin = parseCertificate(vectors.admin.cert_pem)
        expect(admin.common_name).toBe("admin.global")
        expect(equalBytes(admin.public_key, new Uint8Array(publicKeyPEMToDER(vectors.admin.public_key)))).toBe(true)

        for (const voter of vectors.voters) {
            const certificate = parseCertificate(voter.cert_pem)
            expect(certificate.common_name).toBe("voter." + vectors.jurisdiction.id + ".jurisdiction")
            expect(equalBytes(certificate.public_key, new Uint8Array(publicKeyPEMToDER(voter.public_key)))).toBe(true)
        }
    })

    it("reads the signatures and the bytes they cover", async () => {
        const vectors = loadVectors()
        const root_key = await crypto.subtle.importKey("spki", publicKeyPEMToDER(vectors.root.public_key), { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"])

        // r or s has its top bit set in about half the signatures, so these cover integers with and
        // without a sign byte
        const cert_pems = [vectors.root.cert_pem, vectors.admin.cert_pem, ...vectors.voters.map(voter => voter.cert_pem)]
        for (const cert_pem of cert_pems) {
            const certificate = parseCertificate(cert_pem)
            expect(certificate.signature.length).toBe(96)
            expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, root_key, certificate.signature, certificate.signed)).toBe(true)
        }
        // the other root's certificate is signed by a different key
        const other = parseCertificate(vectors.other_root_admin_cert)
        expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, root_key, other.signature, other.signed)).toBe(false)
    })

    it("rejects certificates the API doesn't issue", () => {
        const vectors = loadVectors()
        const bytes = certificateDER(vectors.voters[0].cert_pem)

        const cases : Record<string, string> = {
            "a truncated certificate": certificatePEM(bytes.slice(0, -1)),
            "a byte after the certificate": certificatePEM([...bytes, 0]),
            "an indefinite length": certificatePEM([bytes[0], 0x80, ...bytes.slice(2)]),
            // the certificate's length in three bytes rather than two
            "a length that isn't minimal": certificatePEM([bytes[0], 0x83, 0x00, ...bytes.slice(2)]),
            "a multi-byte tag": certificatePEM([0x1f, ...bytes.slice(1)]),
            "another signature algorithm": certificatePEM(replaceAt(replaceAt(bytes, ECDSA_WITH_SHA384, ECDSA_WITH_SHA256, 0), ECDSA_WITH_SHA384, ECDSA_WITH_SHA256, 0)),
            "signature algorithms that don't match": certificatePEM(replaceAt(bytes, ECDSA_WITH_SHA384, ECDSA_WITH_SHA256, 1)),
            // the issuer's common name comes first, then the subject's
            "a subject that isn't a common name": certificatePEM(replaceAt(bytes, COMMON_NAME, ORGANIZATION, 1)),
            "a public key": vectors.voters[0].public_key,
            "two certificates": vectors.voters[0].cert_pem + vectors.voters[1].cert_pem,
            "text around the certificate": "certificate:\n" + vectors.voters[0].cert_pem,
        }
        const accepted = Object.keys(cases).filter(name => {
            try {
                parseCertificate(cases[name])
                return true
            } catch {
                return false
            }
        })
        expect(accepted).toEqual([])
    })
})

describe("rawECDSASignature", () => {
    it("pads short integers and drops sign bytes", () => {
        // r is 1, and s needs a sign byte, since its top bit is set
        const s = [0x80, ...new Array(47).fill(0x01)]
        const raw = rawECDSASignature(new Uint8Array(der(0x30, der(0x02, [0x01]), der(0x02, [0x00, ...s]))), 48)

        expect(Array.from(raw.slice(0, 48))).toEqual([...new Array(47).fill(0), 0x01])
        expect(Array.from(raw.slice(48))).toEqual(s)
    })

    it("rejects integers that aren't positive, minimal or short enough", () => {
        const one = der(0x02, [0x01])
        const cases : Record<string, number[]> = {
            "a negative integer": der(0x30, der(0x02, [0x80]), one),
            "an extra zero byte": der(0x30, der(0x02, [0x00, 0x01]), one),
            "zero": der(0x30, der(0x02, [0x00]), one),
            "an empty integer": der(0x30, der(0x02, []), one),
            "an integer that's too long": der(0x30, der(0x02, new Array(49).fill(0x01)), one),
            "a third integer": der(0x30, one, one, one),
            "a byte after the signature": [...der(0x30, one, one), 0x00],
            "a set rather than a sequence": der(0x31, one, one),
        }
        const accepted = Object.keys(cases).filter(name => {
            try {
                rawECDSASignature(new Uint8Array(cases[name]), 48)
                return true
            } catch {
                return false
            }
        })
        expect(accepted).toEqual([])
    })
})
