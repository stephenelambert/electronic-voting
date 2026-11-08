import { describe, expect, it } from "vitest"
import { publicKeyHash } from "./keys"
import { loadRoot } from "./root"
import { accepted, loadVectors } from "./testvectors"

describe("loadRoot", () => {
    it("accepts the API's root", async () => {
        const vectors = loadVectors()

        const root = await loadRoot(vectors.root)

        expect(root.public_key).toBe(vectors.root.public_key)
        expect(root.instance).toBe(await publicKeyHash(vectors.root.public_key))
        expect(vectors.election.signed_request.instance).toBe(root.instance)
    })

    it("rejects roots that don't check out", async () => {
        const vectors = loadVectors()

        const cases = {
            "another root's public key": { cert_pem: vectors.root.cert_pem, public_key: vectors.other_root.public_key },
            "a certificate that isn't a root's": { cert_pem: vectors.admin.cert_pem, public_key: vectors.admin.public_key },
            "a public key rather than a certificate": { cert_pem: vectors.root.public_key, public_key: vectors.root.public_key },
        }
        expect(await accepted(cases, loadRoot)).toEqual([])
    })
})
