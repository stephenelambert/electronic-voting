import { describe, expect, it } from "vitest"
import { CertificateRole } from "../models/certificate"
import { canonicalJSON, signedData } from "./auth"

describe("signedData", () => {
    // the same as TestRequestSignedDataIsExact in the API's tests
    it("matches the API's encoding", () => {
        expect(signedData("voter.authorize", "aW5zdGFuY2U=", CertificateRole.global_admin, null, "1793059200000", `{"jurisdiction_id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a"}`))
            .toBe("voter.authorize\naW5zdGFuY2U=\nglobal_admin\n\n1793059200000\n" + `{"jurisdiction_id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a"}`)
        expect(signedData("blind_signature.request", "aW5zdGFuY2U=", CertificateRole.voter, "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a", "1793059200000", "{\n}"))
            .toBe("blind_signature.request\naW5zdGFuY2U=\nvoter\n0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a\n1793059200000\n{\n}")
    })

    it("leaves empty lines for a request that only needs the account", () => {
        expect(signedData("recovery_record.read", "aW5zdGFuY2U=", null, null, "1793059200000", ""))
            .toBe("recovery_record.read\naW5zdGFuY2U=\n\n\n1793059200000\n")
    })
})

describe("canonicalJSON", () => {
    // the same as TestCanonicalJSONIsExact in the API's tests: < > & aren't escaped, quotes,
    // backslashes and control characters are, and so are U+2028 and U+2029, which the API's encoder
    // always escapes
    it("matches the API's encoding", () => {
        const body = {
            id: "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a",
            name: "<b>Tom & \"Jerry\"</b> \\ \n\t\b\f\u0001\u007f \u{2028}\u{2029} é🗳",
            count: 3,
        }

        expect(canonicalJSON(body))
            .toBe(String.raw`{"id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a","name":"<b>Tom & \"Jerry\"</b> \\ \n\t\b\f\u0001` + "\u007f \\u2028\\u2029 " + `é🗳","count":3}`)
    })
})
