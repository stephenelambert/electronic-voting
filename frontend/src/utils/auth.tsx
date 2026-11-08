import { CertificateRole } from "@/models/certificate";
import { User } from "@/models/user";
import { getUser } from "./user";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./base64";
import { importECDSAPublicKey } from "./keys";
import { getRoot } from "./root";

// SignedRequest is a request the server stored exactly as it was signed
export interface SignedRequest {
    // action names what the request does, like "voter.authorize"
    action: string;
    // instance is the instance the request was signed for: the base64 SHA-256 hash of its root
    // certificate's public key
    instance: string;
    // role and jurisdiction_id are the role and jurisdiction of the certificate the signer acted
    // under, or null if the request didn't need them
    role: CertificateRole | null;
    jurisdiction_id: string | null;
    request_timestamp: string;
    body: string;
    public_key: string;
    signature: string;
    // cert_pem is the certificate that role and jurisdiction_id name, which the signer acted under,
    // or null if the request didn't need one
    cert_pem: string | null;
}

// signedData returns what an authenticated request's signature covers, one field per line in this
// order: the request's action, which names what it does (like "voter.authorize"), the instance it's
// for, the role and jurisdiction of the certificate the signer is acting under (empty if none), its
// timestamp, and its body. Only the body can contain a newline, so it goes last and no field needs a
// length prefix. The API's localcrypto.RequestSignedData builds the same data.
export function signedData(action : string, instance : string, role : CertificateRole | null, jurisdiction_id : string | null, request_timestamp : string, body : string) : string {
    return [action, instance, role ?? "", jurisdiction_id ?? "", request_timestamp, body].join("\n")
}

// LINE_SEPARATOR and PARAGRAPH_SEPARATOR are U+2028 and U+2029, which the API's JSON encoder always
// escapes and JSON.stringify doesn't
const LINE_SEPARATOR = String.fromCharCode(0x2028)
const PARAGRAPH_SEPARATOR = String.fromCharCode(0x2029)

// canonicalJSON returns the one encoding of a signed request's body that the API accepts (see its
// localcrypto.CanonicalJSON): what JSON.stringify produces, with U+2028 and U+2029 escaped too.
// Objects' fields have to be in the order of the API's request types for consistent parsing.
export function canonicalJSON(value : unknown) : string {
    // the two characters can only be inside strings in JSON.stringify's output, so escaping them
    // everywhere is safe
    return JSON.stringify(value).split(LINE_SEPARATOR).join("\\u2028").split(PARAGRAPH_SEPARATOR).join("\\u2029")
}

// getConfigForAuthenticatedRequest signs a request for the API, and returns the axios config that
// sends the signature. action names what the request does, and role and jurisdiction_id are the role
// and jurisdiction of the certificate the user is acting under, or null if the request only needs
// their account. It resolves to null if the user isn't logged in or the request can't be signed.
export async function getConfigForAuthenticatedRequest(action : string, role : CertificateRole | null, jurisdiction_id : string | null, body : string): Promise<object|null> {
    const user : User | null = await getUser();
    if (user === null) {
        return null
    }

    // sign for the instance of the root getRoot checked, which audits check requests against too
    let instance : string
    try {
        instance = (await getRoot()).instance
    } catch (error) {
        console.log("error getting the instance to sign a request for", error)
        return null
    }

    // get the current time into a string
    const now = Date.now().toString()

    const text_encoder : TextEncoder = new TextEncoder()
    const encoded_data : ArrayBuffer = text_encoder.encode(signedData(action, instance, role, jurisdiction_id, now, body)).buffer

    const signature = await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" },
        },
        user.private_key as CryptoKey,
        encoded_data,
    )

    const encoded_public_key = arrayBufferToBase64(text_encoder.encode(user.public_key).buffer)
    const encoded_signature = arrayBufferToBase64(signature)
    // the action and instance aren't sent, since the API fills in its own when it checks the signature
    const auth_header = "Bearer " + [now, encoded_public_key, role ?? "", jurisdiction_id ?? "", encoded_signature].join(".");

    return {
        headers: { "Authorization": auth_header }
    }
}

// verifyOwnSignedRequest checks that a request the server stored was signed with the user's own
// key, the same way the server checks requests: an ECDSA signature over what signedData returns for it
export async function verifyOwnSignedRequest(signed_request : SignedRequest) : Promise<boolean> {
    const user : User | null = await getUser();
    if (user === null) {
        return false
    }

    return await verifyRequestSignature(await importECDSAPublicKey(user.public_key), signed_request)
}

// verifySignedRequest checks that a request the server stored was signed with the public key stored
// with it, the same way the server checks requests. That shows the request hasn't been altered, but
// not who holds the key, which takes checking the key's certificate.
export async function verifySignedRequest(signed_request : SignedRequest) : Promise<boolean> {
    return await verifyRequestSignature(await importECDSAPublicKey(signed_request.public_key), signed_request)
}

// verifyRequestSignature checks that public_key signed a stored request: an ECDSA signature over what
// signedData returns for it
async function verifyRequestSignature(public_key : CryptoKey, signed_request : SignedRequest) : Promise<boolean> {
    const text_encoder : TextEncoder = new TextEncoder()
    const signed_data : ArrayBuffer = text_encoder.encode(signedData(signed_request.action, signed_request.instance, signed_request.role, signed_request.jurisdiction_id, signed_request.request_timestamp, signed_request.body)).buffer

    return await crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" },
        },
        public_key,
        base64ToArrayBuffer(signed_request.signature),
        signed_data,
    )
}
