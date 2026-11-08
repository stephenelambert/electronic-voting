import { getRootCertificate, RootCertificate } from "@/services/rootcertificateservice";
import { publicKeyHash, publicKeyPEMToDER } from "@/utils/keys";
import { Certificate, equalBytes, parseCertificate } from "@/utils/x509";

// Root is the API's root certificate, which issues every other certificate, once loadRoot has
// checked it
export interface Root {
    // public_key is the root's public key (PEM)
    public_key : string;
    // key is the root's public key, imported to check the certificates it issued
    key : CryptoKey;
    // instance is what requests signed for this instance name it by: the base64 SHA-256 hash of the
    // root's public key
    instance : string;
}

// ROOT_COMMON_NAME is the common name of the API's root certificate
const ROOT_COMMON_NAME = "system"

// publicKeyDER returns a PEM public key's DER bytes, which are the same however the PEM is laid out
export function publicKeyDER(public_key_pem : string) : Uint8Array {
    return new Uint8Array(publicKeyPEMToDER(public_key_pem))
}

// signedBy reports whether key signed the certificate
export async function signedBy(key : CryptoKey, certificate : Certificate) : Promise<boolean> {
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, certificate.signature, certificate.signed)
}

// loadRoot checks the API's root certificate and its public key, as getRootCertificate fetches them,
// and returns the root, ready to check certificates and requests against. It throws unless the
// certificate is a root's, for the key, and signed by it. The API serves its own root, so for now,
// trusting it means trusting the API's host.
export async function loadRoot(root : RootCertificate) : Promise<Root> {
    const certificate = parseCertificate(root.cert_pem)
    if (certificate.common_name !== ROOT_COMMON_NAME) {
        throw new Error("root certificate isn't a root's")
    }
    if (!equalBytes(certificate.public_key, publicKeyDER(root.public_key))) {
        throw new Error("root's public key isn't its certificate's")
    }

    const key = await crypto.subtle.importKey("spki", certificate.public_key, { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"])
    if (!await signedBy(key, certificate)) {
        throw new Error("root certificate isn't signed by its own key")
    }

    return { public_key: root.public_key, key, instance: await publicKeyHash(root.public_key) }
}

// root_promise resolves to the API's root, once it's been fetched and checked
let root_promise : Promise<Root> | null = null

// getRoot resolves to the API's root certificate, checked by loadRoot. It's only fetched once, unless
// fetching or checking it fails.
export function getRoot() : Promise<Root> {
    if (root_promise == null) {
        root_promise = getRootCertificate().then(resp => {
            if (resp == null || resp.status_code != 200 || resp.root == null) {
                throw new Error("couldn't fetch the root certificate")
            }
            return loadRoot(resp.root)
        })
        // fetch it again next time if this attempt fails
        root_promise.catch(() => {
            root_promise = null
        })
    }

    return root_promise
}
