
import { arrayBufferToBase64, base64ToArrayBuffer, base64urlToArrayBuffer } from "./base64"

// keyFromExportKey derives the AES key that encrypts the account's AES key from OPAQUE's export key
// (unpadded base64url). Only the client gets the export key, and it's the same at every login, as
// long as the account doesn't register again.
export async function keyFromExportKey(export_key : string) : Promise<CryptoKey> {
    const base_key : CryptoKey = await crypto.subtle.importKey("raw",
        base64urlToArrayBuffer(export_key),
        "HKDF",
        false,
        ["deriveKey"])

    return await crypto.subtle.deriveKey({
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode("electronic-voting/aes-key-wrap/v1"),
    }, base_key, {
        name: "AES-GCM",
        length: 256,
    }, false,
    ["encrypt", "decrypt"])
}

// generates an ECDSA key for signing requests, returns a CryptoKeyPair
export async function makeECDSA(): Promise<CryptoKeyPair>{
    const key_pair:CryptoKeyPair = await crypto.subtle.generateKey({
        name: "ECDSA",
        namedCurve: "P-384",
    }, true,
    ["sign"])

    return key_pair
}

/*
Convert an ArrayBuffer into a string
from https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string/
*/
function ab2str(buf:ArrayBuffer): string {
    return String.fromCharCode.apply(null, Array.from(new Uint8Array(buf)));
}

export async function exportPrivateKey(private_key: CryptoKey): Promise<string> {
    const exported : ArrayBuffer = await window.crypto.subtle.exportKey("pkcs8", private_key);
    const exportedAsString : string = ab2str(exported);
    const exportedAsBase64 : string = window.btoa(exportedAsString);
    const pemExported : string = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;

    return pemExported;
}

/*
Convert a string into an ArrayBuffer
from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
*/
function str2ab(str : string) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

export async function importECDSAPrivateKey(private_key_pem : string) : Promise<CryptoKey> {
    // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = private_key_pem.substring(
    pemHeader.length,
    private_key_pem.length - pemFooter.length,
  );
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "ECDSA",
      namedCurve: "P-384",
    },
    true,
    ["sign"],
  );
}

export async function exportPublicKey(public_key : CryptoKey) : Promise<string> {
    const exported : ArrayBuffer = await window.crypto.subtle.exportKey("spki", public_key);
    const exportedAsString : string = ab2str(exported);
    const exportedAsBase64 : string = window.btoa(exportedAsString);
    const pemExported : string = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;

    return pemExported;
}

// publicKeyPEMToDER returns the DER bytes of a PEM public key, which are the same however the PEM is
// laid out
export function publicKeyPEMToDER(public_key_pem : string) : ArrayBuffer {
    const base64_body : string = public_key_pem
        .replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "")
        .replace(/\s+/g, "")
    return base64ToArrayBuffer(base64_body)
}

// MIN_ELECTION_KEY_BITS is the smallest modulus checkElectionPublicKey accepts, matching the size
// of the election keys the API generates
const MIN_ELECTION_KEY_BITS = 2048

// checkElectionPublicKey throws unless a PEM public key from the server is fit to be an election
// key: RSA, with a modulus of at least MIN_ELECTION_KEY_BITS and the usual public exponent (65537).
// It runs before the key is signed into a request to create an election, so the request only
// vouches for a sound key, and before a vote is blinded under it. It resolves to the key, imported
// for RSA-PSS with SHA-384 (how votes are signed) and extractable, since blinding reads its modulus.
export async function checkElectionPublicKey(public_key_pem : string) : Promise<CryptoKey> {
    // importing fails unless it is an RSA key
    const key : CryptoKey = await crypto.subtle.importKey(
        "spki",
        publicKeyPEMToDER(public_key_pem),
        { name: "RSA-PSS", hash: "SHA-384" },
        true,
        ["verify"],
    )

    const algorithm = key.algorithm as RsaHashedKeyAlgorithm
    if (algorithm.modulusLength < MIN_ELECTION_KEY_BITS) {
        throw new Error("election key modulus is only " + algorithm.modulusLength + " bits")
    }
    // the exponent is big-endian bytes, so 65537 is [1, 0, 1]
    if (Array.from(algorithm.publicExponent).join(",") != "1,0,1") {
        throw new Error("election key public exponent is not 65537")
    }

    return key
}

// publicKeyHash computes the base64 SHA-256 hash of a PEM public key's DER encoding. Requests for
// blind signatures include it to name the election key the vote was blinded under, and every signed
// request includes the root certificate's to name the instance it's for.
export async function publicKeyHash(public_key_pem : string) : Promise<string> {
    const digest : ArrayBuffer = await crypto.subtle.digest("SHA-256", publicKeyPEMToDER(public_key_pem))
    return arrayBufferToBase64(digest)
}

// importECDSAPublicKey imports a user's PEM public key, for checking signatures they made
export async function importECDSAPublicKey(public_key_pem : string) : Promise<CryptoKey> {
    return await crypto.subtle.importKey(
        "spki",
        publicKeyPEMToDER(public_key_pem),
        { name: "ECDSA", namedCurve: "P-384" },
        false,
        ["verify"],
    )
}

// checkOwnPublicKey throws unless public_key_pem is the public key of private_key, the user's
// extractable ECDSA private key. Login checks the public key the server sends with it: only the
// user's password decrypts the private key, but the server could swap the public key for one of its
// own and then sign things this client would accept as the user's, like a vote recovery record.
export async function checkOwnPublicKey(private_key : CryptoKey, public_key_pem : string) : Promise<void> {
    // imported extractable, so its point can be compared with the private key's
    const public_key : CryptoKey = await crypto.subtle.importKey(
        "spki",
        publicKeyPEMToDER(public_key_pem),
        { name: "ECDSA", namedCurve: "P-384" },
        true,
        ["verify"],
    )

    // an exported EC private key includes its public point, x and y
    const own : JsonWebKey = await crypto.subtle.exportKey("jwk", private_key)
    const sent : JsonWebKey = await crypto.subtle.exportKey("jwk", public_key)
    if (own.crv !== sent.crv || own.x !== sent.x || own.y !== sent.y) {
        throw new Error("public key from the server doesn't match the private key")
    }
}

// publicKeyFingerprint computes a SHA-256 fingerprint of a PEM public key, formatted as
// space-separated groups of 4 uppercase hex characters. It is computed locally, so users can compare
// fingerprints without trusting the server that provided the key.
export async function publicKeyFingerprint(public_key_pem : string) : Promise<string> {
    const der : ArrayBuffer = publicKeyPEMToDER(public_key_pem)
    const digest : ArrayBuffer = await crypto.subtle.digest("SHA-256", der)

    const hex : string = Array.from(new Uint8Array(digest))
        .map(byte => ("0" + byte.toString(16)).slice(-2))
        .join("")
        .toUpperCase()

    return hex.match(/.{4}/g)?.join(" ") ?? ""
}

// shortFingerprint returns the first groups of a fingerprint from publicKeyFingerprint, for
// places where the full fingerprint doesn't fit
export function shortFingerprint(fingerprint : string) : string {
    const groups : string[] = fingerprint.split(" ")
    if (groups.length <= 4) {
        return fingerprint
    }

    return groups.slice(0, 4).join(" ") + " …"
}

export async function exportAESKey(key : CryptoKey) : Promise<string> {
    const exported : ArrayBuffer = await window.crypto.subtle.exportKey("raw", key)
    return arrayBufferToBase64(exported)
}

export async function importAESKey(key_string : string) : Promise<CryptoKey> {
    const bytes : ArrayBuffer = base64ToArrayBuffer(key_string)
    return await crypto.subtle.importKey("raw",
        bytes,
        "AES-GCM",
        true,
        ["encrypt", "decrypt"]
    )
}

// cleartext is an ArrayBuffer, returns ArrayBuffer
export async function encryptWithAES(key : CryptoKey, cleartext : Uint8Array) : Promise<Uint8Array> {
    const iv : Uint8Array = window.crypto.getRandomValues(new Uint8Array(16))
    const base_ciphertext : ArrayBuffer = await window.crypto.subtle.encrypt({
        name: "AES-GCM",
        iv,
    }, key, cleartext)

    const uint8_ciphertext : Uint8Array = new Uint8Array(base_ciphertext)
    
    // concatenate the iv and the ciphertext
    const ciphertext : Uint8Array = new Uint8Array(iv.length + uint8_ciphertext.length)
    ciphertext.set(iv, 0)
    ciphertext.set(uint8_ciphertext, iv.length)

    return ciphertext
}

// plaintext is an ArrayBuffer, returns an ArrayBuffer
export async function decryptWithAES(key : CryptoKey, ciphertext : Uint8Array): Promise<ArrayBuffer> {
    const iv : Uint8Array = ciphertext.slice(0, 16)
    const base_ciphertext : Uint8Array = ciphertext.slice(16)

    return await window.crypto.subtle.decrypt({
        name: "AES-GCM",
        iv,
    }, key, base_ciphertext)
}