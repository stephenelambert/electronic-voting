import { base64ToArrayBuffer } from "./base64"

// This reads the X.509 certificates the API issues, so the browser can check them (see checkSigner).
// It's deliberately narrow: it only accepts what Go's x509 package produces for them, in DER with
// one-byte tags and minimal lengths, and it reads the fields checking needs by their position, so the
// issuer's name can't be mistaken for the subject's. WebCrypto checks the signatures, over the exact
// bytes they cover.

// DERElement is one encoded value: its tag, its contents, and the whole element, header included
interface DERElement {
    tag : number;
    contents : Uint8Array;
    encoded : Uint8Array;
}

// the tags of the elements certificates use
const TAG_INTEGER = 0x02
const TAG_BIT_STRING = 0x03
const TAG_OBJECT_IDENTIFIER = 0x06
const TAG_UTF8_STRING = 0x0c
const TAG_PRINTABLE_STRING = 0x13
const TAG_SEQUENCE = 0x30
const TAG_SET = 0x31
// a certificate's version is explicitly tagged [0], and its extensions [3]
const TAG_VERSION = 0xa0
const TAG_EXTENSIONS = 0xa3

// VERSION_3 is the encoded version of an X.509 v3 certificate, which is the only kind the API issues
const VERSION_3 = [0x02, 0x01, 0x02]

// ECDSA_WITH_SHA384 is the encoded AlgorithmIdentifier for ECDSA with SHA-384 (1.2.840.10045.4.3.3),
// which is how the API's P-384 root signs certificates
const ECDSA_WITH_SHA384 = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]

// COMMON_NAME is the encoded object identifier of a common name (2.5.4.3)
const COMMON_NAME = [0x55, 0x04, 0x03]

// P384_INTEGER_BYTES is the size of a P-384 integer, which r and s each take in the signatures
// WebCrypto checks
const P384_INTEGER_BYTES = 48

// Certificate is what checking a certificate the API issued needs from it
export interface Certificate {
    // signed is the part of the certificate its issuer's signature covers (its TBSCertificate)
    signed : Uint8Array;
    // signature is the issuer's ECDSA signature over signed, as r and s concatenated, which is how
    // WebCrypto takes it
    signature : Uint8Array;
    // common_name is the subject's common name, which names the role and jurisdiction the
    // certificate is for (see localcrypto.CreateCertificateTemplate)
    common_name : string;
    // public_key is the subject's public key, as DER (a SubjectPublicKeyInfo)
    public_key : Uint8Array;
}

// equalBytes reports whether a and b hold the same bytes
export function equalBytes(a : ArrayLike<number>, b : ArrayLike<number>) : boolean {
    if (a.length != b.length) {
        return false
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] != b[i]) {
            return false
        }
    }

    return true
}

// readElements reads the elements encoded one after another in bytes, which they must fill exactly
function readElements(bytes : Uint8Array) : DERElement[] {
    const elements : DERElement[] = []
    let offset = 0
    while (offset < bytes.length) {
        if (offset + 2 > bytes.length) {
            throw new Error("certificate ends partway through an element")
        }
        const tag = bytes[offset]
        // tag numbers of 31 and up take more bytes, which certificates don't use
        if ((tag & 0x1f) == 0x1f) {
            throw new Error("certificate has a multi-byte tag")
        }

        let length = bytes[offset + 1]
        let header = 2
        if (length >= 0x80) {
            // the long form: the low bits are how many bytes the length takes. DER never uses the
            // indefinite form (0x80), and a certificate is never anywhere near 16 MB
            const length_bytes = length & 0x7f
            if (length_bytes == 0 || length_bytes > 3 || offset + 2 + length_bytes > bytes.length) {
                throw new Error("certificate has a length that isn't supported")
            }
            length = 0
            for (let i = 0; i < length_bytes; i++) {
                length = length * 256 + bytes[offset + 2 + i]
            }
            // DER takes as few bytes as it can: the short form below 128, and no leading zero bytes
            if (length < 0x80 || bytes[offset + 2] == 0) {
                throw new Error("certificate has a length that isn't minimal")
            }
            header += length_bytes
        }

        const end = offset + header + length
        if (end > bytes.length) {
            throw new Error("certificate ends partway through an element")
        }
        elements.push({ tag, contents: bytes.subarray(offset + header, end), encoded: bytes.subarray(offset, end) })
        offset = end
    }

    return elements
}

// readElement reads the one element in bytes, which must have the tag
function readElement(bytes : Uint8Array, tag : number) : DERElement {
    const elements = readElements(bytes)
    if (elements.length != 1 || elements[0].tag != tag) {
        throw new Error("certificate doesn't have the structure the API gives certificates")
    }

    return elements[0]
}

// readChildren reads the elements in a constructed element, which must have these tags, in this order
function readChildren(element : DERElement, tags : number[]) : DERElement[] {
    const children = readElements(element.contents)
    if (children.length != tags.length || children.some((child, i) => child.tag != tags[i])) {
        throw new Error("certificate doesn't have the structure the API gives certificates")
    }

    return children
}

// commonName reads the common name in a certificate's subject, which the API gives exactly one
// attribute: the common name
function commonName(name : DERElement) : string {
    const [attributes] = readChildren(name, [TAG_SET])
    const [attribute] = readChildren(attributes, [TAG_SEQUENCE])
    // the attribute's type, then its value, which Go encodes as a PrintableString when it can
    const parts = readElements(attribute.contents)
    if (parts.length != 2 || parts[0].tag != TAG_OBJECT_IDENTIFIER || !equalBytes(parts[0].contents, COMMON_NAME)
        || (parts[1].tag != TAG_PRINTABLE_STRING && parts[1].tag != TAG_UTF8_STRING)) {
        throw new Error("certificate's subject isn't only a common name")
    }

    return new TextDecoder("utf-8", { fatal: true }).decode(parts[1].contents)
}

// rawECDSASignature converts a DER ECDSA signature, a SEQUENCE of the integers r and s, to r and s
// concatenated, each padded to size bytes, which is how WebCrypto takes signatures. It throws unless
// both are positive integers of at most size bytes, encoded minimally.
export function rawECDSASignature(der : Uint8Array, size : number) : Uint8Array {
    const integers = readChildren(readElement(der, TAG_SEQUENCE), [TAG_INTEGER, TAG_INTEGER])

    const raw = new Uint8Array(size * 2)
    integers.forEach((integer, i) => {
        let value = integer.contents
        // DER integers are signed, so a positive one only starts with a zero byte when the next byte's
        // top bit is set
        if (value.length == 0 || value[0] >= 0x80 || (value[0] == 0 && (value.length == 1 || value[1] < 0x80))) {
            throw new Error("signature has an integer that isn't positive or isn't minimal")
        }
        if (value[0] == 0) {
            value = value.subarray(1)
        }
        if (value.length > size) {
            throw new Error("signature has an integer that's too long")
        }
        raw.set(value, (i + 1) * size - value.length)
    })

    return raw
}

// parseCertificate reads a PEM certificate the API issued. It throws if it isn't one: if it isn't a
// single DER certificate signed with ECDSA and SHA-384, or doesn't name only a common name as its
// subject.
export function parseCertificate(cert_pem : string) : Certificate {
    const match = /^-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\r?\n?$/.exec(cert_pem)
    if (match == null) {
        throw new Error("certificate isn't one PEM certificate")
    }
    const der = new Uint8Array(base64ToArrayBuffer(match[1].replace(/\s+/g, "")))

    const [signed, algorithm, signature] = readChildren(readElement(der, TAG_SEQUENCE), [TAG_SEQUENCE, TAG_SEQUENCE, TAG_BIT_STRING])
    // the version, serial number, signature algorithm, issuer, validity, subject, public key and
    // extensions
    const fields = readChildren(signed, [TAG_VERSION, TAG_INTEGER, TAG_SEQUENCE, TAG_SEQUENCE, TAG_SEQUENCE, TAG_SEQUENCE, TAG_SEQUENCE, TAG_EXTENSIONS])
    if (!equalBytes(fields[0].contents, VERSION_3)) {
        throw new Error("certificate isn't version 3")
    }
    // the algorithm is named in the signed part too, and both must be ECDSA with SHA-384
    if (!equalBytes(algorithm.encoded, ECDSA_WITH_SHA384) || !equalBytes(fields[2].encoded, ECDSA_WITH_SHA384)) {
        throw new Error("certificate isn't signed with ECDSA and SHA-384")
    }
    // a bit string starts with how many bits of its last byte are unused, and a signature has none
    if (signature.contents.length == 0 || signature.contents[0] != 0) {
        throw new Error("certificate's signature isn't whole bytes")
    }

    return {
        signed: signed.encoded,
        signature: rawECDSASignature(signature.contents.subarray(1), P384_INTEGER_BYTES),
        common_name: commonName(fields[5]),
        public_key: fields[6].encoded,
    }
}
