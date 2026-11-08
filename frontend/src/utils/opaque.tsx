// OPAQUE (RFC 9807) is how accounts register and log in, so the API never sees a password, or
// anything it could check one against without its OPRF seed. @serenity-kit/opaque runs the client's
// side. It's only loaded when it's needed, since its WebAssembly is large.
import type * as OpaqueLibrary from "@serenity-kit/opaque"

type Opaque = typeof OpaqueLibrary

// library_promise resolves to the OPAQUE library once it's loaded
let library_promise : Promise<Opaque> | null = null

// loadOpaque resolves to the OPAQUE library once its WebAssembly is ready. It's only loaded once,
// unless loading it fails.
export function loadOpaque() : Promise<Opaque> {
    if (library_promise == null) {
        library_promise = import("@serenity-kit/opaque").then(async library => {
            await library.ready
            return library
        })
        // load it again next time if this attempt fails
        library_promise.catch(() => {
            library_promise = null
        })
    }

    return library_promise
}

// KEY_STRETCHING is the Argon2id the client runs during registration and login: 64 MiB, 3 passes and
// 4 lanes, which is the library's "memory-constrained" preset. It's spelled out so a new default in
// the library can't change every account's keys, since changing it means every account has to
// register again.
export const KEY_STRETCHING = { "argon2id-custom": { memory: 65536, iterations: 3, parallelism: 4 } }

// normalizeUsername trims whitespace from names for consistency
export function normalizeUsername(username : string) : string {
    return username.trim()
}

// passwordInput is what OPAQUE is given as the password: the username along with the password. RFC
// 9807 stretches with a fixed salt, so only the server's OPRF key for each account keeps the
// accounts' stretched passwords apart, and clients can't check that the server uses a different key
// for each. With the username in the input, a server that used one key for every account would
// still have to stretch each guess separately for each account. The password is NFC normalized so
// the same password typed on different devices matches. Changing this means every account has to
// register again.
export function passwordInput(username : string, password : string) : string {
    return JSON.stringify(["electronic-voting/opaque/v1", username, password.normalize("NFC")])
}

// identifiers are the identities bound into an account's registration record, which have to be the
// same at every login: the username for the client. The server's identity is left to the default,
// its public key, which is what the API uses too.
export function identifiers(username : string) : { client : string } {
    return { client: username }
}
