export function arrayBufferToBase64( buffer : ArrayBuffer ) : string {
	let binary = '';
	const bytes = new Uint8Array( buffer );
	const len = bytes.byteLength;
	for (let i = 0; i < len; i++) {
		binary += String.fromCharCode( bytes[ i ] );
	}
	return btoa( binary );
}

// base64urlToArrayBuffer decodes unpadded base64url, which the OPAQUE library uses
export function base64urlToArrayBuffer(base64url : string) : ArrayBuffer {
    const base64 : string = base64url.replace(/-/g, "+").replace(/_/g, "/")
    return base64ToArrayBuffer(base64 + "=".repeat((4 - base64.length % 4) % 4))
}

export function base64ToArrayBuffer(base64 : string) : ArrayBuffer {
    const binary_string = atob(base64)
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for(let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}