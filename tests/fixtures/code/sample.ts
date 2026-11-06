export async function makeKeys(): Promise<void> {
  const pair = await crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 128 }, true, ["encrypt"]);
  const ec = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
}
