import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};

export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  // TODO implement this function using the crypto package to generate a public and private RSA key pair.
  //      the public key should be used for encryption and the private key for decryption. Make sure the
  //      keys are extractable.

  try {
    // Generate an RSA key pair
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    return { publicKey, privateKey };
  } catch (error) {
    console.error('Error generating RSA key pair:', error);
    throw error; // Optionally, rethrow the error to handle it elsewhere
  }

}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a public key
  try {
    const exportedKey = await crypto.subtle.exportKey("spki", key);
    const exportedKeyBase64 = arrayBufferToBase64(exportedKey);
    return exportedKeyBase64;
  }
  catch (error) {
    console.error("Error exporting public key:", error);
    return "";
  }
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  // TODO implement this function to return a base64 string version of a private key
  if (!key) {
    return null;
  }
  try {
    const exportedKey = await crypto.subtle.exportKey("pkcs8", key);
    const exportedKeyBuffer = new Uint8Array(exportedKey);
    const exportedKeyBase64 = arrayBufferToBase64(exportedKeyBuffer);

    return exportedKeyBase64;
  }
  catch (error) {
    console.error("Error exporting private key:", error);
    return null;
  }

}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportPubKey function to it's native crypto key object

  try {
    // Convert the base64 string back to an ArrayBuffer
    const keyBuffer = base64ToArrayBuffer(strKey);

    // Import the key from the ArrayBuffer
    const importedKey = await crypto.subtle.importKey(
        "spki",
        keyBuffer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        true,
        ["encrypt"]
    );

    return importedKey;
  } catch (error) {
    console.error("Error importing public key:", error);
    throw error;
  }
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportPrvKey function to it's native crypto key object

  try {
    // Convert the base64 string to an ArrayBuffer
    const keyBuffer = base64ToArrayBuffer(strKey);

    // Import the private key from the ArrayBuffer
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        keyBuffer,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        true,
        ["decrypt"]
    );

    return privateKey;
  } catch (error) {
    console.error("Error importing private key:", error);
    throw error;
  }
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: use the provided base64ToArrayBuffer function

  try {
    // Convert the base64-encoded data to an ArrayBuffer
    const dataBuffer = base64ToArrayBuffer(b64Data);

    // Convert the base64 public key string to a CryptoKey object
    const publicKey = await importPubKey(strPublicKey);

    // Encrypt the data using the RSA public key
    const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: "RSA-OAEP",
        },
        publicKey,
        dataBuffer
    );

    // Convert the encrypted ArrayBuffer to a base64 string
    const encryptedData = arrayBufferToBase64(encryptedBuffer);

    return encryptedData;
  } catch (error) {
    console.error("Error encrypting message:", error);
    throw error;
  }
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function

  try {
    // Convert the base64-encoded data to an ArrayBuffer
    const dataBuffer = base64ToArrayBuffer(data);

    // Decrypt the data using the RSA private key
    const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: "RSA-OAEP",
        },
        privateKey,
        dataBuffer
    );

    // Convert the decrypted ArrayBuffer to a string
    const decryptedString = new TextDecoder().decode(decryptedBuffer);

    return decryptedString;
  } catch (error) {
    console.error("Error decrypting message:", error);
    throw error;
  }
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // TODO implement this function using the crypto package to generate a symmetric key.
  //      the key should be used for both encryption and decryption. Make sure the
  //      keys are extractable.

  // remove this
  return {} as any;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a symmetric key

  try {
    // Export the key
    const exportedKey = await crypto.subtle.exportKey("raw", key);

    // Convert the exported key ArrayBuffer to a base64 string
    const exportedKeyBase64 = arrayBufferToBase64(exportedKey);

    return exportedKeyBase64;
  } catch (error) {
    console.error("Error exporting symmetric key:", error);
    throw error;
  }
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportSymKey function to it's native crypto key object

  try {
    // Convert the base64 string key to an ArrayBuffer
    const keyBuffer = base64ToArrayBuffer(strKey);

    // Import the key from the ArrayBuffer
    const importedKey = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );

    return importedKey;
  } catch (error) {
    console.error("Error importing symmetric key:", error);
    throw error;
  }
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: encode the data to a uin8array with TextEncoder

  try {
    // Convert the data string to a Uint8Array
    const encodedData = new TextEncoder().encode(data);

    // Encrypt the data using the symmetric key
    const encryptedArray = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: new Uint8Array(12) }, // Empty IV for this example, replace with the correct IV if applicable
        key,
        encodedData
    );

    // Convert the encrypted ArrayBuffer to a base64 string
    const encryptedBase64 = arrayBufferToBase64(encryptedArray);

    return encryptedBase64;
  } catch (error) {
    console.error("Error encrypting data:", error);
    throw error;
  }
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function and use TextDecode to go back to a string format

  try {
    // Convert the base64 string symmetric key back to an ArrayBuffer
    const keyBuffer = base64ToArrayBuffer(strKey);

    // Convert the base64 string encrypted data back to an ArrayBuffer
    const encryptedBuffer = base64ToArrayBuffer(encryptedData);

    // Import the symmetric key from the ArrayBuffer
    const symmetricKey = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    // Decrypt the data using the symmetric key
    const decryptedArray = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(12) }, // Empty IV for this example, replace with the correct IV if applicable
        symmetricKey,
        encryptedBuffer
    );

    // Convert the decrypted ArrayBuffer back to a string
    const decryptedData = new TextDecoder().decode(decryptedArray);

    return decryptedData;
  } catch (error) {
    console.error("Error decrypting data:", error);
    throw error;
  }
}
