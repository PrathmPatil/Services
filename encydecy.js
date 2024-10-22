1)
// Encryption key
const keyMaterial = 'encryptionKey123'; 

// Convert string to ArrayBuffer
function stringToArrayBuffer(str) {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}

// Convert ArrayBuffer to base64 string
function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
}

// Convert base64 string to ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Generate encryption key
async function getCryptoKey(keyMaterial) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw', 
        encoder.encode(keyMaterial),
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
    return key;
}

// Encryption function
async function encrypt(data) {
    const key = await getCryptoKey(keyMaterial);
    const iv = crypto.getRandomValues(new Uint8Array(12));  // Initialization vector (IV)

    const encryptedData = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        },
        key,
        stringToArrayBuffer(data)
    );

    return {
        encrypted_data: arrayBufferToBase64(encryptedData),
        iv: arrayBufferToBase64(iv),
        tag: null  // Tag is automatically handled in AES-GCM in JS
    };
}

// Decryption function
async function decrypt(encrypted_data, iv) {
    const key = await getCryptoKey(keyMaterial);
    const ivBuffer = base64ToArrayBuffer(iv);
    const encryptedBuffer = base64ToArrayBuffer(encrypted_data);

    try {
        const decryptedData = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer,
                tagLength: 128
            },
            key,
            encryptedBuffer
        );

        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (e) {
        return 'Decryption failed';
    }
}

// Example usage:
(async () => {
    const data = '@!#!$%^&*()_+';
    const encrypted = await encrypt(data);
    console.log('Encrypted:', encrypted);

    const decrypted = await decrypt(encrypted.encrypted_data, encrypted.iv);
    console.log('Decrypted:', decrypted);
})();


2)
// Generate a key
async function generateKey() {
    return crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// Encrypt function
async function encryptData(data, key) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Initialization vector

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encodedData
    );
    
    return { iv, encryptedData: new Uint8Array(encrypted) };
}

// Decrypt function
async function decryptData(encryptedData, key, iv) {
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encryptedData
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}

// Example usage
async function performEncryptionDecryption() {
    const key = await generateKey();
    
    const data = "234567890f;lkxcvb'6789ohvb'e6780-p";
    console.log("Original Data:", data);

    // Encrypt data
    const { iv, encryptedData } = await encryptData(data, key);
    console.log("Encrypted Data:", encryptedData);

    // Decrypt data
    const decryptedData = await decryptData(encryptedData, key, iv);
    console.log("Decrypted Data:", decryptedData);
}

performEncryptionDecryption();


3)
need to add crypto-js (this is for package.json base)
const CryptoJS = require('crypto-js');

// Encryption service
function encryptData(data, secretKey) {
    try {
        const ciphertext = CryptoJS.AES.encrypt(JSON.stringify(data), secretKey).toString();
        return ciphertext;
    } catch (error) {
        console.error("Encryption error:", error);
        return null;
    }
}

// Decryption service
function decryptData(ciphertext, secretKey) {
    try {
        const bytes = CryptoJS.AES.decrypt(ciphertext, secretKey);
        const decryptedData = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        return decryptedData;
    } catch (error) {
        console.error("Decryption error:", error);
        return null;
    }
}

// Example usage
const secretKey = 'mySecretKey123!';
const dataToEncrypt = { name: "John Doe", email: "john@example.com" };

// Encrypt the data
const encryptedData = encryptData(dataToEncrypt, secretKey);
console.log("Encrypted Data:", encryptedData);

// Decrypt the data
const decryptedData = decryptData(encryptedData, secretKey);
console.log("Decrypted Data:", decryptedData);

1)hash crypto
const crypto = require('crypto');

// Function to hash a password using SHA-256
function hashPassword(password) {
    const hash = crypto.createHash('sha256');
    hash.update(password);
    return hash.digest('hex'); // Return the hash in hexadecimal format
}

// Example usage
const password = 'mySecurePassword';
const hashedPassword = hashPassword(password);
console.log('Hashed Password:', hashedPassword);

2)hash crypto
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    
    // Hash the password using SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    
    // Convert the hash to a hexadecimal string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return hashHex;
}

// Example usage
const password = 'mySecurePassword';
hashPassword(password).then(hashedPassword => {
    console.log('Hashed Password:', hashedPassword);
});





