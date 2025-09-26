import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { randomBytes, createCipheriv } from "crypto";
import { readFileSync, existsSync } from "fs";
import path from "path";
import "dotenv/config";

const {
  R2_ACCOUNT_ID,
  R2_ACCESS_KEY_ID,
  R2_SECRET_ACCESS_KEY,
  R2_BUCKET_NAME,
} = process.env;

if (!R2_ACCOUNT_ID || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET_NAME) {
  console.error("Error：Check the R2 config in .env file is complete or not");
  process.exit(1);
}

const R2_ENDPOINT = `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;

/**
 * encrypt the file buffer using AES-256-GCM.
 * @param buffer - the file content to encrypt
 * @param key - 256-bit (32 bytes) key
 * @returns encrypted buffer (format: iv + ciphertext + authTag)
 */
function encrypt(buffer: Buffer, key: Buffer): Buffer {
  // AES-GCM recommends using 12 bytes (96-bit) IV
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag(); // authTag is always 16 bytes

  // --- key modification: use IV -> Ciphertext -> AuthTag standard order ---
  // this ensures compatibility with the browser Web Crypto API
  return Buffer.concat([iv, encrypted, authTag]);
}

async function uploadEncryptedBook(filePath: string) {
  try {
    if (!existsSync(filePath)) throw new Error(`Can not find file path：${filePath}`);
    console.log("1. Find the file path...");

    const secretKey = randomBytes(32);
    console.log("2. Generate the secret key...");

    const fileBuffer = readFileSync(filePath);
    console.log("3. Finish reading the file...");

    const encryptedBuffer = encrypt(fileBuffer, secretKey);
    console.log("4. Complete the encryption...");

    const s3Client = new S3Client({
      region: "auto",
      endpoint: R2_ENDPOINT,
      credentials: {
        accessKeyId: R2_ACCESS_KEY_ID as string,
        secretAccessKey: R2_SECRET_ACCESS_KEY as string,
      },
    });

    const originalFileName = path.basename(filePath, path.extname(filePath));
    const fileExtension = path.extname(filePath);
    const fileKey = `${originalFileName}_${Date.now()}${fileExtension}.encrypted`;

    const uploadParams = {
      Bucket: R2_BUCKET_NAME,
      Key: fileKey,
      Body: encryptedBuffer,
      ContentType: "application/octet-stream",
    };

    console.log(`5. Uploading the file to "${R2_BUCKET_NAME}"...`);
    await s3Client.send(new PutObjectCommand(uploadParams));
    console.log("6. Upload the file to R2 successfully!");

    console.log("\n--- Result ---");
    console.log(`The secret key: ${secretKey.toString("hex")}`);
    console.log(`R2 File Key: ${fileKey}`);
    console.log("------------------------\n");
    console.log("Please update the secret key and R2 file key into the database");

  } catch (error) {
    if (error instanceof Error) console.error("\nError", error.message);
    else console.error("\nUnknown Error", error);
  }
}

const bookPath = process.argv[2];
if (!bookPath) {
  console.log("\nHow to use: tsx src/upload.ts file path");
  console.log("Example: tsx src/upload.ts ./books/my-book.pdf\n");
} else {
  uploadEncryptedBook(bookPath);
}

    

