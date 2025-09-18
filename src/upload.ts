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
  console.error("❌ 错误：请检查 .env 文件中的 R2 配置是否完整。");
  process.exit(1);
}

const R2_ENDPOINT = `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;

/**
 * 使用 AES-256-GCM 加密文件缓冲区
 * @param buffer - 要加密的文件内容
 * @param key - 256位 (32字节) 的密钥
 * @returns 加密后的缓冲区 (格式: iv + ciphertext + authTag)
 */
function encrypt(buffer: Buffer, key: Buffer): Buffer {
  // AES-GCM 推荐使用 12 字节 (96位) 的 IV
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag(); // authTag 总是 16 字节

  // --- 关键修改: 使用 IV -> Ciphertext -> AuthTag 的标准顺序 ---
  // 这确保了与浏览器 Web Crypto API 的兼容性
  return Buffer.concat([iv, encrypted, authTag]);
}

async function uploadEncryptedBook(filePath: string) {
  try {
    if (!existsSync(filePath)) throw new Error(`文件未找到：${filePath}`);
    console.log("1. 🚀 开始处理文件...");

    const secretKey = randomBytes(32);
    console.log("2. 🔑 已生成随机加密密钥 (SK)。");

    const fileBuffer = readFileSync(filePath);
    console.log("3. 📖 文件读取完成。");

    const encryptedBuffer = encrypt(fileBuffer, secretKey);
    console.log("4. 🔒 文件加密完成。");

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

    console.log(`5. ☁️ 正在上传文件到 R2 存储桶 "${R2_BUCKET_NAME}"...`);
    await s3Client.send(new PutObjectCommand(uploadParams));
    console.log("6. ✅ 文件上传成功！");

    console.log("\n--- ✨ 处理结果 ✨ ---");
    console.log(`🔑 随机加密 SK (请妥善保管): ${secretKey.toString("hex")}`);
    console.log(`📄 R2 File Key: ${fileKey}`);
    console.log("------------------------\n");
    console.log("⚠️ 重要提示：请将 SK 和 File Key 更新到您的数据库中。");

  } catch (error) {
    if (error instanceof Error) console.error("\n❌ 处理过程中发生错误:", error.message);
    else console.error("\n❌ 发生未知错误:", error);
  }
}

const bookPath = process.argv[2];
if (!bookPath) {
  console.log("\n用法: tsx src/upload.ts <文件路径>");
  console.log("示例: tsx src/upload.ts ./books/my-book.pdf\n");
} else {
  uploadEncryptedBook(bookPath);
}

    

