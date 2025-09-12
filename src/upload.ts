// src/upload.ts

import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { randomBytes, createCipheriv } from "crypto";
import { readFileSync, existsSync } from "fs";
import path from "path";
import "dotenv/config"; // 自动加载 .env 文件

// --- 配置加载与校验 ---
const {
  R2_ACCOUNT_ID,
  R2_ACCESS_KEY_ID,
  R2_SECRET_ACCESS_KEY,
  R2_BUCKET_NAME,
} = process.env;
console.log(process.env.DATABASE_URL);
if (
  !R2_ACCOUNT_ID ||
  !R2_ACCESS_KEY_ID ||
  !R2_SECRET_ACCESS_KEY ||
  !R2_BUCKET_NAME
) {
  console.log(R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME);
  console.error("❌ 错误：请检查 .env 文件中的 R2 配置是否完整。");
  process.exit(1);
}

const R2_ENDPOINT = `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;

// --- 加密函数 ---

/**
 * 使用 AES-256-GCM 加密文件缓冲区
 * @param buffer - 要加密的文件内容
 * @param key - 256位 (32字节) 的密钥
 * @returns 加密后的缓冲区 (格式: iv + authTag + encryptedData)
 */
function encrypt(buffer: Buffer, key: Buffer): Buffer {
  // 生成一个随机的16字节初始化向量 (IV)
  const iv = randomBytes(16);
  // 创建加密器实例，指定算法、密钥和IV
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  
  // 加密数据
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  // 获取认证标签 (Auth Tag)，GCM模式下必须获取
  const authTag = cipher.getAuthTag();

  // 按照 IV -> AuthTag -> EncryptedData 的顺序拼接，方便解密时分离
  return Buffer.concat([iv, authTag, encrypted]);
}

// --- 主函数 ---
async function uploadEncryptedBook(filePath: string) {
  try {
    // 1. 校验文件路径
    if (!existsSync(filePath)) {
      throw new Error(`文件未找到：${filePath}`);
    }

    console.log("1. 🚀 开始处理文件...");

    // 2. 生成随机加密密钥 (Secret Key)
    const secretKey = randomBytes(32); // 32 bytes = 256 bits
    console.log("2. 🔑 已生成随机加密密钥 (SK)。");

    // 3. 读取本地文件
    const fileBuffer = readFileSync(filePath);
    console.log("3. 📖 文件读取完成。");

    // 4. 加密文件
    const encryptedBuffer = encrypt(fileBuffer, secretKey);
    console.log("4. 🔒 文件加密完成。");

    // 5. 初始化 R2 客户端
    const s3Client = new S3Client({
      region: "auto",
      endpoint: R2_ENDPOINT,
      credentials: {
        accessKeyId: R2_ACCESS_KEY_ID as string,
        secretAccessKey: R2_SECRET_ACCESS_KEY as string,
      },
    });

    // 6. 准备上传参数
    const originalFileName = path.basename(filePath, path.extname(filePath));
    const fileExtension = path.extname(filePath);
    const fileKey = `${originalFileName}_${Date.now()}${fileExtension}.encrypted`;

    const uploadParams = {
      Bucket: R2_BUCKET_NAME,
      Key: fileKey,
      Body: encryptedBuffer,
      ContentType: "application/octet-stream", // 加密文件使用通用的二进制流类型
    };

    // 7. 执行上传
    console.log(`5. ☁️ 正在上传文件到 R2 存储桶 "${R2_BUCKET_NAME}"...`);
    await s3Client.send(new PutObjectCommand(uploadParams));
    console.log("6. ✅ 文件上传成功！");

    // 8. 打印重要信息
    console.log("\n--- ✨ 处理结果 ✨ ---");
    console.log(`🔑 随机加密 SK (请妥善保管): ${secretKey.toString("hex")}`);
    console.log(`📄 R2 File Key: ${fileKey}`);
    console.log("------------------------\n");
    console.log(
      "⚠️ 重要提示：请务必安全地存储 SK，它是解密文件的唯一凭证。丢失后文件将无法恢复。"
    );

  } catch (error) {
    if (error instanceof Error) {
      console.error("\n❌ 处理过程中发生错误:", error.message);
    } else {
      console.error("\n❌ 发生未知错误:", error);
    }
  }
}

// --- 脚本入口 ---
// process.argv[0] 是 node 执行程序路径
// process.argv[1] 是脚本文件路径
const bookPath = process.argv[2];

if (!bookPath) {
  console.log("\nerror: 请输入图书的完整路径");
} else {
  await uploadEncryptedBook(bookPath);
}