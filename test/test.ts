import * as nist from '@noble/curves/nist.js';

// 使用内部曲线对象
const ProjectivePoint = (nist as any).p256_Point.ProjectivePoint;

// 未压缩公钥 Hex
const pubHex = "04" +
  "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
  "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

const point = ProjectivePoint.fromHex(pubHex);
const x = point.x.toBigInt();
const y = point.y.toBigInt();

console.log("x:", x.toString());
console.log("y:", y.toString());
