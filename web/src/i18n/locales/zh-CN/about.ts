export default {
  title: '关于 gpg4web',
  intro:
    'gpg4web 是一个完全在您的浏览器中运行的完整 OpenPGP 客户端。所有加密运算均由编译为 WebAssembly 的 Rust 内核在本地完成 —— 任何密钥材料、口令或明文都不会离开您的设备。',
  cryptoCore: '加密内核',
  features: '功能',
  feature1: '生成密钥对：Curve25519、Ed25519、RSA、NIST 曲线',
  feature2: '🛡 后量子 OpenPGP 密钥（IETF 草案）：ML-DSA、SLH-DSA、ML-KEM',
  feature3: '向一个或多个收件人加密与解密消息',
  feature4: '对文件进行签名 / 加密 / 解密 / 验证（二进制或 ASCII 装甲格式）',
  feature5: '内嵌、分离及明文签名 + 验证',
  feature6: '导入 / 导出 ASCII 装甲密钥，以及可移植的 .gnupg 主目录归档',
  feature7: '可在桌面端和移动端使用',
  pqVault: '后量子保险库',
  pqVaultIntro: '您的密钥环存储在 localStorage 中，并以后量子信封密封：',
  pqVault1: 'ML-KEM-768（NIST FIPS 203）在每次保存时封装一个全新的数据密钥',
  pqVault2: 'AES-256-GCM 对载荷进行加密',
  pqVault3: 'Argon2id 使用您的主密码密封 KEM 私钥',
  pqVaultHint:
    '即便攻击者获取了您的存储数据块，也必须同时攻破 Argon2id 和 ML-KEM —— 二者都无法被量子计算机破解。',
  sourceLicense: '源代码与许可证',
  sourceLicenseBody:
    'gpg4web 是自由软件，依据 GNU 通用公共许可证 v3.0（或更高版本）发布。完整源代码已在 GitHub 上公开 —— 欢迎贡献代码与安全审计。',
  builtWith: '技术栈',
}
