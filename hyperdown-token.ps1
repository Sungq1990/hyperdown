<#
.SYNOPSIS
  解密 Hyperdown 本地加密文件（session.json / netdisk-cookies.json）并打印明文。

.DESCRIPTION
  密钥来自 Windows 凭据管理器：
    目标: Hyperdown Local Vault:file-encryption-key-v1
  文件格式:
    hyperdown-local-vault:v1: + base64( 12字节 nonce + AES-256-GCM 密文 + 16字节 tag )
  AAD 为前缀字符串 "hyperdown-local-vault:v1:"。

  仅需 Windows PowerShell 5.1（无需 Python、无需安装任何模块）。

.PARAMETER Path
  要解密的文件路径。省略时默认尝试 D:\Hyperdown\data\session.json。

.PARAMETER WriteState
  可选。解密后把 access_token / refresh_token 写入签到脚本使用的状态文件
  (~/.hyperdown_checkin.json)。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\hyperdown-token.ps1 D:\Hyperdown\data\session.json

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\hyperdown-token.ps1 D:\Hyperdown\data\session.json -WriteState
#>

param(
    [Parameter(Position = 0)]
    [string]$Path,

    [switch]$WriteState
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$PREFIX = 'hyperdown-local-vault:v1:'
$CRED_TARGET = 'Hyperdown Local Vault:file-encryption-key-v1'

if (-not $Path) {
    $Path = 'D:\Hyperdown\data\session.json'
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "请提供加密文件路径，例如: powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" D:\Hyperdown\data\session.json"
    }
}

if (-not (Test-Path -LiteralPath $Path)) {
    throw "文件不存在: $Path"
}

# ------------------------------------------------------------------ C# 帮助类
$cs = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class HdVaultCred
{
    [StructLayout(LayoutKind.Sequential)]
    public struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredEnumerate(string filter, uint flags, out uint count, out IntPtr credentials);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern void CredFree(IntPtr buffer);

    private static string BlobToText(CREDENTIAL cred)
    {
        if (cred.CredentialBlobSize == 0 || cred.CredentialBlob == IntPtr.Zero)
            return string.Empty;
        byte[] blob = new byte[cred.CredentialBlobSize];
        Marshal.Copy(cred.CredentialBlob, blob, 0, blob.Length);
        return Encoding.UTF8.GetString(blob).Trim();
    }

    public static string GetSecret(string target)
    {
        IntPtr ptr;
        if (CredRead(target, 1, 0, out ptr))
        {
            try
            {
                CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
                return BlobToText(cred);
            }
            finally { CredFree(ptr); }
        }

        // 精确目标不存在时，枚举所有凭据找 Hyperdown Local Vault 相关项。
        uint count;
        IntPtr list;
        if (CredEnumerate(null, 0, out count, out list))
        {
            try
            {
                for (uint i = 0; i < count; i++)
                {
                    IntPtr item = Marshal.ReadIntPtr(list, (int)(i * IntPtr.Size));
                    CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(item, typeof(CREDENTIAL));
                    if (cred.TargetName != null &&
                        cred.TargetName.IndexOf("Hyperdown Local Vault", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        string secret = BlobToText(cred);
                        if (secret.Length > 0)
                            return secret;
                    }
                }
            }
            finally { CredFree(list); }
        }

        throw new Exception("未找到 Windows 凭据: " + target + "。请确认 Hyperdown 客户端至少登录过一次。");
    }
}

public static class HdVaultAesGcm
{
    [StructLayout(LayoutKind.Sequential)]
    private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public long cbData;
        public int dwFlags;
    }

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

    private static string Err(string where, int status)
    {
        return where + " 失败, NTSTATUS=0x" + status.ToString("X8");
    }

    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] aad)
    {
        IntPtr alg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        IntPtr pNonce = IntPtr.Zero;
        IntPtr pAad = IntPtr.Zero;
        IntPtr pTag = IntPtr.Zero;

        try
        {
            int st = BCryptOpenAlgorithmProvider(out alg, "AES", null, 0);
            if (st != 0) throw new Exception(Err("BCryptOpenAlgorithmProvider", st));

            byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            st = BCryptSetProperty(alg, "ChainingMode", mode, mode.Length, 0);
            if (st != 0) throw new Exception(Err("BCryptSetProperty(ChainingModeGCM)", st));

            st = BCryptGenerateSymmetricKey(alg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (st != 0) throw new Exception(Err("BCryptGenerateSymmetricKey", st));

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            info.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            info.dwInfoVersion = 1;

            pNonce = Marshal.AllocHGlobal(nonce.Length);
            Marshal.Copy(nonce, 0, pNonce, nonce.Length);
            info.pbNonce = pNonce;
            info.cbNonce = nonce.Length;

            pAad = Marshal.AllocHGlobal(Math.Max(1, aad.Length));
            if (aad.Length > 0) Marshal.Copy(aad, 0, pAad, aad.Length);
            info.pbAuthData = pAad;
            info.cbAuthData = aad.Length;

            pTag = Marshal.AllocHGlobal(tag.Length);
            Marshal.Copy(tag, 0, pTag, tag.Length);
            info.pbTag = pTag;
            info.cbTag = tag.Length;

            byte[] output = new byte[ciphertext.Length];
            int written = 0;
            st = BCryptDecrypt(hKey, ciphertext, ciphertext.Length, ref info, null, 0,
                               output, output.Length, out written, 0);
            if (st != 0)
                throw new Exception(Err("BCryptDecrypt", st) + "（密钥、AAD 或 tag 不匹配）");

            if (written != output.Length)
            {
                byte[] trimmed = new byte[written];
                Array.Copy(output, trimmed, written);
                return trimmed;
            }
            return output;
        }
        finally
        {
            if (pNonce != IntPtr.Zero) Marshal.FreeHGlobal(pNonce);
            if (pAad != IntPtr.Zero) Marshal.FreeHGlobal(pAad);
            if (pTag != IntPtr.Zero) Marshal.FreeHGlobal(pTag);
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (alg != IntPtr.Zero) BCryptCloseAlgorithmProvider(alg, 0);
        }
    }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp

# ------------------------------------------------------------------ 解密
$raw = (Get-Content -LiteralPath $Path -Raw).Trim()
if (-not $raw.StartsWith($PREFIX)) {
    throw "不是 Hyperdown vault 格式（缺少前缀 $PREFIX）: $Path"
}

$payloadB64 = $raw.Substring($PREFIX.Length).Trim()
$payloadB64 += ('=' * ((4 - $payloadB64.Length % 4) % 4))
$payload = [Convert]::FromBase64String($payloadB64)
if ($payload.Length -lt 12 + 16) {
    throw "密文长度异常: $($payload.Length) 字节"
}

[byte[]]$nonce = $payload[0..11]
[byte[]]$tag = $payload[($payload.Length - 16)..($payload.Length - 1)]
[byte[]]$ct = $payload[12..($payload.Length - 17)]

$keyText = [HdVaultCred]::GetSecret($CRED_TARGET).Trim()
$keyText += ('=' * ((4 - $keyText.Length % 4) % 4))
$key = [Convert]::FromBase64String($keyText)
if ($key.Length -ne 32) {
    throw "凭据中的密钥长度异常: $($key.Length) 字节（期望 32）"
}

$aad = [System.Text.Encoding]::UTF8.GetBytes($PREFIX)
[byte[]]$plain = [HdVaultAesGcm]::Decrypt($key, $nonce, $ct, $tag, $aad)
$text = [System.Text.Encoding]::UTF8.GetString($plain)

Write-Output "===== 解密结果: $Path ====="
try {
    $obj = $text | ConvertFrom-Json
    Write-Output ($obj | ConvertTo-Json -Depth 20)
}
catch {
    Write-Output $text
}

# ------------------------------------------------------------------ 可选：同步签到状态
if ($WriteState) {
    $obj = $text | ConvertFrom-Json
    if (-not $obj.access_token -or -not $obj.refresh_token) {
        throw "解密内容里没有 access_token / refresh_token，无法写入签到状态。"
    }
    $statePath = Join-Path $HOME '.hyperdown_checkin.json'
    $state = [ordered]@{
        access_token             = $obj.access_token
        refresh_token            = $obj.refresh_token
        access_token_expires_at  = $obj.access_token_expires_at
        refresh_token_expires_at = $obj.refresh_token_expires_at
    }
    $json = $state | ConvertTo-Json
    [System.IO.File]::WriteAllText($statePath, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ""
    Write-Output "已同步到签到状态文件: $statePath"
}
