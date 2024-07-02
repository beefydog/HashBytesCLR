using System;
using System.Data.SqlTypes;
using System.Security.Cryptography;
using Microsoft.SqlServer.Server;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

public class XHASHBYTES
{
    [SqlFunction(IsDeterministic = true, IsPrecise = true)]
    public static SqlBinary ComputeHash(SqlString algorithm, SqlBytes input)
    {
        if (algorithm.IsNull || input.IsNull)
        {
            return SqlBinary.Null;
        }

        byte[] inputData = input.Value;
        byte[] hashBytes;

        switch (algorithm.Value.ToUpper())
        {
            case "MD2":
                hashBytes = ComputeBCHash(new MD2Digest(), inputData);
                break;
            case "MD4":
                hashBytes = ComputeBCHash(new MD4Digest(), inputData);
                break;
            case "MD5":
                //hashBytes = MD5.Create().ComputeHash(inputData);
                hashBytes = ComputeBCHash(new MD5Digest(), inputData);
                break;
            case "SHA-1":
               // hashBytes = SHA1.Create().ComputeHash(inputData);
                hashBytes = ComputeBCHash(new Sha1Digest(), inputData);
                break;
            case "SHA-224":
                hashBytes = ComputeBCHash(new Sha224Digest(), inputData);
                break;
            case "SHA-256":
               // hashBytes = SHA256.Create().ComputeHash(inputData);
               hashBytes = ComputeBCHash(new Sha256Digest(), inputData);
                break;
            case "SHA-384":
                // hashBytes = SHA384.Create().ComputeHash(inputData);
                hashBytes = ComputeBCHash(new Sha384Digest(), inputData);
                break;
            case "SHA-512":
                //  hashBytes = SHA512.Create().ComputeHash(inputData);
                hashBytes = ComputeBCHash(new Sha512Digest(), inputData);
                break;
            case "SHA-512/224":
                hashBytes = ComputeBCHash(new Sha512tDigest(224), inputData);
                break;
            case "SHA-512/256":
                hashBytes = ComputeBCHash(new Sha512tDigest(256), inputData);
                break;
            case "SHA3-224":
                hashBytes = ComputeBCHash(new Sha3Digest(224), inputData);
                break;
            case "SHA3-256":
                hashBytes = ComputeBCHash(new Sha3Digest(256), inputData);
                break;
            case "SHA3-384":
                hashBytes = ComputeBCHash(new Sha3Digest(384), inputData);
                break;
            case "SHA3-512":
                hashBytes = ComputeBCHash(new Sha3Digest(512), inputData);
                break;
            default:
                throw new ArgumentException("Available algorithms: MD2,MD4,MD5,SHA-1,SHA-224,SHA-256,SHA-384,SHA-512,SHA-512/224,SHA-512/256,SHA3-224,SHA3-256,SHA3-384,SHA3-512");
        }

        return new SqlBinary(hashBytes);
    }

    private static byte[] ComputeBCHash(IDigest digest, byte[] input)
    {
        digest.BlockUpdate(input, 0, input.Length);
        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }
}
