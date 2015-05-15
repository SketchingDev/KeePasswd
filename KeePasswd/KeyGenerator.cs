namespace KeePasswd
{
    using KeePasswd.Header;
    using System;
    using System.IO;
    using System.Security.Cryptography;

    interface IKeyGenerator
    {
        byte[] Generate(params byte[] keys);
    }

    /// <summary>
    /// Generates the master key used to decrypt the database body.
    /// </summary>
    class KeyGenerator : IKeyGenerator, IDisposable
    {
        private readonly SHA256Managed _sha256;

        private readonly RijndaelManaged _transformAes;

        private readonly ulong _transformRounds;

        private readonly byte[] _masterSeed;

        private readonly ISecurityHeader _header;

        public KeyGenerator(ISecurityHeader header)
        {
            if (header == null)
            {
                throw new ArgumentNullException("header");
            }

            _header = header;
            _transformRounds = header.TransformRounds;
            _masterSeed = header.MasterSeed;

            _sha256 = new SHA256Managed();
            _transformAes = new RijndaelManaged
            {
                Mode = CipherMode.ECB,
                KeySize = 256,
                Key = header.TransformSeed,
                BlockSize = 128
            };
        }

        public byte[] Generate(params byte[] keys)
        {
            byte[] compositeKey = CreateCompositeKey(keys);

            byte[] transformedKey = TransformKey(compositeKey, _transformRounds);

            return SeedKey(_masterSeed, transformedKey);
        }

        private byte[] CreateCompositeKey(params byte[][] keys)
        {
            using (var stream = new MemoryStream())
            {
                foreach (byte[] key in keys)
                {
                    byte[] hashedKey = _sha256.ComputeHash(key);
                    stream.Write(hashedKey, 0, hashedKey.Length);
                }

                return _sha256.ComputeHash(stream.ToArray());
            }
        }

        private byte[] TransformKey(byte[] compositeKey, ulong transformRounds)
        {
            byte[] key = (byte[])compositeKey.Clone();

            using (ICryptoTransform crypto = _transformAes.CreateEncryptor())
            {
                for (ulong i = 0; i < transformRounds; ++i)
                {
                    crypto.TransformBlock(key, 0, 16, key, 0);
                    crypto.TransformBlock(key, 16, 16, key, 16);
                }
            }

            return _sha256.ComputeHash(key);
        }

        private byte[] SeedKey(byte[] masterSeed, byte[] transformedKey)
        {
            using (var stream = new MemoryStream())
            {
                stream.Write(masterSeed, 0, masterSeed.Length);
                stream.Write(transformedKey, 0, transformedKey.Length);

                return _sha256.ComputeHash(stream.ToArray());
            }
        }

        public void Dispose()
        {
            if (_sha256 != null) _sha256.Dispose();
            if (_transformAes != null) _transformAes.Dispose();
        }
    }
}

