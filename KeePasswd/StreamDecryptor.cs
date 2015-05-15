namespace KeePasswd
{
    using KeePasswd.Header;
    using System;
    using System.IO;
    using System.Security.Cryptography;

    interface IStreamDecryptor
    {
        Stream CreateDecryptStream(Stream stream, byte[] key);
    }

    class StreamDecryptor : IStreamDecryptor
    {
        private readonly ISecurityHeader _header;

        public StreamDecryptor(ISecurityHeader header)
        {
            if (header == null)
            {
                throw new ArgumentNullException("header");
            }

            this._header = header;
        }

        public Stream CreateDecryptStream(Stream stream, byte[] key)
        {
            if (stream== null || key == null)
            {
                throw new ArgumentNullException();
            }

            var rijndael2 = new RijndaelManaged
            {
                BlockSize = 128,
                IV = _header.EncryptionIv,
                KeySize = 256,
                Key = key,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            ICryptoTransform decryptor = rijndael2.CreateDecryptor();

            return new CryptoStream(stream, decryptor, CryptoStreamMode.Read);
        }
    }
}
