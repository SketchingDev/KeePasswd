namespace KeePasswd
{
    using KeePasswd.Header;
    using System;
    using System.IO;

    class InvalidSignatureException : Exception 
    {
        public InvalidSignatureException (string message) : base(message){}
    }

    class StreamHeader : ISecurityHeader
    {
        /// <summary>
        /// File identifier, first 32-bit value.
        /// </summary>
        private const uint FileSignature1 = 0x9AA2D903;

        /// <summary>
        /// File identifier, second 32-bit value.
        /// </summary>
        private const uint FileSignature2 = 0xB54BFB67;

        // KeePass 2.x pre-release (alpha and beta) signature
        private const uint FileSignaturePreRelease1 = 0x9AA2D903;
        private const uint FileSignaturePreRelease2 = 0xB54BFB66;

        public byte[] MasterSeed { get; private set; }

        public byte[] EncryptionIv { get; private set; }

        public UInt64 TransformRounds { get; private set; }

        public byte[] TransformSeed { get; private set; }

        public byte[] ExpectedStartBytes { get; private set; }

        public StreamHeader(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            ReadSignatures(stream);
            while (true)
            {
                if (ReadField(stream) == false) break;
            }
        }

        private void ReadSignatures(Stream stream)
        {
            // Read signatures
            byte[] signatureData = new byte[4];

            stream.Read(signatureData, 0, 4);
            UInt32 signatureOne = MemUtil.BytesToUInt32(signatureData);

            stream.Read(signatureData, 0, 4);
            UInt32 signatureTwo = MemUtil.BytesToUInt32(signatureData);

            if ((signatureOne != FileSignature1 || signatureTwo != FileSignature2) &&
                (signatureOne != FileSignaturePreRelease1 || signatureTwo != FileSignaturePreRelease2))
                throw new InvalidSignatureException("Invalid file signature.\nCheck that this is a KDBX database created using KeePass 2.x");

            // Read DB version
            byte[] dbVersionData = new byte[4];
            stream.Read(dbVersionData, 0, 4);

            UInt32 databaseVersion = MemUtil.BytesToUInt32(dbVersionData);
        }

        private bool ReadField(Stream stream)
        {
            int fieldId = stream.ReadByte();

            byte[] fieldSizeRaw = new byte[2];
            stream.Read(fieldSizeRaw, 0, 2);

            UInt16 fieldSize = MemUtil.BytesToUInt16(fieldSizeRaw);

            byte[] data = new byte[fieldSize];
            stream.Read(data, 0, fieldSize);

            bool result = true;
            switch (fieldId)
            {
                case 0: // End Of Header
                    result = false;
                    break;
                case 4: // Master Seed
                    MasterSeed = data;
                    break;
                case 5: // Transform Seed
                    TransformSeed = data;
                    break;
                case 6: // Transform Rounds
                    TransformRounds = MemUtil.BytesToUInt64(data);
                    break;
                case 7: // Encryption IV
                    EncryptionIv = data;
                    break;
                case 9: // Stream Start Bytes
                    ExpectedStartBytes = data;
                    break;
            }

            return result;
        }
    }
}

