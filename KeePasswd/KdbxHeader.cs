namespace KeePasswd
{
    using System;
    using System.IO;

    class KdbxHeader
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

        public byte[] MasterSeed { get; set; }

        public byte[] EncryptionIv { get; set; }

        public UInt64 TransformRounds { get; set; }

        public byte[] TransformSeed { get; set; }

        public byte[] ExpectedStartBytes { get; set; }

        public static KdbxHeader Create(Stream stream)
        {
            var header = new KdbxHeader();

            ReadHeader(stream);
            while (true)
            {
                if (ReadHeaderField(stream, header) == false) break;
            }

            return header;
        }

        private static void ReadHeader(Stream stream)
        {
            // Read signatures
            byte[] signatureData = new byte[4];

            stream.Read(signatureData, 0, 4);
            UInt32 signatureOne = MemUtil.BytesToUInt32(signatureData);

            stream.Read(signatureData, 0, 4);
            UInt32 signatureTwo = MemUtil.BytesToUInt32(signatureData);

            if ((signatureOne != FileSignature1 || signatureTwo != FileSignature2) &&
                (signatureOne != FileSignaturePreRelease1 || signatureTwo != FileSignaturePreRelease2))
                throw new Exception("Invalid file signature.\nCheck that this is a KDBX database created using KeePass 2.x");

            // Read DB version
            byte[] dbVersionData = new byte[4];
            stream.Read(dbVersionData, 0, 4);

            UInt32 databaseVersion = MemUtil.BytesToUInt32(dbVersionData);
        }

        private static bool ReadHeaderField(Stream stream, KdbxHeader header)
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
                    header.MasterSeed = data;
                    break;
                case 5: // Transform Seed
                    header.TransformSeed = data;
                    break;
                case 6: // Transform Rounds
                    header.TransformRounds = MemUtil.BytesToUInt64(data);
                    break;
                case 7: // Encryption IV
                    header.EncryptionIv = data;
                    break;
                case 9: // Stream Start Bytes
                    header.ExpectedStartBytes = data;
                    break;
            }

            return result;
        }

        public override string ToString()
        {
            string output = "Master Seed: " + (MemUtil.ByteArrayToHexString(MasterSeed) ?? "None");
            output += "\nEncryption IV: " + (MemUtil.ByteArrayToHexString(EncryptionIv) ?? "None");
            output += "\nTransform Rounds: " + TransformRounds;
            output += "\nTransform Seed: " + (MemUtil.ByteArrayToHexString(TransformSeed) ?? "None");
            output += "\nExpected Start-Bytes: " + (MemUtil.ByteArrayToHexString(ExpectedStartBytes) ?? "None");

            return output;
        }
    }
}
