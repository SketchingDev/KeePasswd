namespace KeePasswd.Header
{
    using System;
    using System.IO;

    class HeaderOutput
    {
        private TextWriter _textWriter;

        public HeaderOutput(TextWriter textWriter)
        {
            if (textWriter == null)
            {
                throw new ArgumentNullException("textWriter");
            }

            this._textWriter = textWriter;
        }

        public void Write(ISecurityHeader header)
        {
            if (header == null)
            {
                throw new ArgumentNullException("header");
            }

            this._textWriter.WriteLine("Master Seed: " + (MemUtil.ByteArrayToHexString(header.MasterSeed) ?? "None"));
            this._textWriter.WriteLine("Encryption IV: " + (MemUtil.ByteArrayToHexString(header.EncryptionIv) ?? "None"));
            this._textWriter.WriteLine("Transform Rounds: " + header.TransformRounds);
            this._textWriter.WriteLine("Transform Seed: " + (MemUtil.ByteArrayToHexString(header.TransformSeed) ?? "None"));
            this._textWriter.WriteLine("Expected Start-Bytes: " + (MemUtil.ByteArrayToHexString(header.ExpectedStartBytes) ?? "None"));
        }
    }
}
