namespace KeePasswd.Header
{
    using System;

    public interface ISecurityHeader
    {
        byte[] MasterSeed { get; }

        byte[] EncryptionIv { get; }

        UInt64 TransformRounds { get; }

        byte[] TransformSeed { get; }

        byte[] ExpectedStartBytes { get; }
    }
}
