namespace KeePasswd
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using Mono.Options;

    static class Program
    {
        private static bool _showHelp;

        private static bool _showHeader;

        private static string _filePath;

        private static string _passwords;

        static void Main(string[] args)
        {
            var optionSet = new OptionSet
            {
                {"file=|f=", "Path to the KeePass2 KDBX database (required)", v => _filePath = v},
                {"passwords=|p=", "Comma separated list of passwords to try (required)", v => _passwords = v},
                {"header", "Shows the header of the database file", v => _showHeader = (v != null)},
                {"h|?|help", "Prints out the options", v => _showHelp = (v != null)}
            };

            try
            {
                optionSet.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Error.Write(e.Message);
                ShowUsage(optionSet);
                return;
            }

            if (_showHelp || args.Length < 2)
            {
                ShowUsage(optionSet);
                Console.ReadLine();
                return;
            }

            // Get input stream
            Stream stream;
            try
            {
                stream = new FileStream(_filePath, FileMode.Open);
            }
            catch (Exception e)
            {
                Console.Error.Write(e.Message);
                return;
            }

            // Process database
            try
            {
                KdbxHeader header = KdbxHeader.Create(stream);
                if (_showHeader)
                {
                    Console.Write(header);
                    return;
                }

                TryPasswords(stream, header, _passwords.Split(','));
            }
            catch (Exception e)
            {
                Console.Error.Write(e.Message);
            }
            finally
            {
                stream.Dispose();
            }
        }

        static void ShowUsage(OptionSet optionSet)
        {
            Console.WriteLine("KeePasswd");
            optionSet.WriteOptionDescriptions(Console.Out);
        }

        static void TryPasswords(Stream stream, KdbxHeader header, IReadOnlyCollection<string> passwords)
        {
            using (var keyFactory = new KeyFactory(header))
            {
                long startOfStream = stream.Position;
                foreach (string password in passwords)
                {
                    stream.Position = startOfStream;

                    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                    byte[] key = keyFactory.CreateKey(passwordBytes);

                    if (Authenticate(stream, header, key))
                    {
                        Console.WriteLine("The password is '{0}'", password);
                        return;
                    }
                }

                Console.WriteLine("The {0} password(s) were all wrong.", passwords.Count);
            }
        }

        static bool Authenticate(Stream stream, KdbxHeader header, byte[] key)
        {
            Stream decryptedStream = CreatedStreamDecryptor(stream, key, header.EncryptionIv);

            // Compare Expected Start Bytes to Decrypted Bytes
            int startBytesLength = header.ExpectedStartBytes.Length;
            byte[] decryptedBytes = new byte[startBytesLength];

            decryptedStream.Read(decryptedBytes, 0, startBytesLength);

            return decryptedBytes.ArrayEquals(header.ExpectedStartBytes);
        }

        static Stream CreatedStreamDecryptor(Stream stream, byte[] masterKey, byte[] encryptionIv)
        {
            var rijndael2 = new RijndaelManaged
            {
                BlockSize = 128,
                IV = encryptionIv,
                KeySize = 256,
                Key = masterKey,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            ICryptoTransform decryptor = rijndael2.CreateDecryptor();

            return new CryptoStream(stream, decryptor, CryptoStreamMode.Read);
        }

        static bool ArrayEquals(this byte[] one, byte[] two)
        {
            if (one.Length != two.Length) return false;

            int total = one.Length;
            for (int i = 0; i < total; i++)
            {
                if (one[i] != two[i]) return false;
            }

            return true;
        }
    }
}
