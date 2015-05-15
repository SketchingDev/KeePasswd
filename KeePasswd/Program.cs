namespace KeePasswd
{
    using KeePasswd.Header;
    using Mono.Options;
    using System;
    using System.IO;
    using System.Text;

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
                {"header", "Prints the decryption specific fields from the file's header", v => _showHeader = (v != null)},
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
                ISecurityHeader header = new StreamHeader(stream);
                if (_showHeader)
                {
                    (new HeaderOutput(Console.Out)).Write(header);
                    return;
                }

                ProcessPasswords(stream, header, _passwords.Split(','));
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

        private static void ProcessPasswords(Stream stream, ISecurityHeader header, string[] passwords)
        {
            using (var keyGenerator = new KeyGenerator(header))
            {
                var streamDecryptor = new StreamDecryptor(header);

                bool passwordFound = false;
                long expectedStartBytesPosition = stream.Position;
                foreach (string password in passwords)
                {
                    // Generate key from password
                    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                    byte[] key = keyGenerator.Generate(passwordBytes);

                    // Read starting bytes from decrypted stream then reset its position
                    Stream decryptedStream = streamDecryptor.CreateDecryptStream(stream, key);

                    // Check password by comparing decrypted array
                    passwordFound = decryptedStream.BeginsWith(header.ExpectedStartBytes);
                    stream.Position = expectedStartBytesPosition; // Reset stream's position

                    if (passwordFound)
                    {
                        Console.WriteLine("The password is '{0}'", password);
                        break;
                    }
                }

                if (passwordFound == false)
                {
                    Console.WriteLine("Password not found");
                }
            }
        }

        private static void ShowUsage(OptionSet optionSet)
        {
            Console.WriteLine("KeePasswd");
            optionSet.WriteOptionDescriptions(Console.Out);
        }

        private static bool BeginsWith(this Stream stream, byte[] expected)
        {
            int total = expected.Length;
            for (int i = 0; i < total; i++)
            {
                if (expected[i] != stream.ReadByte()) return false;
            }

            return true;
        }
    }
}
