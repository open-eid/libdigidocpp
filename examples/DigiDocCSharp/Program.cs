// Copyright (C) AS Sertifitseerimiskeskus
// This software is released under the BSD License (see LICENSE.BSD)

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using digidoc;

namespace DigiDocCSharp
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Missing document parameter");
                Help();
                return;
            }

            switch (args[0])
            {
                case "add": Add(args); return;
                case "extract": Extract(Convert.ToInt32(args[1]), args[2]); return;
                case "sign": Sign(args); return;
                case "websign": Websign(args); return;
                case "verify": Verify(args[1]); return;
                case "version": Version(); return;
                case "help":
                default: Help(); return;
            }
        }

        private static void Add(string[] args)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Creating file: " + args[args.Length - 1]);
                Container b = Container.create(args[args.Length - 1]);
                for (int i = 1; i < args.Length - 1; ++i)
                {
                    b.addDataFile(args[i], "application/octet-stream");
                }
                b.save();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            digidoc.digidoc.terminate();
        }

        private static void Extract(int index, string file)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Opening file: " + file);
                Container b = Container.open(file);
                DataFile d = b.dataFiles()[index];
                string dest = Path.Combine(Directory.GetCurrentDirectory(), d.fileName());
                Console.WriteLine("Extracting file {0} to {1}", d.fileName(), dest);
                try
                {
                    d.saveAs(dest);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to copy file");
                    Console.WriteLine(e.Message);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            digidoc.digidoc.terminate();
        }

        private static void Help()
        {
            Console.WriteLine("DigiDocCSharp command [params]");
            Console.WriteLine("Command:");
            Console.WriteLine(" help\t\tPrints utility commands");
            Console.WriteLine(" version\tPrints utility version");
            Console.WriteLine(" extract\tExtracts files from document");
            Console.WriteLine("    num");
            Console.WriteLine("    file");
            Console.WriteLine(" add\t\tCreates container with files");
            Console.WriteLine("    datafile1 datafile2 ...");
            Console.WriteLine("    file");
            Console.WriteLine(" sign\t\tSigns file");
#if !_WINDOWS
            Console.WriteLine("    12345");
#endif
            Console.WriteLine("    datafile1 datafile2 ...");
            Console.WriteLine("    file");
            Console.WriteLine(" websign\t\tSigns file");
            Console.WriteLine("    datafile1 datafile2 ...");
            Console.WriteLine("    cert");
            Console.WriteLine("    file");
            Console.WriteLine(" verify\t\tVerifies document signature and shows info");
            Console.WriteLine("    file");
            Version();
        }

        private static void Sign(string[] args)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Creating file: " + args[args.Length - 1]);
                Container b = Container.create(args[args.Length - 1]);
#if _WINDOWS
                for (int i = 1; i < args.Length - 1; ++i)
#else
                for (int i = 2; i < args.Length - 1; ++i)
#endif
                {
                    b.addDataFile(args[i], "application/octet-stream");
                }
#if _WINDOWS
                using (var signer = new WinSigner())
                {
#else
                using (var signer = new PKCS11Signer())
                {
                    signer.setPin(args[1]);
#endif
                    b.sign(signer);
                }
                b.save();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            digidoc.digidoc.terminate();
        }

        private static void Websign(string[] args)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Creating file: " + args[args.Length - 1]);
                Container b = Container.create(args[args.Length - 1]);
                for (int i = 1; i < args.Length - 2; ++i)
                {
                    b.addDataFile(args[i], "application/octet-stream");
                }

                var cert = new X509Certificate(args[args.Length - 2]);
                Signature c = b.prepareWebSignature(cert.Export(X509ContentType.Cert), "time-stamp");
                Console.WriteLine("Signature method: " + c.signatureMethod());
                Console.WriteLine("Digest to sign: " + BitConverter.ToString(c.dataToSign()).Replace("-", string.Empty));
                Console.WriteLine("Please enter signed digest in hex: ");

                byte[] inputBuffer = new byte[1024];
                Stream inputStream = Console.OpenStandardInput(inputBuffer.Length);
                Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));
                string hex = Console.ReadLine();

                byte[] signature = Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16)).ToArray();
                c.setSignatureValue(signature);
                c.extendSignatureProfile("time-stamp");
                b.save();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            digidoc.digidoc.terminate();
        }

        private static void Verify(string file)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Opening file: " + file);
                var cb = new ContainerOpen();
                Container b = Container.open(file, cb);

                Console.WriteLine("Files:");
                foreach (DataFile d in b.dataFiles())
                {
                    Console.WriteLine(" {0} - {1}", d.fileName(), d.mediaType());
                }
                Console.WriteLine();

                Console.WriteLine("Signatures:");
                foreach (Signature s in b.signatures())
                {
                    Console.WriteLine("Address: {0} {1} {2} {3}", s.city(), s.countryName(), s.stateOrProvince(), s.postalCode());

                    Console.Write("Role:");
                    foreach (string role in s.signerRoles())
                    {
                        Console.Write(" " + role);
                    }
                    Console.WriteLine();

                    Console.WriteLine("Time: " + s.trustedSigningTime());
                    Console.WriteLine("Cert: " + s.signingCertificate().Subject);
                    Console.WriteLine("TimeStamp: " + s.TimeStampCertificate().Subject);

                    s.validate();
                    Console.WriteLine("Signature is valid");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Signature is invalid");
                Console.WriteLine(e.Message);
            }
            digidoc.digidoc.terminate();
        }

        private static void Version()
        {
            Console.WriteLine("DigiDocCSharp " + Assembly.GetExecutingAssembly().GetName().Version +
                " libdigidocpp " + digidoc.digidoc.version());
        }
    }

    class ContainerOpen : ContainerOpenCB 
    {
        override public bool validateOnline() { return true; }
    }
}
