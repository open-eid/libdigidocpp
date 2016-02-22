// Copyright (C) AS Sertifitseerimiskeskus
// This software is released under the BSD License (see LICENSE.BSD)

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using digidoc;

namespace DigiDocCSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Missing document parameter");
                help();
                return;
            }

            switch (args[0])
            {
                case "extract": extract(Convert.ToInt32(args[1]), args[2]); return;
                case "sign": sign(args); return;
                case "websign": websign(args); return;
                case "verify": verify(args[1]); return;
                case "version": version(); return;
                case "help":
                default: help(); return;
            }
        }

        static void extract(int index, string file)
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

        static void help()
        {
            Console.WriteLine("DigiDocCSharp command [params]");
            Console.WriteLine("Command:");
            Console.WriteLine(" extract\tExtracts files from document");
            Console.WriteLine("    num");
            Console.WriteLine("    file");
            Console.WriteLine(" help\t\tPrints utility commands");
            Console.WriteLine(" sign\t\tSigns file");
            Console.WriteLine("    datafile1 datafile2 ...");
            Console.WriteLine("    file");
            Console.WriteLine(" websign\t\tSigns file");
            Console.WriteLine("    datafile1 datafile2 ...");
            Console.WriteLine("    cert");
            Console.WriteLine("    file");
            Console.WriteLine(" verify\t\tVerifies document signature and shows info");
            Console.WriteLine("    file");
            Console.WriteLine(" version\tPrints utility version");
            version();
        }

        static void sign(string[] args)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Creating file: " + args[args.Length-1]);
                Container b = Container.create(args[args.Length - 1]);
                for (int i = 1; i < args.Length - 1; ++i)
                    b.addDataFile(args[i], "application/octet-stream");
                using (WinSigner signer = new WinSigner())
                    b.sign(signer);
                b.save();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            digidoc.digidoc.terminate();
        }

        static void websign(string[] args)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Creating file: " + args[args.Length - 1]);
                Container b = Container.create(args[args.Length - 1]);
                for (int i = 1; i < args.Length - 2; ++i)
                    b.addDataFile(args[i], "application/octet-stream");

                X509Certificate cert = new X509Certificate();
                cert.Import(args[args.Length - 2]);
                Signature c = b.prepareWebSignature(cert.Export(X509ContentType.Cert), "BES/time-stamp");
                Console.WriteLine("Signature method: " + c.signatureMethod());
                Console.WriteLine("Digest to sign: " + BitConverter.ToString(c.dataToSign()).Replace("-", string.Empty));
                Console.WriteLine("Please enter signed digest in hex: ");

                byte[] inputBuffer = new byte[1024];
                Stream inputStream = Console.OpenStandardInput(inputBuffer.Length);
                Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));
                String hex = Console.ReadLine();

                byte[] signature = Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16)).ToArray();
                c.setSignatureValue(signature);
                c.extendSignatureProfile("BES/time-stamp");
                b.save();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            digidoc.digidoc.terminate();
        }

        static void verify(string file)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Opening file: " + file);
                Container b = Container.open(file);

                Console.WriteLine("Files:");
                foreach (DataFile d in b.dataFiles())
                    Console.WriteLine(" {0} - {1}", d.fileName(), d.mediaType());
                Console.WriteLine();

                Console.WriteLine("Signatures:");
                foreach (Signature s in b.signatures())
                {
                    Console.WriteLine("Address: {0} {1} {2} {3}", s.city(), s.countryName(), s.stateOrProvince(), s.postalCode());

                    Console.Write("Role:");
                    foreach (String role in s.signerRoles())
                        Console.Write(" " + role);
                    Console.WriteLine();

                    Console.WriteLine("Time: " + s.trustedSigningTime());
                    Console.WriteLine("Cert: " + new X509Certificate2(s.signingCertificateDer()).Subject);

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

        static void version()
        {
            Console.WriteLine("DigiDocCSharp 0.2 libdigidocpp " + digidoc.digidoc.version());
        }
    }
}
