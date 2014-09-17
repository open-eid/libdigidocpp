// Copyright (C) AS Sertifitseerimiskeskus
// This software is released under the BSD License (see LICENSE.BSD)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
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

            int pos = args[0].IndexOf("=");
            switch (pos == -1 ? args[0] : args[0].Substring(0, pos))
            {
                case "-extract":
                    if (pos < 0)
                    {
                        Console.WriteLine("Index must be 0 or greater");
                        help();
                    }
                    else
                        extract(Convert.ToUInt32(args[0].Substring(pos + 1)), args[1]);
                    return;
                case "-verify": verify(args[1]); return;
                case "-version": version(); return;
                case "-help":
                default: help(); return;
            }
        }

        static void extract(uint index, string file)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Opening file: " + file);
                WDoc b = new WDoc(file);
                if (index < b.documentCount())
                {
                    Document d = b.getDocument(index);
                    string dest = Path.Combine(Directory.GetCurrentDirectory(), d.getFileName());
                    Console.WriteLine("Extracting file {0} to {1}", d.getFileName(), dest);
                    try
                    {
                        File.Copy(d.getFilePath(), dest);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Failed to copy file");
                        Console.WriteLine(e.Message);
                    }
                }
                else
                    Console.WriteLine("No such document");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            digidoc.digidoc.terminate();
        }

        static void help()
        {
            Console.WriteLine("DigiDocCSharpt [[command] file]");
            Console.WriteLine("Command:");
            Console.WriteLine(" -extract=[num]\tExtracts files from document");
            Console.WriteLine(" -help\t\tPrints utility commands");
            Console.WriteLine(" -verify\tVerifies document signature and shows info");
            Console.WriteLine(" -version\tPrints utility version");
            version();
        }

        static void verify(string file)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Opening file: " + file);
                WDoc b = new WDoc(file);

                Console.WriteLine("Files:");
                for (uint i = 0; i < b.documentCount(); ++i)
                {
                    Document d = b.getDocument(i);
                    Console.WriteLine(" {0} - {1}", i, d.getFileName());
                }
                Console.WriteLine();

                Console.WriteLine("Signatures:");
                for (uint i = 0; i < b.signatureCount(); ++i)
                {
                    Signature s = b.getSignature(i);

                    SignatureProductionPlace p = s.getProductionPlace();
                    Console.WriteLine("Address: {0} {1} {2} {3}", p.city, p.countryName, p.stateOrProvince, p.postalCode);

                    SignerRole r = s.getSignerRole();
                    Console.Write("Role:");
                    for (int j = 0; j < r.claimedRoles.Count; ++j)
                        Console.Write(" " + r.claimedRoles[j]);
                    Console.WriteLine();

                    Console.WriteLine("Time: " + s.getSigningTime());

                    System.Security.Cryptography.X509Certificates.X509Certificate2 c =
                        new System.Security.Cryptography.X509Certificates.X509Certificate2(s.getSigningCert());
                    Console.WriteLine("Cert: " + c.Subject);
                    try
                    {
                        s.validateOffline();
                        Console.WriteLine("Signature is valid");
                    }
                    catch (DigidocSignatureException e)
                    {
                        Console.WriteLine("Signature is invalid");
                        Console.WriteLine(e.Message);
                    }
                }
            }
            catch (DigidocBDocException e)
            {
                Console.WriteLine(e.Message);
            }
            catch (DigidocIOException e)
            {
                Console.WriteLine(e.Message);
            }
            catch (DigidocSignException e)
            {
                Console.WriteLine(e.Message);
            }
            catch (DigidocSignatureException e)
            {
                Console.WriteLine(e.Message);
            }
            catch (DigidocException e)
            {
                Console.WriteLine(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            digidoc.digidoc.terminate();
        }

        static void version()
        {
            Console.WriteLine("DigiDocCSharp 0.1");
        }
    }
}
