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
                        extract(Convert.ToInt32(args[0].Substring(pos + 1)), args[1]);
                    return;
                case "-verify": verify(args[1]); return;
                case "-version": version(); return;
                case "-help":
                default: help(); return;
            }
        }

        static void extract(int index, string file)
        {
            digidoc.digidoc.initialize();
            try
            {
                Console.WriteLine("Opening file: " + file);
                Container b = new Container(file);
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
                Container b = new Container(file);

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
                    foreach (String role in s.signerRoles())
                        Console.Write(" " + role);
                    Console.WriteLine();

                    Console.WriteLine("Time: " + s.signingTime());

                    System.Security.Cryptography.X509Certificates.X509Certificate2 c =
                        new System.Security.Cryptography.X509Certificates.X509Certificate2(s.signingCert());
                    Console.WriteLine("Cert: " + c.Subject);
                    try
                    {
                        s.validate();
                        Console.WriteLine("Signature is valid");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Signature is invalid");
                        Console.WriteLine(e.Message);
                    }
                }
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
