package ee.ria.libdigidocpp;

import java.io.ByteArrayInputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

public class libdigidocpp {
    public static void main(String[] args)
    {
        if (args.length < 1)
        {
        	System.out.println("Missing document parameter");
            help();
            return;
        }

        switch (args[0])
        {
            case "extract": extract(Integer.parseInt(args[1]), args[2]); return;
            case "sign": sign(args); return;
            case "websign": websign(args); return;
            case "verify": verify(args[1]); return;
            case "version": version(); return;
            case "help":
            default: help(); return;
        }
    }

    static void extract(int index, String file)
    {
        init();
        try
        {
            System.out.println("Opening file: " + file);
            Container b = Container.open(file);
            DataFiles d = b.dataFiles();
            String dest = FileSystems.getDefault().getPath(d.get(index).fileName()).toAbsolutePath().toString();
            System.out.println("Extracting file " + d.get(index).fileName() + " to " + dest);
            try
            {
                d.get(index).saveAs(dest);
            }
            catch (Exception e)
            {
                System.out.println("Failed to copy file");
                System.out.println(e.getMessage());
            }
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        digidoc.terminate();
    }

    static void help()
    {
        System.out.println("libdigidocpp-java command [params]");
        System.out.println("Command:");
        System.out.println(" extract\tExtracts files from document");
        System.out.println("    num");
        System.out.println("    file");
        System.out.println(" help\t\tPrints utility commands");
        System.out.println(" sign\t\tSigns file");
        System.out.println("    pkcs11path pin");
        System.out.println("    datafile1 datafile2 ...");
        System.out.println("    file");
        System.out.println(" websign\t\tSigns file");
        System.out.println("    datafile1 datafile2 ...");
        System.out.println("    cert");
        System.out.println("    file");
        System.out.println(" verify\t\tVerifies document signature and shows info");
        System.out.println("    file");
        System.out.println(" version\tPrints utility version");
        version();
    }

    static void sign(String[] args)
    {
        DigiDocConf conf = new DigiDocConf(null);
        Conf.init(conf.transfer());
        init();
        try
        {
            System.out.println("Creating file: " + args[args.length-1]);
            Container b = Container.create(args[args.length - 1]);
            for (int i = 3; i < args.length - 1; ++i)
                b.addDataFile(args[i], "application/octet-stream");
            PKCS11Signer signer = new PKCS11Signer(args[1]);
            signer.setPin(args[2]);
            b.sign(signer);
            b.save();
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        digidoc.terminate();
    }

    static void websign(String[] args)
    {
        init();
        try
        {
            System.out.println("Creating file: " + args[args.length - 1]);
            Container b = Container.create(args[args.length - 1]);
            for (int i = 1; i < args.length - 2; ++i)
                b.addDataFile(args[i], "application/octet-stream");

            X509Certificate cert = toX509(Files.readAllBytes(FileSystems.getDefault().getPath(args[args.length - 2])));
            Signature c = b.prepareWebSignature(cert.getEncoded(), "BES/time-stamp");
            System.out.println("Signature method: " + c.signatureMethod());
            System.out.println("Digest to sign: " + toHex(c.dataToSign()));
            System.out.println("Please enter signed digest in hex: ");

            Scanner scanner = new Scanner(System.in);
            String signature = scanner.nextLine();
            scanner.close();

            c.setSignatureValue(fromHex(signature));
            c.extendSignatureProfile("BES/time-stamp");
            b.save();
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        digidoc.terminate();
    }

    static void verify(String file)
    {
        init();
        try
        {
            System.out.println("Opening file: " + file);
            Container b = Container.open(file);

            System.out.println("Files:");
            DataFiles d = b.dataFiles();
            for (int i = 0; i < d.size(); ++i)
                System.out.println(" " + d.get(i).fileName() + " - " + d.get(i).mediaType());
            System.out.println();

            System.out.println("Signatures:");
            b.signatures();
            Signatures s = b.signatures();
            for (int i = 0; i < s.size(); ++i)
            {
                System.out.println(String.format("Address: %s %s %s %s", s.get(i).city(), s.get(i).countryName(), s.get(i).stateOrProvince(), s.get(i).postalCode()));

                System.out.print("Role:");
                StringVector roles = s.get(i).signerRoles();
                for (int j = 0; j < roles.size(); ++ j)
                    System.out.print(" " + roles.get(j));
                System.out.println();

                System.out.println("Time: " + s.get(i).trustedSigningTime());
                System.out.println("Cert: " + toX509(s.get(i).signingCertificateDer()).getSubjectDN().toString());

                s.get(i).validate();
                System.out.println("Signature is valid");
            }
        }
        catch (Exception e)
        {
            System.out.println("Signature is invalid");
            System.out.println(e.getMessage());
        }
        digidoc.terminate();
    }

    static void version() {
        System.out.println("DigiDocCSharp 0.2 libdigidocpp " + digidoc.version());
    }

    static void init() {
        System.loadLibrary("digidoc_java");
        digidoc.initializeLib("libdigidocpp-java", "");
    }

    static X509Certificate toX509(byte[] der) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }
    
    public static String toHex(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] fromHex(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }
}
