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
    static {
        System.loadLibrary("digidoc_java");
    }

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
            default: help();
        }
    }

    static void extract(int index, String file)
    {
        digidoc.initializeLib("libdigidocpp-java", "");
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
        digidoc.initializeLib("libdigidocpp-java", "");
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
        digidoc.initializeLib("libdigidocpp-java", "");
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
        digidoc.initializeLib("libdigidocpp-java", "");
        try
        {
            System.out.println("Opening file: " + file);
            Container b = Container.open(file);

            System.out.println("Files:");
            for (DataFile dataFile : b.dataFiles()) System.out.println(" " + dataFile.fileName() + " - " + dataFile.mediaType());
            System.out.println();

            System.out.println("Signatures:");
            for (Signature signature : b.signatures()) {
                System.out.printf("Address: %s %s %s %s%n", signature.city(), signature.countryName(), signature.stateOrProvince(), signature.postalCode());

                System.out.print("Role:");
                StringVector roles = signature.signerRoles();
                for (String role : roles) System.out.print(" " + role);
                System.out.println();

                System.out.println("Time: " + signature.trustedSigningTime());
                System.out.println("Cert: " + toX509(signature.signingCertificateDer()).getSubjectDN().toString());

                signature.validate();
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
