package ee.ria.libdigidocpp;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Scanner;

public class libdigidocpp {
    static {
        System.loadLibrary("digidoc_java");
    }

    public static void main(String[] args) {
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

    static void extract(int index, String file) {
        digidoc.initializeLib("libdigidocpp-java", "");
        try
        {
            System.out.println("Opening file: " + file);
            Container b = Container.open(file);
            assert b != null;
            DataFiles d = b.dataFiles();
            String dest = Paths.get(d.get(index).fileName()).toAbsolutePath().toString();
            System.out.println("Extracting file " + d.get(index).fileName() + " to " + dest);
            d.get(index).saveAs(dest);
        }
        catch (Exception e)
        {
            System.out.println("Failed to copy file");
            System.out.println(e.getMessage());
        }
        digidoc.terminate();
    }

    static void help() {
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

    static void sign(String[] args) {
        DigiDocConf conf = new DigiDocConf();
        Conf.init(conf.transfer());
        digidoc.initializeLib("libdigidocpp-java", "");
        try
        {
            System.out.println("Creating file: " + args[args.length-1]);
            Container b = Container.create(args[args.length - 1]);
            assert b != null;
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

    static void websign(String[] args) {
        digidoc.initializeLib("libdigidocpp-java", "");
        try (Scanner scanner = new Scanner(System.in))
        {
            System.out.println("Creating file: " + args[args.length - 1]);
            Container b = Container.create(args[args.length - 1]);
            assert b != null;
            for (int i = 1; i < args.length - 2; ++i)
                b.addDataFile(args[i], "application/octet-stream");

            X509Certificate cert = toX509(Files.readAllBytes(Paths.get(args[args.length - 2])));
            ExternalSigner signer = new ExternalSigner(cert.getEncoded());
            Signature c = b.prepareSignature(signer);
            System.out.println("Signature method: " + c.signatureMethod());
            System.out.println("Digest to sign: " + HexFormat.of().formatHex(c.dataToSign()));
            System.out.println("Please enter signed digest in hex: ");

            String signature = scanner.nextLine();
            c.setSignatureValue(HexFormat.of().parseHex(signature));
            c.extendSignatureProfile(signer);
            b.save();
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        digidoc.terminate();
    }

    static void verify(String file) {
        digidoc.initializeLib("libdigidocpp-java", "");
        try
        {
            System.out.println("Opening file: " + file);
            ContainerOpen cb = new ContainerOpen();
            Container b = Container.open(file, cb);
            assert b != null;

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
                System.out.println("Cert: " + signature.signingCertificate().getSubjectDN().toString());
                System.out.println("TimeStamp Cert: " + signature.TimeStampCertificate().getSubjectDN().toString());
                for(TSAInfo tsaInfo : signature.ArchiveTimeStamps()) {
                    System.out.println("Archive Time: " + tsaInfo.getTime());
                    System.out.println("Archive Cert: " + tsaInfo.getCert().getSubjectDN().toString());
                }

                try
                {
                    signature.validate();
                    System.out.println("Signature is valid");
                }
                catch (Exception e)
                {
                    System.out.println("Signature is invalid");
                    System.out.println(e.getMessage());
                }
            }
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        digidoc.terminate();
    }

    static void version() {
        System.out.println("DigiDocJAVA 0.5 libdigidocpp " + digidoc.version());
    }

    static X509Certificate toX509(byte[] der) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    static private class ContainerOpen extends ContainerOpenCB
    {
        @Override
        public boolean validateOnline() { return true; }
    }
}
