import digidoc
import sys
import os


class Program:
    digidoc.initialize()

    def __init__(self, args):
        if len(args) < 2:
            print("Missing document parameter")
            self.help()
            return
        if args[1] == "add":
            self.add(args)
            return
        if args[1] == "extract":
            self.extract(args[2], args[3])
            return
        if args[1] == "sign":
            self.sign(args)
            return
        if args[1] == "verify":
            self.verify(args[2])
            return
        if args[1] == "version":
            self.version()
            return
        self.help()

    def __del__(self):
        digidoc.terminate()

    def add(self, args):
        print("Creating file: ", args[len(args) - 1])
        doc = digidoc.Container.create(args[len(args) - 1])
        for i in args[2:-1]:
            doc.addDataFile(i, "application/octet-stream")
        doc.save();

    def extract(self, index, file):
        print("Opening file: " + file)
        doc = digidoc.Container.open(file)
        dataFiles = doc.dataFiles()
        dataFile = dataFiles[int(index)]
        dest = os.path.join(os.path.abspath(os.getcwd()), dataFile.fileName())
        print("Extracting file {0} to {1}".format(dataFile.fileName(), dest))
        dataFile.saveAs(dest)

    def help(self):
        print("main.py command [params]")
        print("Command:")
        print(" help\t\tPrints utility commands")
        print(" version\tPrints utility version")
        print(" extract\tExtracts files from document")
        print("    num")
        print("    file")
        print(" add\t\tCreates container with files")
        print("    datafile1 datafile2 ...")
        print("    file")
        print(" sign\t\tSigns file")
        print("    pkcs11path pin")
        print("    datafile1 datafile2 ...")
        print("    file")
        print(" verify\t\tVerifies document signature and shows info")
        print("    file")
        self.version()

    def sign(self, args):
        print("Creating file: ", args[len(args) - 1])
        doc = digidoc.Container.create(args[len(args) - 1])
        for i in args[4:-1]:
            doc.addDataFile(i, "application/octet-stream")
        signer = digidoc.PKCS11Signer(args[2]);
        signer.setPin(args[3]);
        doc.sign(signer);
        doc.save()

    def verify(self, file):
        print("Opening file: " + file)
        doc = digidoc.Container.open(file)

        print("Files:")
        for d in doc.dataFiles():
            print(" {} - {}".format(d.fileName(), d.mediaType()))

        print("Signatures:")
        for s in doc.signatures():
            print("  Signed by: {}".format(s.signedBy()))
            print("  Address: {} {} {} {}".format(s.city(), s.countryName(), s.stateOrProvince(), s.postalCode()))
            print("  Role:")
            for role in s.signerRoles():
                print("   " + role)
            print("  Time: " + s.trustedSigningTime())
            s.validate()
            print("  Signature is valid")

    def version(self):
        print("digidoc python 0.1 " + digidoc.version())


if __name__ == '__main__':
    Program(sys.argv)
