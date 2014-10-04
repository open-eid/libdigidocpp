#include <Container.h>
#include <crypto/PKCS11Signer.h>

#include <sstream>
#include <iostream>

using namespace digidoc;

static void exception(std::ostream &s, const Exception &e)
{
    s << e.file() << ":" << e.line() << " code(" << e.code() << ") " << e.msg() << std::endl;
    for(const Exception &ex: e.causes())
        exception(s, ex);
}

int main()
{
    try
    {
        digidoc::initialize();
        PKCS11Signer signer;
        signer.setPin("00000");
        Container doc(Container::AsicType);
        std::stringstream *s = new std::stringstream;
        *s << "test";
        doc.addDataFile(s, "test.txt", "text/plain");
        doc.sign(&signer, "BES");
        doc.save("/tmp/test.bdoc");
        digidoc::terminate();
    }
    catch(const Exception &e)
    {
        exception(std::cout, e);
    }

    return 0;
}
