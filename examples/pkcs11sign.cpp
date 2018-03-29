#include <Container.h>
#include <crypto/PKCS11Signer.h>

#include <iostream>
#include <memory>
#include <sstream>

using namespace digidoc;

static std::ostream &operator<<(std::ostream &s, const Exception &e)
{
    s << e.file() << ":" << e.line() << " code(" << e.code() << ") " << e.msg() << std::endl;
    for(const Exception &ex: e.causes())
        s << ex;
    return s;
}

int main()
{
    try
    {
        digidoc::initialize();
        std::unique_ptr<Container> doc(Container::create("/tmp/test.asice"));
        std::stringstream *s = new std::stringstream;
        *s << "test";
        doc->addDataFile(s, "test.txt", "text/plain");
        PKCS11Signer signer;
        signer.setPin("00000");
        signer.setProfile("BES");
        doc->sign(&signer);
        doc->save();
        digidoc::terminate();
    }
    catch(const Exception &e)
    {
        std::cout << e;
    }

    return 0;
}
