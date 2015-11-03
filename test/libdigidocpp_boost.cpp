/*
 * libdigidocpp
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define BOOST_TEST_MODULE "C++ Unit Tests for libdigidocpp"
#include <boost/test/included/unit_test.hpp>
#include <boost/mpl/list.hpp>

#include <Container.h>
#include <DataFile.h>
#include <Signature.h>
#include <XmlConf.h>
#include <crypto/PKCS12Signer.h>
#include <crypto/X509Cert.h>
#include <util/DateTime.h>
#include <util/File.h>

#ifdef _WIN32
#include <direct.h>
#define chdir _chdir
#else
#include <unistd.h>
#endif

using namespace digidoc;
using namespace std;

namespace std
{
ostream &operator<<(ostream &os, const X509Cert &cert)
{
    return os << "X509Cert(" << cert.subjectName() << ")";
}

ostream &operator<<(ostream &os, const vector<unsigned char> &data)
{
    os << "Data(" << data.size() << ") { " << hex << uppercase << setfill('0');
    for(vector<unsigned char>::const_iterator i = data.begin(); i != data.end(); ++i)
        os << setw(2) << static_cast<int>(*i) << ' ';
    os << dec << nouppercase << setfill(' ') << "}";
    return os;
}

ostream &operator<<(ostream &os, const vector<string> &roles)
{
    os << "SignatureRoles(";
    for(const string &role: roles)
        os << role << ", ";
    return os << ")";
}

ostream &operator<<(ostream &os, const vector<X509Cert::KeyUsage> &usage)
{
    os << "X509Cert::KeyUsage(";
    for(X509Cert::KeyUsage i: usage)
    {
        switch(i)
        {
        case X509Cert::DigitalSignature: os << "DigitalSignature, "; break;
        case X509Cert::NonRepudiation: os << "NonRepudiation, "; break;
        case X509Cert::KeyEncipherment: os << "KeyEncipherment, "; break;
        case X509Cert::DataEncipherment: os << "DataEncipherment, "; break;
        case X509Cert::KeyAgreement: os << "KeyAgreement, "; break;
        case X509Cert::KeyCertificateSign: os << "KeyCertificateSign, "; break;
        case X509Cert::CRLSign: os << "CRLSign, "; break;
        case X509Cert::EncipherOnly: os << "EncipherOnly, "; break;
        case X509Cert::DecipherOnly: os << "DecipherOnly, "; break;
        default: os << "Unknown usage, "; break;
        }
    }
    return os << ")";
}
}

namespace digidoc
{

class TestConfig: public Conf
{
public:
    string libdigidocConf() const override { return "digidoc.conf"; }
    int logLevel() const override { return 4; }
    string logFile() const override { return "libdigidocpp.log"; }
    string xsdPath() const override { return DIGIDOCPPCONF; }
    string certsPath() const override { return "."; }
    string ocsp(const string &) const override
    { return "http://demo.sk.ee/ocsp"; }
    bool PKCS12Disable() const override { return true; }
    string TSUrl() const override { return "http://demo.sk.ee/tsa/"; }
    bool TSLAutoUpdate() const override { return false; }
    bool TSLOnlineDigest() const override { return false; }
};

class BDoc2: public Container
{
public:
    static const string TYPE, EXT;
};
class DDoc: public Container
{
public:
    static const string TYPE, EXT;
};
const string BDoc2::TYPE = "application/vnd.etsi.asic-e+zip";
const string DDoc::TYPE = "DIGIDOC-XML/1.3";
const string BDoc2::EXT = "asice";
const string DDoc::EXT = "ddoc";
}

static void translate_exception(const Exception &e)
{
    stringstream s;
    s << endl << e.file() << "(" << e.line() << "): " << e.msg();
    BOOST_ERROR(s.str().c_str());
    for(const Exception &ex: e.causes())
        translate_exception(ex);
}

struct DigiDocPPFixture
{
    DigiDocPPFixture()
    {
        //BOOST_MESSAGE("loading libdigidocpp: " + digidoc::version());
        int argc = boost::unit_test::framework::master_test_suite().argc;
        if(argc > 1)
        {
            //BOOST_MESSAGE("Data path " + string(boost::unit_test::framework::master_test_suite().argv[argc-1]));
            chdir(boost::unit_test::framework::master_test_suite().argv[argc-1]);
        }
        boost::unit_test::unit_test_monitor.register_exception_translator<Exception>(&translate_exception);
        Conf::init(new TestConfig);
        digidoc::initialize("untitestboost");
    }

    ~DigiDocPPFixture()
    {
        digidoc::terminate();
        BOOST_MESSAGE("unloading libdigidocpp");
    }
};

BOOST_GLOBAL_FIXTURE(DigiDocPPFixture)

BOOST_AUTO_TEST_SUITE(SignerSuite)
BOOST_AUTO_TEST_CASE(signerParameters)
{
    unique_ptr<Signer> signer;

    BOOST_CHECK_THROW(signer.reset(new PKCS12Signer("signer1.p12", "signer0")), Exception); // wrong pass
    BOOST_CHECK_THROW(signer.reset(new PKCS12Signer("signer0.p12", "signer1")), Exception); // missing file
    BOOST_CHECK_THROW(signer.reset(new PKCS12Signer("test1.txt", "signer1")), Exception); // invalid file
    BOOST_CHECK_NO_THROW(signer.reset(new PKCS12Signer("signer1.p12", "signer1")));
    if(!signer)
        return;

    signer->setSignatureProductionPlace("Tartu", "Tartumaa", "12345", "Estonia");

    vector<string> roles;
    roles.push_back( "Role1" );
    signer->setSignerRoles( roles );

    BOOST_CHECK_EQUAL(signer->signerRoles(), roles);
    BOOST_CHECK_EQUAL(signer->city(), "Tartu");
    BOOST_CHECK_EQUAL(signer->stateOrProvince(), "Tartumaa");
    BOOST_CHECK_EQUAL(signer->postalCode(), "12345");
    BOOST_CHECK_EQUAL(signer->countryName(), "Estonia");

    const unsigned char digest[] = "Signature";
    vector<unsigned char> signature;
    BOOST_CHECK_NO_THROW(signature = signer->sign("http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        vector<unsigned char>(digest, digest+sizeof(digest))));

    const unsigned char sig[] = {
        0x8F, 0x05, 0x7B, 0x15, 0xC8, 0x9B, 0x18, 0x76, 0x93, 0x70, 0xA2, 0x3A,
        0x15, 0xC2, 0x64, 0xCD, 0x20, 0x1F, 0x18, 0x8D, 0xDA, 0xC9, 0xFD, 0x68,
        0xB0, 0x25, 0xF4, 0x16, 0xCC, 0xF3, 0xC0, 0x6A, 0x77, 0x90, 0x00, 0x0E,
        0x52, 0x27, 0x57, 0xE8, 0x86, 0x7D, 0xB9, 0x53, 0xDB, 0x7E, 0x76, 0x84,
        0xA9, 0x3D, 0xB4, 0x73, 0x48, 0x8B, 0xC1, 0xCD, 0x72, 0x53, 0xC6, 0x3C,
        0xB3, 0xBD, 0x4E, 0x65, 0x2E, 0x36, 0xE3, 0x60, 0x8F, 0xED, 0xE5, 0x05,
        0xA7, 0x91, 0xE5, 0x8F, 0x00, 0x1C, 0x6C, 0x50, 0xB5, 0x98, 0x95, 0xD3,
        0x4B, 0x0B, 0x6D, 0x7F, 0x58, 0xD1, 0xCD, 0x10, 0x2B, 0x4C, 0xA8, 0x2B,
        0xD8, 0xB5, 0x41, 0x97, 0xCB, 0x9B, 0x05, 0x93, 0x87, 0xC7, 0x3E, 0x41,
        0xCD, 0x6E, 0x28, 0xB9, 0x6F, 0xDE, 0x91, 0xAD, 0xC8, 0x90, 0x90, 0xB6,
        0x48, 0x62, 0x37, 0x43, 0xBC, 0x71, 0xE3, 0x85, 0x9D, 0x31, 0xAD, 0x21,
        0x7B, 0xCD, 0x33, 0xF6, 0x37, 0x34, 0x95, 0x10, 0x4E, 0x86, 0xEE, 0x30,
        0x42, 0x70, 0xBB, 0x59, 0x33, 0xB3, 0x90, 0x22, 0x16, 0xAA, 0x9E, 0x34,
        0xFA, 0x7C, 0xAA, 0x7F, 0x40, 0x31, 0xE9, 0xA0, 0x7F, 0xC8, 0xE0, 0x25,
        0x45, 0x23, 0x14, 0x32, 0x05, 0x17, 0x00, 0x74, 0x41, 0xC9, 0x5C, 0xA1,
        0xE3, 0xDF, 0x60, 0x55, 0x72, 0xDB, 0x10, 0x7A, 0x2D, 0x87, 0x65, 0x5E,
        0xC2, 0xB3, 0x5F, 0xB6, 0xE6, 0x53, 0xD8, 0x76, 0xAA, 0x70, 0xFB, 0x93,
        0x7D, 0xB0, 0xB2, 0x47, 0x02, 0xFC, 0x00, 0xFB, 0x83, 0xD5, 0x9A, 0x22,
        0xD0, 0x5C, 0xAA, 0xB3, 0x33, 0xDB, 0x2D, 0xEB, 0x35, 0x82, 0xC8, 0x5D,
        0x08, 0x3A, 0xAD, 0xCA, 0x4E, 0x34, 0x30, 0x78, 0x7A, 0x07, 0xB8, 0x30,
        0x81, 0x02, 0x4E, 0x99, 0xBD, 0x2C, 0x9E, 0x93, 0x14, 0x6F, 0x0C, 0x56,
        0xE7, 0x58, 0x07, 0x91
    };
    BOOST_CHECK_EQUAL(signature, vector<unsigned char>(sig, sig+sizeof(sig)));
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(X509CertSuite)
BOOST_AUTO_TEST_CASE(parameters)
{
    unique_ptr<Signer> signer1(new PKCS12Signer("signer1.p12", "signer1"));
    X509Cert c = signer1->cert();
    BOOST_CHECK_EQUAL(c, signer1->cert());
    BOOST_CHECK_EQUAL(!c, false);

    BOOST_CHECK_EQUAL(c.serial(), "2");
    BOOST_CHECK_EQUAL(c.subjectName("CN"), "signer1");
    BOOST_CHECK_EQUAL(c.subjectName("C"), "EE");
    BOOST_CHECK_EQUAL(c.issuerName("CN"), "libdigidocpp Inter");
    BOOST_CHECK_EQUAL(c.issuerName("C"), "EE");
    vector<X509Cert::KeyUsage> usage;
    usage.push_back(X509Cert::DigitalSignature);
    usage.push_back(X509Cert::NonRepudiation);
    BOOST_CHECK_EQUAL(c.keyUsage(), usage);
    BOOST_CHECK_EQUAL(c.isValid(), true);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(DocSuite)
#ifdef LINKED_LIBDIGIDOC
typedef boost::mpl::list<BDoc2,DDoc> DocTypes;
#else
typedef boost::mpl::list<BDoc2> DocTypes;
#endif
BOOST_AUTO_TEST_CASE_TEMPLATE(constructor, Doc, DocTypes)
{
    unique_ptr<Container> d(Container::create("test." + Doc::EXT));
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 0U);
    BOOST_CHECK_EQUAL(d->signatures().size(), 0U);
    BOOST_CHECK_EQUAL(d->mediaType(), Doc::TYPE);

    d.reset(Container::open("test." + Doc::EXT));
    if(!d)
       return;
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    BOOST_CHECK_EQUAL(d->mediaType(), Doc::TYPE);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(document, Doc, DocTypes)
{
    unique_ptr<Container> d(Container::create("test." + Doc::EXT));

    BOOST_CHECK_THROW(d->removeDataFile(0U), Exception);

    // Add first Document
    BOOST_CHECK_NO_THROW(d->addDataFile("test1.txt", "file1"));
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    if(!d->dataFiles().empty())
    {
        const DataFile *doc1 = d->dataFiles().front();
        if(d->mediaType() == DDoc::TYPE)
            BOOST_CHECK_EQUAL(doc1->id(), "D0");
        BOOST_CHECK_EQUAL(doc1->fileName(), "test1.txt");
        BOOST_CHECK_EQUAL(doc1->mediaType(), "file1");
    }

    // Add second Document
    BOOST_CHECK_NO_THROW(d->addDataFile("test2.bin", "file2"));
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 2U);
    if(!d->dataFiles().empty())
    {
        const DataFile *doc2 = d->dataFiles().back();
        if(d->mediaType() == DDoc::TYPE)
            BOOST_CHECK_EQUAL(doc2->id(), "D1");
        BOOST_CHECK_EQUAL(doc2->fileName(), "test2.bin");
        BOOST_CHECK_EQUAL(doc2->mediaType(), "file2");
    }

    // Remove first Document
    BOOST_CHECK_NO_THROW(d->removeDataFile(0U));
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    if(!d->dataFiles().empty())
    {
        const DataFile *doc3 = d->dataFiles().front();
        if(d->mediaType() == DDoc::TYPE)
            BOOST_CHECK_EQUAL(doc3->id(), "D1");
        BOOST_CHECK_EQUAL(doc3->fileName(), "test2.bin");
        BOOST_CHECK_EQUAL(doc3->mediaType(), "file2");
    }

    // Remove second Document
    BOOST_CHECK_NO_THROW(d->removeDataFile(0U));
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 0U);

    if(d->mediaType() == DDoc::TYPE)
        return;

    d.reset(Container::open("test." + Doc::EXT));
    const DataFile *data = d->dataFiles().front();
    BOOST_CHECK_NO_THROW(data->saveAs("test1.tmp"));

    BOOST_CHECK_EQUAL(data->calcDigest("http://www.w3.org/2000/09/xmldsig#sha1"), vector<unsigned char>({
        0x1B, 0xE1, 0x68, 0xFF, 0x83, 0x7F, 0x04, 0x3B, 0xDE, 0x17,
        0xC0, 0x31, 0x43, 0x41, 0xC8, 0x42, 0x71, 0x04, 0x7B, 0x31 }));
    BOOST_CHECK_EQUAL(data->calcDigest("http://www.w3.org/2001/04/xmldsig-more#sha224"), vector<unsigned char>({
        0xD7, 0x60, 0x41, 0x11, 0x2E, 0x34, 0x3B, 0x2B, 0xDC, 0x14,
        0xD4, 0x39, 0x34, 0xE5, 0xAE, 0xD7, 0xAB, 0xF9, 0x01, 0x92,
        0xC6, 0x54, 0x3B, 0xDF, 0x2A, 0xE4, 0xF8, 0x1B }));
    BOOST_CHECK_EQUAL(data->calcDigest("http://www.w3.org/2001/04/xmlenc#sha256"), vector<unsigned char>({
        0xA8, 0x83, 0xDA, 0xFC, 0x48, 0x0D, 0x46, 0x6E, 0xE0, 0x4E,
        0x0D, 0x6D, 0xA9, 0x86, 0xBD, 0x78, 0xEB, 0x1F, 0xDD, 0x21,
        0x78, 0xD0, 0x46, 0x93, 0x72, 0x3D, 0xA3, 0xA8, 0xF9, 0x5D,
        0x42, 0xF4 }));
    BOOST_CHECK_EQUAL(data->calcDigest("http://www.w3.org/2001/04/xmldsig-more#sha384"), vector<unsigned char>({
        0x63, 0x7E, 0x2E, 0xDD, 0x55, 0x55, 0x70, 0xED, 0xA9, 0x66,
        0xD9, 0x9D, 0x4E, 0x77, 0xD9, 0xFB, 0xB3, 0xAA, 0xB8, 0x4A,
        0x49, 0x8F, 0xF5, 0x5A, 0xC2, 0x1B, 0x96, 0x3C, 0x1E, 0x05,
        0xC2, 0xAD, 0xDF, 0xB5, 0xC1, 0x5C, 0xD2, 0x07, 0x1E, 0x7E,
        0xDD, 0x47, 0x35, 0x9D, 0x78, 0x79, 0x41, 0xD3 }));
    BOOST_CHECK_EQUAL(data->calcDigest("http://www.w3.org/2001/04/xmlenc#sha512"), vector<unsigned char>({
        0x79, 0x85, 0x55, 0x83, 0x70, 0xF0, 0xDE, 0x86, 0xA8, 0x64,
        0xE0, 0x05, 0x0A, 0xFD, 0xF4, 0x5D, 0x70, 0x29, 0xB8, 0x79,
        0x8B, 0xCD, 0x72, 0xCD, 0xDB, 0xF7, 0x81, 0x32, 0x9F, 0x99,
        0x38, 0x0E, 0x3F, 0x3B, 0x1A, 0xFD, 0xCA, 0x67, 0x65, 0xD8,
        0x9F, 0xC3, 0x88, 0xB2, 0x13, 0xDF, 0x8F, 0x6A, 0x19, 0x3C,
        0xFC, 0x56, 0xD4, 0xFF, 0x2E, 0xF6, 0xE0, 0xA9, 0x9B, 0xD8,
        0x83, 0xA6, 0xD9, 0x8C }));
}

BOOST_AUTO_TEST_CASE_TEMPLATE(signature, Doc, DocTypes)
{
    unique_ptr<Container> d(Container::create("test." + Doc::EXT));

    BOOST_CHECK_THROW(d->removeSignature(0U), Exception);

    unique_ptr<Signer> signer1(new PKCS12Signer("signer1.p12", "signer1"));
    BOOST_CHECK_THROW(d->sign(signer1.get()), Exception);
    if(Doc::EXT == DDoc::EXT)
        return;

    // Add first Signature
    BOOST_CHECK_NO_THROW(d->addDataFile("test1.txt", "file"));
    BOOST_CHECK_NO_THROW(d->sign(signer1.get()));
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    if(d->signatures().size() == 1)
        BOOST_CHECK_EQUAL(d->signatures().at(0)->signingCertificate(), signer1->cert());
    BOOST_CHECK_NO_THROW(d->save(Doc::EXT + ".tmp"));

    // Signed container cannot add and remove documents
    BOOST_CHECK_THROW(d->addDataFile("test1.txt", "file"), Exception);
    BOOST_CHECK_THROW(d->removeDataFile(0U), Exception);

    // Add second Signature
    unique_ptr<Signer> signer2(new PKCS12Signer("signer2.p12", "signer2"));
    BOOST_CHECK_NO_THROW(d->sign(signer2.get()));
    BOOST_CHECK_EQUAL(d->signatures().size(), 2U);
    if(d->signatures().size() == 2)
        BOOST_CHECK_EQUAL(d->signatures().at(1)->signingCertificate(), signer2->cert());
    BOOST_CHECK_NO_THROW(d->save());

    // Remove first Signature
    BOOST_CHECK_NO_THROW(d->removeSignature(0U));
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    if(d->signatures().size() == 1)
        BOOST_CHECK_EQUAL(d->signatures().at(0)->signingCertificate(), signer2->cert());

    if(d->mediaType() == BDoc2::TYPE)
    {
        unique_ptr<Signer> signer3(new PKCS12Signer("signerEC.p12", "signerEC"));
        Signature *s3 = 0;
        BOOST_CHECK_NO_THROW(s3 = d->sign(signer3.get()));
        BOOST_CHECK_EQUAL(d->signatures().size(), 2U);
        if(s3)
        {
            BOOST_CHECK_EQUAL(s3->signingCertificate(), signer3->cert());
            BOOST_CHECK_NO_THROW(s3->validate());
        }
        BOOST_CHECK_NO_THROW(d->save());

        // Reload from file and validate
        d.reset(Container::open(Doc::EXT + ".tmp"));
        BOOST_CHECK_EQUAL(d->signatures().size(), 2U);
        if((s3 = d->signatures().back()))
        {
            BOOST_CHECK_EQUAL(s3->signingCertificate(), signer3->cert());
            BOOST_CHECK_NO_THROW(s3->validate());
        }

        // Remove third Signature
        BOOST_CHECK_NO_THROW(d->removeSignature(1U));
        BOOST_CHECK_EQUAL(d->signatures().size(), 1U);

        // TS signature
        signer2->setProfile("time-stamp");
        BOOST_CHECK_NO_THROW(s3 = d->sign(signer2.get()));
        //BOOST_CHECK_EQUAL(s3->TSCertificate(), signer2->cert());
        //BOOST_CHECK_NO_THROW(s3->validate());
        BOOST_CHECK_NO_THROW(d->save(Doc::EXT + "-TS.tmp"));
        BOOST_CHECK_NO_THROW(d->removeSignature(1U));
        BOOST_CHECK_EQUAL(d->signatures().size(), 1U);

        // TSA signature
        signer2->setProfile("time-stamp-archive");
        BOOST_CHECK_NO_THROW(s3 = d->sign(signer2.get()));
        //BOOST_CHECK_EQUAL(s3->TSCertificate(), signer2->cert());
        //BOOST_CHECK_NO_THROW(s3->validate());
        BOOST_CHECK_NO_THROW(d->save(Doc::EXT + "-TSA.tmp"));
        BOOST_CHECK_NO_THROW(d->removeSignature(1U));
        BOOST_CHECK_EQUAL(d->signatures().size(), 1U);

        // TSA signature
        signer2->setProfile("time-stamp-archive");
        BOOST_CHECK_NO_THROW(d->sign(signer2.get()));
        BOOST_CHECK_NO_THROW(d->save(Doc::EXT + "-TMA.tmp"));
        BOOST_CHECK_NO_THROW(d->removeSignature(1U));
        BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    }

    // Remove second Signature
    BOOST_CHECK_NO_THROW(d->removeSignature(0U));
    BOOST_CHECK_EQUAL(d->signatures().size(), 0U);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(files, Doc, DocTypes)
{
    unique_ptr<Signer> signer1(new PKCS12Signer("signer1.p12", "signer1"));
    vector<string> data;
    data.push_back("0123456789~#%&()=`@{[]}'");
    data.push_back("öäüõ");
    for(vector<string>::const_iterator i = data.begin(); i != data.end(); ++i)
    {
        unique_ptr<Container> d(Container::create("test." + Doc::EXT));
        const Signature *s1 = 0;
        BOOST_CHECK_NO_THROW(d->addDataFile(*i + ".txt", "file"));
        if(Doc::EXT == DDoc::EXT)
            return;
        BOOST_CHECK_NO_THROW(s1 = d->sign(signer1.get()));
        if(s1)
            s1->validate();
        d->save(*i + Doc::EXT + ".tmp");
        d.reset(Container::open(*i + Doc::EXT + ".tmp"));
        BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
        s1 = d->signatures().front();
        s1->validate();
    }
}

BOOST_AUTO_TEST_CASE_TEMPLATE(signatureParameters, Doc, DocTypes)
{
    unique_ptr<Container> d(Container::create("test." + Doc::EXT));
    unique_ptr<Signer> signer1(new PKCS12Signer("signer1.p12", "signer1"));

    signer1->setSignatureProductionPlace("Tartu", "Tartumaa", "12345", "Estonia");

    vector<string> roles;
    roles.push_back( "Role1" );
    signer1->setSignerRoles( roles );

    const Signature *s1 = 0;
    BOOST_CHECK_NO_THROW(d->addDataFile("test1.txt", "file"));
    BOOST_CHECK_NO_THROW(d->addDataFile("test2.bin", "file"));
    if(Doc::EXT == DDoc::EXT)
        return;
    BOOST_CHECK_NO_THROW(s1 = d->sign(signer1.get()));
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    if(s1)
    {
        if(d->mediaType() != DDoc::TYPE)
            BOOST_CHECK_NO_THROW(s1->validate());
        BOOST_CHECK_EQUAL(s1->id(), "S0");
        BOOST_CHECK_EQUAL(s1->signingCertificate(), signer1->cert());
        if(d->mediaType() != DDoc::TYPE)
            BOOST_CHECK_EQUAL(s1->signerRoles(), roles);
        BOOST_CHECK_EQUAL(s1->city(), "Tartu");
        BOOST_CHECK_EQUAL(s1->stateOrProvince(), "Tartumaa");
        BOOST_CHECK_EQUAL(s1->postalCode(), "12345");
        BOOST_CHECK_EQUAL(s1->countryName(), "Estonia");
        time_t t = time(0);
        struct tm *t2 = gmtime(&t);
        string time = util::date::xsd2string(util::date::makeDateTime(*t2));
        BOOST_WARN_EQUAL(s1->claimedSigningTime().substr(0, 16), time.substr(0, 16));
        BOOST_WARN_EQUAL(s1->OCSPProducedAt().substr(0, 16), time.substr(0, 16));
        BOOST_CHECK_EQUAL(s1->OCSPCertificate().subjectName("CN"), "TEST of SK OCSP RESPONDER 2011");
    }

    BOOST_CHECK_NO_THROW(d->save(Doc::EXT + ".tmp")); //Check if reloading and binary files work
    d.reset(Container::open(Doc::EXT + ".tmp"));
    if(d->signatures().size() == 1U)
        BOOST_CHECK_NO_THROW(d->signatures().front()->validate());

    unique_ptr<Signer> signer3(new PKCS12Signer("signer3.p12", "signer3"));
    BOOST_CHECK_THROW(d->sign(signer3.get()), Exception); // OCSP UNKNOWN
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ConfSuite)
BOOST_AUTO_TEST_CASE(XmlConfCase)
{
    XmlConf c("digidocpp.conf", util::File::path(DIGIDOCPPCONF, "/conf.xsd"));
    BOOST_CHECK_EQUAL(c.logLevel(), 2);
    BOOST_CHECK_EQUAL(c.logFile(), "digidocpp.log");
    BOOST_CHECK_EQUAL(c.digestUri(), "http://www.w3.org/2001/04/xmlenc#sha256");
    //BOOST_CHECK_EQUAL(c.PKCS11Driver(), PKCS11_MODULE);
    BOOST_CHECK_EQUAL(c.xsdPath().substr(c.xsdPath().size() - 6, 6), "schema");
    BOOST_CHECK_EQUAL(c.proxyHost(), "host");
    BOOST_CHECK_EQUAL(c.proxyPort(), "port");
    BOOST_CHECK_EQUAL(c.proxyUser(), "user");
    BOOST_CHECK_EQUAL(c.proxyPass(), "pass");
    BOOST_CHECK_EQUAL(util::File::fileName(c.PKCS12Cert()), "cert");
    BOOST_CHECK_EQUAL(c.PKCS12Pass(), "pass");
    BOOST_CHECK_EQUAL(c.PKCS12Disable(), true);
    BOOST_CHECK_EQUAL(c.ocsp("ESTEID-SK 2007"), "http://ocsp.sk.ee");
}
BOOST_AUTO_TEST_SUITE_END()
