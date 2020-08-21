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
#include "test.h"

#include <boost/mpl/list.hpp>

#include <DataFile.h>
#include <Signature.h>
#include <XmlConf.h>
#include <crypto/PKCS12Signer.h>
#include <crypto/X509Crypto.h>
#include <util/DateTime.h>

namespace digidoc
{

class TestFixture: public DigiDocPPFixture
{
public:
    TestFixture()
    {
        copyTSL("EE_T-good.xml");
        digidoc::initialize("untitestboost");
    }
};

class ASiCE: public Container
{
public:
    static const string TYPE, EXT;
};
class DDoc: public Container
{
public:
    static const string TYPE, EXT;
};
class ASiCS: public Container
{
public:
    static const string TYPE, EXT;
};
const string ASiCE::TYPE = "application/vnd.etsi.asic-e+zip";
const string ASiCE::EXT = "asice";
const string ASiCS::TYPE = "application/vnd.etsi.asic-s+zip";
const string ASiCS::EXT = "asics";
const string DDoc::TYPE = "DIGIDOC-XML/1.3";
const string DDoc::EXT = "ddoc";
}


BOOST_GLOBAL_FIXTURE(TestFixture);

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
    roles.emplace_back("Role1");
    signer->setSignerRoles( roles );

    BOOST_CHECK_EQUAL(signer->signerRoles(), roles);
    BOOST_CHECK_EQUAL(signer->city(), "Tartu");
    BOOST_CHECK_EQUAL(signer->stateOrProvince(), "Tartumaa");
    BOOST_CHECK_EQUAL(signer->postalCode(), "12345");
    BOOST_CHECK_EQUAL(signer->countryName(), "Estonia");

    const vector<unsigned char> digest = {'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '\0' };
    vector<unsigned char> signature;
    BOOST_CHECK_NO_THROW(signature = signer->sign("http://www.w3.org/2001/04/xmlenc#sha256", digest));

    const vector<unsigned char> sig = {
        0x17, 0x2F, 0x5B, 0x7D, 0x16, 0x27, 0x32, 0x86, 0x4E, 0xF1, 0x97, 0x62,
        0x2B, 0x6E, 0x5E, 0x03, 0x52, 0x48, 0x6C, 0x14, 0xE0, 0x0C, 0xE8, 0xBB,
        0xA7, 0x88, 0x9D, 0x06, 0x08, 0x9A, 0x1A, 0x33, 0xA8, 0xD7, 0x96, 0x10,
        0x32, 0xE0, 0xF1, 0x57, 0x85, 0xB7, 0x04, 0x59, 0x27, 0x34, 0xCB, 0x74,
        0xD1, 0xCB, 0xE5, 0x2C, 0x28, 0xD7, 0xF8, 0x9E, 0x2C, 0x14, 0x5B, 0xCA,
        0xBC, 0x14, 0x29, 0xD2, 0xC7, 0xC7, 0x6A, 0xC3, 0x02, 0x82, 0x21, 0x83,
        0x7D, 0x64, 0xD3, 0xB6, 0x7E, 0x46, 0xDE, 0x46, 0xCB, 0x60, 0xE7, 0x0C,
        0xB3, 0x13, 0xBD, 0x85, 0x55, 0xF2, 0x19, 0xAB, 0xD7, 0x60, 0x8F, 0xF3,
        0x11, 0xAB, 0xD8, 0x36, 0x3A, 0x54, 0x5C, 0xA8, 0x16, 0x0F, 0x09, 0xFC,
        0x6F, 0xCA, 0x8C, 0x60, 0xDF, 0xCF, 0x9F, 0x1D, 0xA4, 0xF4, 0xF8, 0x61,
        0x0F, 0x68, 0xC3, 0x80, 0xB0, 0xD9, 0x07, 0xB9, 0x85, 0x72, 0xE7, 0x2E,
        0x10, 0xED, 0xB2, 0xB4, 0xD7, 0xFA, 0x8D, 0xA5, 0xB0, 0x87, 0x21, 0x9A,
        0xAD, 0x26, 0xB6, 0x89, 0x60, 0x13, 0x7B, 0x72, 0x59, 0x2B, 0xCF, 0x0E,
        0x6B, 0xBB, 0x04, 0x87, 0xCB, 0x1D, 0x1A, 0x15, 0x37, 0x2D, 0x9C, 0x91,
        0xFA, 0xA5, 0x7E, 0x45, 0xA7, 0x85, 0x7A, 0x7E, 0x77, 0x9B, 0x66, 0x44,
        0xC4, 0xCE, 0x63, 0xA6, 0xFC, 0x8F, 0xD0, 0x8F, 0xD4, 0xA0, 0x8A, 0x68,
        0x82, 0xBA, 0x71, 0x94, 0x65, 0xF7, 0x01, 0x79, 0x7D, 0xDB, 0xCB, 0x06,
        0x27, 0xF6, 0xC7, 0x05, 0xA6, 0x7F, 0xAE, 0x0B, 0x85, 0x94, 0x3A, 0x8A,
        0xB0, 0x7F, 0xA6, 0x42, 0xA2, 0x6D, 0x3E, 0x22, 0x0B, 0xBF, 0xE9, 0xDA,
        0x70, 0xAF, 0xDF, 0x78, 0xBA, 0x73, 0xB4, 0xCC, 0xD3, 0x14, 0x76, 0x78,
        0xB3, 0x64, 0x5B, 0x78, 0x33, 0xE1, 0x73, 0x9F, 0xD4, 0x5F, 0x43, 0xCD,
        0xDB, 0x63, 0x96, 0x52
    };
    BOOST_CHECK_EQUAL(signature, sig);
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

BOOST_AUTO_TEST_SUITE(X509Crypto)
BOOST_AUTO_TEST_CASE(parameters)
{
    X509Cert cert("47101010033.cer", X509Cert::Pem);
    digidoc::X509Crypto crypto(cert);
    BOOST_CHECK_EQUAL(crypto.isRSAKey(), true);
    BOOST_CHECK_EQUAL(crypto.compareIssuerToString(cert.issuerName()), 0);
    BOOST_CHECK_EQUAL(crypto.compareIssuerToString("emailAddress=pki@sk.ee,CN=TEST of ESTEID-SK 2015,O=AS Sertifitseerimiskeskus,C=EE"), -1);
    BOOST_CHECK_EQUAL(crypto.compareIssuerToString("emailAddress=pki@sk.ee,CN=TEST of EST\\45ID-SK 2015,O=AS Sertifitseerimiskeskus,C=EE"), -1);
    BOOST_CHECK_EQUAL(crypto.compareIssuerToString(cert.issuerName()+"EE"), -1);

    unique_ptr<Signer> signer1(new PKCS12Signer("signer1.p12", "signer1"));
    vector<unsigned char> data({'H','e','l','l','o',' ','w','o','r','l','d'});
    vector<unsigned char> signature = signer1->sign("http://www.w3.org/2001/04/xmlenc#sha256", data);
    BOOST_CHECK_EQUAL(digidoc::X509Crypto(signer1->cert()).verify("http://www.w3.org/2001/04/xmlenc#sha256", data, signature), true);
    data.resize(data.size() - 1);
    BOOST_CHECK_EQUAL(digidoc::X509Crypto(signer1->cert()).verify("http://www.w3.org/2001/04/xmlenc#sha256", data, signature), false);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(DocSuite)
#ifdef LINKED_LIBDIGIDOC
using DocTypes = boost::mpl::list<ASiCE,DDoc>;
#else
using DocTypes = boost::mpl::list<ASiCE>;
#endif
BOOST_AUTO_TEST_CASE_TEMPLATE(constructor, Doc, DocTypes)
{
    unique_ptr<Container> d = Container::createPtr("test." + Doc::EXT);
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 0U);
    BOOST_CHECK_EQUAL(d->signatures().size(), 0U);
    BOOST_CHECK_EQUAL(d->mediaType(), Doc::TYPE);

    d = Container::openPtr("test." + Doc::EXT);
    if(!d)
       return;
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    BOOST_CHECK_EQUAL(d->mediaType(), Doc::TYPE);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(document, Doc, DocTypes)
{
    unique_ptr<Container> d = Container::createPtr("test." + Doc::EXT);

    BOOST_CHECK_THROW(d->removeDataFile(0U), Exception);

    // Add first Document
    BOOST_CHECK_NO_THROW(d->addDataFile("test1.txt", "text/plain"));
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    if(!d->dataFiles().empty())
    {
        const DataFile *doc1 = d->dataFiles().front();
        if(d->mediaType() == DDoc::TYPE)
            BOOST_CHECK_EQUAL(doc1->id(), "D0");
        BOOST_CHECK_EQUAL(doc1->fileName(), "test1.txt");
        BOOST_CHECK_EQUAL(doc1->mediaType(), "text/plain");
    }

    // Add second Document
    BOOST_CHECK_NO_THROW(d->addDataFile("test2.bin", "text/plain"));
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 2U);
    if(!d->dataFiles().empty())
    {
        const DataFile *doc2 = d->dataFiles().back();
        if(d->mediaType() == DDoc::TYPE)
            BOOST_CHECK_EQUAL(doc2->id(), "D1");
        BOOST_CHECK_EQUAL(doc2->fileName(), "test2.bin");
        BOOST_CHECK_EQUAL(doc2->mediaType(), "text/plain");
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
        BOOST_CHECK_EQUAL(doc3->mediaType(), "text/plain");
    }

    // Remove second Document
    BOOST_CHECK_NO_THROW(d->removeDataFile(0U));
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 0U);

    if(d->mediaType() == DDoc::TYPE)
        return;

    d = Container::openPtr("test." + Doc::EXT);
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
    unique_ptr<Container> d = Container::createPtr("test." + Doc::EXT);

    BOOST_CHECK_THROW(d->removeSignature(0U), Exception);

    unique_ptr<Signer> signer1(new PKCS12Signer("signer1.p12", "signer1"));
    signer1->setProfile("time-mark");
    BOOST_CHECK_THROW(d->sign(signer1.get()), Exception);
    if(Doc::EXT == DDoc::EXT)
        return;

    // Add first Signature
    BOOST_CHECK_NO_THROW(d->addDataFile("test1.txt", "text/plain"));
    BOOST_CHECK_NO_THROW(d->sign(signer1.get()));
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    if(d->signatures().size() == 1)
    {
        BOOST_CHECK_EQUAL(d->signatures().at(0)->signingCertificate(), signer1->cert());
        BOOST_CHECK_NO_THROW(d->signatures().at(0)->validate());
    }
    BOOST_CHECK_NO_THROW(d->save(Doc::EXT + ".tmp"));

    // Signed container cannot add and remove documents
    BOOST_CHECK_THROW(d->addDataFile("test1.txt", "text/plain"), Exception);
    BOOST_CHECK_THROW(d->removeDataFile(0U), Exception);

    // Add second Signature
    unique_ptr<Signer> signer2(new PKCS12Signer("signer2.p12", "signer2"));
    BOOST_CHECK_NO_THROW(d->sign(signer2.get()));
    BOOST_CHECK_EQUAL(d->signatures().size(), 2U);
    if(d->signatures().size() == 2)
    {
        BOOST_CHECK_EQUAL(d->signatures().at(1)->signingCertificate(), signer2->cert());
        BOOST_CHECK_NO_THROW(d->signatures().at(1)->validate());
    }
    BOOST_CHECK_NO_THROW(d->save());

    // Remove first Signature
    BOOST_CHECK_NO_THROW(d->removeSignature(0U));
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    if(d->signatures().size() == 1)
        BOOST_CHECK_EQUAL(d->signatures().at(0)->signingCertificate(), signer2->cert());

    if(d->mediaType() == ASiCE::TYPE)
    {
        unique_ptr<Signer> signer3(new PKCS12Signer("signerEC.p12", "signerEC"));
        Signature *s3 = nullptr;
        BOOST_CHECK_NO_THROW(s3 = d->sign(signer3.get()));
        BOOST_CHECK_EQUAL(d->signatures().size(), 2U);
        if(s3)
        {
            BOOST_CHECK_EQUAL(s3->signingCertificate(), signer3->cert());
            BOOST_CHECK_NO_THROW(s3->validate());
        }
        BOOST_CHECK_NO_THROW(d->save());

        // Reload from file and validate
        d = Container::openPtr(Doc::EXT + ".tmp");
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

        // Save with no SignatureValue and later add signautre value, time-mark
        signer2->setProfile("time-mark");
        d = Container::createPtr(Doc::EXT + ".tmp");
        BOOST_CHECK_NO_THROW(d->addDataFile("test1.txt", "text/plain"));
        Signature *s = nullptr;
        BOOST_CHECK_NO_THROW(s = d->prepareSignature(signer2.get()));
        vector<unsigned char> signatureValue;
        BOOST_CHECK_NO_THROW(signatureValue = signer2->sign(s->signatureMethod(), s->dataToSign()));
        BOOST_CHECK_NO_THROW(d->save());
        d = Container::openPtr(Doc::EXT + ".tmp");
        s = d->signatures().back();
        BOOST_CHECK_NO_THROW(s->setSignatureValue(signatureValue));
        BOOST_CHECK_NO_THROW(s->extendSignatureProfile(signer2->profile()));
        BOOST_CHECK_NO_THROW(d->save());
        BOOST_CHECK_NO_THROW(s->validate());
    }

    // Remove second Signature
    BOOST_CHECK_NO_THROW(d->removeSignature(0U));
    BOOST_CHECK_EQUAL(d->signatures().size(), 0U);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(files, Doc, DocTypes)
{
    unique_ptr<Signer> signer1(new PKCS12Signer("signer1.p12", "signer1"));
    for(const string &data : {"0123456789~#%&()=`@{[]}'", "öäüõ"})
    {
        unique_ptr<Container> d = Container::createPtr("test." + Doc::EXT);
        const Signature *s1 = nullptr;
        BOOST_CHECK_NO_THROW(d->addDataFile(data + ".txt", "text/plain"));
        if(Doc::EXT == DDoc::EXT)
            return;
        BOOST_CHECK_NO_THROW(s1 = d->sign(signer1.get()));
        if(s1)
            s1->validate();
        d->save(data + Doc::EXT + ".tmp");
        d = Container::openPtr(data + Doc::EXT + ".tmp");
        BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
        s1 = d->signatures().front();
        s1->validate();
    }
}

BOOST_AUTO_TEST_CASE_TEMPLATE(signatureParameters, Doc, DocTypes)
{
    unique_ptr<Container> d = Container::createPtr("test." + Doc::EXT);
    unique_ptr<Signer> signer1(new PKCS12Signer("signer1.p12", "signer1"));

    signer1->setSignatureProductionPlace("Tartu", "Tartumaa", "12345", "Estonia");

    vector<string> roles;
    roles.emplace_back("Role1");
    signer1->setSignerRoles( roles );

    const Signature *s1 = nullptr;
    BOOST_CHECK_NO_THROW(d->addDataFile("test1.txt", "text/plain"));
    BOOST_CHECK_NO_THROW(d->addDataFile("test2.bin", "text/plain"));
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
        time_t t = time(nullptr);
        string time = util::date::xsd2string(util::date::makeDateTime(util::date::gmtime(t)));
        BOOST_WARN_EQUAL(s1->claimedSigningTime().substr(0, 16), time.substr(0, 16));
        BOOST_WARN_EQUAL(s1->OCSPProducedAt().substr(0, 16), time.substr(0, 16));
        BOOST_CHECK_EQUAL(s1->OCSPCertificate().subjectName("CN"), "TEST of SK OCSP RESPONDER 2011");
    }

    BOOST_CHECK_NO_THROW(d->save(Doc::EXT + ".tmp")); //Check if reloading and binary files work
    d = Container::openPtr(Doc::EXT + ".tmp");
    if(d->signatures().size() == 1U)
        BOOST_CHECK_NO_THROW(d->signatures().front()->validate());

    unique_ptr<Signer> signer3(new PKCS12Signer("signer3.p12", "signer3"));
    BOOST_CHECK_THROW(d->sign(signer3.get()), Exception); // OCSP UNKNOWN
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ConfSuite)
BOOST_AUTO_TEST_CASE(XmlConfCase) {
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

BOOST_AUTO_TEST_SUITE(FileUtilSuite)
BOOST_AUTO_TEST_CASE(FromUriPathConvertsAsciiEncodingToCharacters)
{
    const std::string asciiEncodedStr = "%3dtest%20%40";
    const std::string expectedDecodedStr = "=test @";

    string result = util::File::fromUriPath(asciiEncodedStr);

    BOOST_CHECK_EQUAL(expectedDecodedStr, result);
}

BOOST_AUTO_TEST_CASE(FromUriPathDoesNotConvertIncompleteAsciiCode)
{
    const std::string asciiEncodedStr = "%3dtest%20%4";
    const std::string expectedDecodedStr = "=test %4";

    string result = util::File::fromUriPath(asciiEncodedStr);

    BOOST_CHECK_EQUAL(expectedDecodedStr, result);
}

BOOST_AUTO_TEST_CASE(FromUriPathPreservesTrailingPercentageSign)
{
    const std::string asciiEncodedStr = "%3dtest%20%";
    const std::string expectedDecodedStr = "=test %";

    string result = util::File::fromUriPath(asciiEncodedStr);

    BOOST_CHECK_EQUAL(expectedDecodedStr, result);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ASiCSTestSuite)
BOOST_AUTO_TEST_CASE(OpenValidASiCSContainer)
{
    unique_ptr<Container> d = Container::openPtr("test.asics");
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    BOOST_CHECK_EQUAL(d->mediaType(), ASiCS::TYPE);

    const DataFile *doc = d->dataFiles().front();
    BOOST_CHECK_EQUAL(doc->fileName(), "test1.txt");

    const auto ts = d->signatures().front();
    BOOST_CHECK_NO_THROW(ts->validate());
    if(ts)
    {
        BOOST_CHECK_EQUAL("8766262679921277358", ts->id()); // Serial number: 0x79A805763478B9AE
        BOOST_WARN_EQUAL("2016-11-02T11:07:45Z", ts->TimeStampTime().substr(0, 16));
        BOOST_CHECK_EQUAL("DEMO of SK TSA 2014", ts->TimeStampCertificate().subjectName("CN"));
    }
}

BOOST_AUTO_TEST_CASE(OpenValidASiCSContainerWithOtherMeta)
{
    unique_ptr<Container> d = Container::openPtr("test-meta.asics");
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    BOOST_CHECK_EQUAL(d->mediaType(), ASiCS::TYPE);

    const DataFile *doc = d->dataFiles().front();
    BOOST_CHECK_EQUAL(doc->fileName(), "test1.txt");

    const auto ts = d->signatures().front();
    BOOST_CHECK_NO_THROW(ts->validate());
}

BOOST_AUTO_TEST_CASE(OpenInvalidTsASiCSContainer)
{
    unique_ptr<Container> d = Container::openPtr("test-invalidts.asics");
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    BOOST_CHECK_EQUAL(d->mediaType(), ASiCS::TYPE);

    const DataFile *doc = d->dataFiles().front();
    BOOST_CHECK_EQUAL(doc->fileName(), "test2.txt");

    const auto ts = d->signatures().front();
    BOOST_CHECK_THROW(ts->validate(), Exception);
}

BOOST_AUTO_TEST_CASE(TeRaASiCSContainer)
{
    unique_ptr<Container> d = Container::openPtr("test-tera.asics");
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    BOOST_CHECK_EQUAL(d->mediaType(), ASiCS::TYPE);

    const DataFile *doc = d->dataFiles().front();
    BOOST_CHECK_EQUAL(doc->fileName(), "ddoc_for_testing.ddoc");
    BOOST_CHECK_EQUAL(doc->fileSize(), 8736U);

    const auto ts = d->signatures().front();
    BOOST_CHECK_NO_THROW(ts->validate());

    BOOST_WARN_EQUAL("2017-04-10T06:27:28Z", ts->TimeStampTime().substr(0, 19));
    BOOST_CHECK_EQUAL("DEMO of SK TSA 2014", ts->TimeStampCertificate().subjectName("CN"));
}

BOOST_AUTO_TEST_CASE(TeRaEmptyASiCSContainer)
{
    unique_ptr<Container> d = Container::openPtr("test-tera-empty.asics");
    BOOST_CHECK_EQUAL(d->dataFiles().size(), 1U);
    BOOST_CHECK_EQUAL(d->signatures().size(), 1U);
    BOOST_CHECK_EQUAL(d->mediaType(), ASiCS::TYPE);

    const DataFile *doc = d->dataFiles().front();
    BOOST_CHECK_EQUAL(doc->fileName(), "emptyFile.ddoc");
    BOOST_CHECK_EQUAL(doc->fileSize(), 0U);

    const auto ts = d->signatures().front();
    BOOST_CHECK_NO_THROW(ts->validate());
}

BOOST_AUTO_TEST_CASE(OpenInvalidMimetypeContainer)
{
    BOOST_CHECK_THROW(Container::openPtr("test-invalid.asics"), Exception);
}
BOOST_AUTO_TEST_SUITE_END()
