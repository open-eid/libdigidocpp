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

#pragma once

#include <boost/test/included/unit_test.hpp>

#include <Container.h>
#include <Conf.h>
#include <Exception.h>
#include <crypto/X509Cert.h>
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

DIGIDOCPP_WARNING_PUSH
DIGIDOCPP_WARNING_DISABLE_MSVC(4996)
class TestConfig: public ConfCurrent
{
public:
	int logLevel() const override { return 4; }
	string logFile() const override { return path + "/libdigidocpp.log"; }
	string xsdPath() const override { return DIGIDOCPPCONF; }
	string ocsp(const string &) const override
	{ return "http://demo.sk.ee/ocsp"; }
	set<string> OCSPTMProfiles() const override {
		set<string> profiles = ConfCurrent::OCSPTMProfiles();
		profiles.emplace("1.3.6.1.4.1.10015.3.1.1");
		return profiles;
	}
	bool PKCS12Disable() const override { return true; }
	string TSUrl() const override { return "http://demo.sk.ee/tsa/"; }
	bool TSLAutoUpdate() const override { return false; }
	string TSLCache() const override { return path; }
	bool TSLOnlineDigest() const override { return false; }
	string TSLUrl() const override { return path + "/TSL.xml"; }
	vector<X509Cert> TSLCerts() const override { return { X509Cert(path + "/TSL.crt", X509Cert::Pem) }; }

	string path = ".";
};
DIGIDOCPP_WARNING_POP

}


class DigiDocPPFixture
{
public:
	DigiDocPPFixture()
	{
		//BOOST_MESSAGE("loading libdigidocpp: " + digidoc::version());
		TestConfig *conf = new TestConfig;
		int argc = boost::unit_test::framework::master_test_suite().argc;
		if(argc > 1)
		{
			//BOOST_MESSAGE("Data path " + string(boost::unit_test::framework::master_test_suite().argv[argc-1]));
DIGIDOCPP_WARNING_PUSH
DIGIDOCPP_WARNING_DISABLE_GCC("-Wunused-result")
			chdir(boost::unit_test::framework::master_test_suite().argv[argc-1]);
DIGIDOCPP_WARNING_POP
			path = conf->path = boost::unit_test::framework::master_test_suite().argv[argc-1];
		}
		boost::unit_test::unit_test_monitor.register_exception_translator<Exception>(&translate_exception);
		Conf::init(conf);
	}

	virtual ~DigiDocPPFixture()
	{
		digidoc::terminate();
		//BOOST_MESSAGE("unloading libdigidocpp");
	}

	static void translate_exception(const Exception &e)
	{
		stringstream s;
		s << endl << e.file() << "(" << e.line() << "): " << e.msg();
		BOOST_ERROR(s.str().c_str());
		for(const Exception &ex: e.causes())
			translate_exception(ex);
	}

	void copyTSL(const string &from)
	{
		ifstream i(util::File::encodeName(from).c_str(), ofstream::binary);
		ofstream o(util::File::encodeName(path + "/EE_T.xml").c_str(), ifstream::binary);
		o << i.rdbuf();
		o.close();
		i.close();
	}

	string path = ".";
};
