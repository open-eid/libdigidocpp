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

#include <SignatureCAdES_T.h>
#include <SignatureCAdES_p.h>

#include <Conf.h>
#include <Exception.h>
#include <log.h>
#include <crypto/Digest.h>
#include <crypto/TS.h>
#include <crypto/X509Cert.h>
#include <util/DateTime.h>

using namespace digidoc;
using namespace digidoc::util::date;
using namespace std;

void SignatureCAdES_T::extendSignatureProfile(const string &profile)
{
    if(profile != "PAdES_BASELINE_T")
        return;
    ASN1_OCTET_STRING *signature = CMS_SignerInfo_get0_signature(d->si);
    Digest digest;
    digest.update(signature->data, signature->length);
    vector<unsigned char> tsa = TS(CONF(TSUrl), digest);
    if(tsa.empty())
        THROW("Failed to add TimeStamp info");
    if(CMS_unsigned_add1_attr_by_NID(d->si, NID_id_smime_aa_timeStampToken, V_ASN1_SEQUENCE, tsa.data(), tsa.size()) != 1)
        THROW("Failed to add TimeStamp info");
}

string SignatureCAdES_T::trustedSigningTime() const
{
    string time = TimeStampTime();
    return time.empty() ? claimedSigningTime() : time;
}

X509Cert SignatureCAdES_T::TimeStampCertificate() const { return ts().cert(); }
string SignatureCAdES_T::TimeStampTime() const { return ASN1TimeToXSD(ts().time()); }

TS SignatureCAdES_T::ts() const
{
    int pos = CMS_unsigned_get_attr_by_NID(d->si, NID_id_smime_aa_timeStampToken, -1);
    if(pos == -1)
        return TS(vector<unsigned char>());
    X509_ATTRIBUTE *attr = CMS_unsigned_get_attr(d->si, pos);
    if(!attr)
        return TS(vector<unsigned char>());
    ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(attr, 0);
    if(!type || type->type != V_ASN1_SEQUENCE)
        return TS(vector<unsigned char>());
    return TS(vector<unsigned char>(type->value.sequence->data, type->value.sequence->data+type->value.sequence->length));
}

void SignatureCAdES_T::validate(const std::string &policy) const
{
    Exception exception(__FILE__, __LINE__, "Signature validation");
    try {
        SignatureCAdES_B::validate(policy);
    } catch(const Exception &e) {
        for(const Exception &ex: e.causes())
            exception.addCause(ex);
    }

    try {
        ASN1_OCTET_STRING *signature = CMS_SignerInfo_get0_signature(d->si);
        Digest digest;
        digest.update(signature->data, signature->length);
        ts().verify(digest);
    } catch(const Exception &e) {
        exception.addCause(e);
    }
    if(!exception.causes().empty())
        throw exception;
}
