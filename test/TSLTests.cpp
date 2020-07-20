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

#define BOOST_TEST_MODULE "TSL Tests for libdigidocpp"
#include "test.h"

#include <Signature.h>

#include <fstream>

class TSLFixture: public DigiDocPPFixture
{
public:
    TSLFixture()
    {
        copyTSL(boost::unit_test::framework::master_test_suite().argv[
            boost::unit_test::framework::master_test_suite().argc - 3]);
        digidoc::initialize("untitestboost");
    }
};

BOOST_GLOBAL_FIXTURE(TSLFixture);

BOOST_AUTO_TEST_SUITE(TSLSuite)
BOOST_AUTO_TEST_CASE(TSLCase)
{
    unique_ptr<Container> d = Container::openPtr("tsl.asice");
    const auto ts = d->signatures().front();
    string status = boost::unit_test::framework::master_test_suite().argv[
        boost::unit_test::framework::master_test_suite().argc - 2];
    if(status == "good")
    {
        BOOST_CHECK_NO_THROW(ts->validate());
    }
    else
    {
        BOOST_CHECK_THROW(ts->validate(), Exception);
    }
}

BOOST_AUTO_TEST_SUITE_END()
