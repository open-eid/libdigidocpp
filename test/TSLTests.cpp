// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#define BOOST_TEST_MODULE "TSL Tests for libdigidocpp"
#include "test.h"

#include <Signature.h>

#include <fstream>

class TSLFixture: public DigiDocPPFixture
{
public:
    TSLFixture()
        : DigiDocPPFixture{boost::unit_test::framework::master_test_suite().argv[
            boost::unit_test::framework::master_test_suite().argc - 3]}
    {
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
