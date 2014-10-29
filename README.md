# libdigidocpp

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority

## Building
[![Build Status](https://travis-ci.org/open-eid/libdigidocpp.svg?branch=master)](https://travis-ci.org/open-eid/libdigidocpp)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/727/badge.svg)](https://scan.coverity.com/projects/727)

### Ubuntu

1. Install dependencies

        sudo apt-get install cmake libxml-security-c-dev xsdcxx libssl-dev

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        /usr/local/bin/digidoc-tool
        
### OSX

1. Install dependencies from [http://www.cmake.org](http://www.cmake.org)

        sh prepare_osx_build_environment.sh all

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        /usr/local/bin/digidoc-tool

## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds.

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
