# SPDX-FileCopyrightText: Estonian Information System Authority
# SPDX-License-Identifier: LGPL-2.1-or-later

from distutils.core import setup

setup(
    name='digidocpp',
    version='${VERSION}',
    license='LGPL-2.1-or-later',
    author='RIA',
    author_email='info@ria.ee',
    url='https://open-eid.github.io/libdigidocpp/',
    description='DigiDoc digital signature library',
    packages=['digidoc'],
    package_dir={'digidoc': 'src'},
    package_data={'digidoc': ['digidoc.py', '_digidoc_python*.so']}
)
