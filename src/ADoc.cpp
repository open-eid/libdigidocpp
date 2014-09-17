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

#include "ADoc.h"

#include "log.h"
#include "Signature.h"

using namespace digidoc;

ADoc::ADoc()
{
}

ADoc::~ADoc()
{
}

/**
 * Returns unique signature id
 *
 * @returns unique signature id
 */
unsigned int ADoc::newSignatureId() const
{
    SignatureList list = signatures();
    unsigned int id = 0;
    while(true)
    {
        bool found = false;
        for(SignatureList::const_iterator i = list.begin(); i != list.end(); ++i)
        {
            if((*i)->id() == Log::format("S%u", id))
            {
                found = true;
                break;
            }
        }
        if(!found)
            return id;
        ++id;
    }
    return id;
}
