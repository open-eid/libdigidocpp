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

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace digidoc::util
{
struct XMLTextError
{
    enum class Reason
    {
        None,
        InvalidUTF8,
        InvalidXMLCharacter
    };

    constexpr explicit operator bool() const noexcept { return reason != Reason::None; }

    Reason reason {Reason::None};
    size_t offset {};
    uint32_t codePoint {};
};

inline XMLTextError validateXMLText(std::string_view text) noexcept
{
    for(size_t offset = 0; offset < text.size();)
    {
        const auto lead = static_cast<uint8_t>(text[offset]);
        uint32_t codePoint {};
        size_t length {};
        uint32_t minimum {};
        if(lead <= 0x7F)
        {
            codePoint = lead;
            length = 1;
        }
        else if(lead >= 0xC2 && lead <= 0xDF)
        {
            codePoint = lead & 0x1F;
            length = 2;
            minimum = 0x80;
        }
        else if(lead >= 0xE0 && lead <= 0xEF)
        {
            codePoint = lead & 0x0F;
            length = 3;
            minimum = 0x800;
        }
        else if(lead >= 0xF0 && lead <= 0xF4)
        {
            codePoint = lead & 0x07;
            length = 4;
            minimum = 0x10000;
        }
        else
        {
            return {XMLTextError::Reason::InvalidUTF8, offset};
        }

        if(length > text.size() - offset)
            return {XMLTextError::Reason::InvalidUTF8, offset};
        for(size_t i = 1; i < length; ++i)
        {
            const auto continuation = static_cast<uint8_t>(text[offset + i]);
            if((continuation & 0xC0) != 0x80)
                return {XMLTextError::Reason::InvalidUTF8, offset};
            codePoint = (codePoint << 6) | (continuation & 0x3F);
        }
        if(codePoint < minimum || codePoint > 0x10FFFF ||
           (codePoint >= 0xD800 && codePoint <= 0xDFFF))
            return {XMLTextError::Reason::InvalidUTF8, offset};
        if(codePoint != 0x09 && codePoint != 0x0A && codePoint != 0x0D &&
           (codePoint < 0x20 || codePoint == 0xFFFE || codePoint == 0xFFFF))
            return {XMLTextError::Reason::InvalidXMLCharacter, offset, codePoint};
        offset += length;
    }
    return {};
}
}
