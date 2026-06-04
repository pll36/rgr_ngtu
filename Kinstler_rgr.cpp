#include "my_ciphers.h"

#include <vector>
#include <algorithm>

// ?????????????????????????????????????????????
//  UTF-8 <-> UTF-32 conversion
//  (no <locale>, no <codecvt>, no alphabet tables)
// ?????????????????????????????????????????????

static std::u32string utf8ToUtf32(const std::string& source)
{
    std::u32string result;
    size_t index = 0;

    while (index < source.size())
    {
        unsigned char byte = static_cast<unsigned char>(source[index]);
        char32_t codepoint = 0;
        int extraBytes = 0;

        if (byte < 0x80)
        {
            codepoint = byte;
            extraBytes = 0;
        }
        else if (byte < 0xC0)
        {
            // Continuation byte without a leading byte — skip it
            ++index;
            continue;
        }
        else if (byte < 0xE0)
        {
            codepoint = byte & 0x1F;
            extraBytes = 1;
        }
        else if (byte < 0xF0)
        {
            codepoint = byte & 0x0F;
            extraBytes = 2;
        }
        else
        {
            codepoint = byte & 0x07;
            extraBytes = 3;
        }

        ++index;

        for (int extra = 0; extra < extraBytes; ++extra)
        {
            if (index >= source.size())
            {
                break;
            }

            unsigned char continuation =
                static_cast<unsigned char>(source[index]);

            codepoint = (codepoint << 6) | (continuation & 0x3F);
            ++index;
        }

        result += codepoint;
    }

    return result;
}

static std::string utf32ToUtf8(const std::u32string& source)
{
    std::string result;

    for (char32_t codepoint : source)
    {
        if (codepoint < 0x80)
        {
            result += static_cast<char>(codepoint);
        }
        else if (codepoint < 0x800)
        {
            result += static_cast<char>(0xC0 | (codepoint >> 6));
            result += static_cast<char>(0x80 | (codepoint & 0x3F));
        }
        else if (codepoint < 0x10000)
        {
            result += static_cast<char>(0xE0 | (codepoint >> 12));
            result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (codepoint & 0x3F));
        }
        else
        {
            result += static_cast<char>(0xF0 | (codepoint >> 18));
            result += static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F));
            result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (codepoint & 0x3F));
        }
    }

    return result;
}

// ?????????????????????????????????????????????
//  Columnar transposition
// ?????????????????????????????????????????????

struct KeyPosition
{
    char symbol;
    int originalIndex;
};

static std::vector<int> buildColumnOrder(const std::string& key)
{
    std::vector<KeyPosition> positions;

    for (int i = 0; i < static_cast<int>(key.size()); ++i)
    {
        positions.push_back({ key[i], i });
    }

    std::sort(
        positions.begin(),
        positions.end(),
        [](const KeyPosition& leftPosition,
            const KeyPosition& rightPosition)
        {
            if (leftPosition.symbol == rightPosition.symbol)
            {
                return leftPosition.originalIndex < rightPosition.originalIndex;
            }

            return leftPosition.symbol < rightPosition.symbol;
        });

    std::vector<int> columnOrder;

    for (const KeyPosition& position : positions)
    {
        columnOrder.push_back(position.originalIndex);
    }

    return columnOrder;
}

// Padding character used to fill the last row of the table.
// Must not appear in normal Unicode text.
static const char32_t PADDING_CHAR = U'\U0010FFFD';

std::string encryptColumnar(
    const std::string& text,
    const std::string& key)
{
    if (key.empty())
    {
        return text;
    }

    // Work in Unicode codepoints so multi-byte characters are never split.
    std::u32string unicodeText = utf8ToUtf32(text);

    int columns = static_cast<int>(key.size());
    int rows =
        (static_cast<int>(unicodeText.size()) + columns - 1) / columns;

    std::vector<std::vector<char32_t>> table(
        rows,
        std::vector<char32_t>(columns, PADDING_CHAR));

    int position = 0;

    for (int row = 0; row < rows; ++row)
    {
        for (int column = 0; column < columns; ++column)
        {
            if (position < static_cast<int>(unicodeText.size()))
            {
                table[row][column] = unicodeText[position++];
            }
        }
    }

    std::vector<int> columnOrder = buildColumnOrder(key);

    std::u32string unicodeResult;

    for (int column : columnOrder)
    {
        for (int row = 0; row < rows; ++row)
        {
            unicodeResult += table[row][column];
        }
    }

    return utf32ToUtf8(unicodeResult);
}

std::string decryptColumnar(
    const std::string& text,
    const std::string& key)
{
    if (key.empty())
    {
        return text;
    }

    std::u32string unicodeText = utf8ToUtf32(text);

    int columns = static_cast<int>(key.size());
    int rows = static_cast<int>(unicodeText.size()) / columns;

    std::vector<std::vector<char32_t>> table(
        rows,
        std::vector<char32_t>(columns));

    std::vector<int> columnOrder = buildColumnOrder(key);

    int position = 0;

    for (int column : columnOrder)
    {
        for (int row = 0; row < rows; ++row)
        {
            table[row][column] = unicodeText[position++];
        }
    }

    std::u32string unicodeResult;

    for (int row = 0; row < rows; ++row)
    {
        for (int column = 0; column < columns; ++column)
        {
            unicodeResult += table[row][column];
        }
    }

    // Strip padding added during encryption
    while (!unicodeResult.empty() && unicodeResult.back() == PADDING_CHAR)
    {
        unicodeResult.pop_back();
    }

    return utf32ToUtf8(unicodeResult);
}

// ?????????????????????????????????????????????
//  TEA block cipher
// ?????????????????????????????????????????????

static uint32_t bytesToUint32(const unsigned char* bytes)
{
    uint32_t value = 0;

    value |= static_cast<uint32_t>(bytes[0]);
    value |= static_cast<uint32_t>(bytes[1]) << 8;
    value |= static_cast<uint32_t>(bytes[2]) << 16;
    value |= static_cast<uint32_t>(bytes[3]) << 24;

    return value;
}

static void uint32ToBytes(uint32_t value, unsigned char* bytes)
{
    bytes[0] = value & 0xFF;
    bytes[1] = (value >> 8) & 0xFF;
    bytes[2] = (value >> 16) & 0xFF;
    bytes[3] = (value >> 24) & 0xFF;
}

static void encryptTeaBlock(
    uint32_t& leftWord,
    uint32_t& rightWord,
    const TeaKey& key)
{
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9;

    for (int round = 0; round < 32; ++round)
    {
        sum += delta;

        leftWord +=
            ((rightWord << 4) + key.values[0]) ^
            (rightWord + sum) ^
            ((rightWord >> 5) + key.values[1]);

        rightWord +=
            ((leftWord << 4) + key.values[2]) ^
            (leftWord + sum) ^
            ((leftWord >> 5) + key.values[3]);
    }
}

static void decryptTeaBlock(
    uint32_t& leftWord,
    uint32_t& rightWord,
    const TeaKey& key)
{
    const uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta * 32;

    for (int round = 0; round < 32; ++round)
    {
        rightWord -=
            ((leftWord << 4) + key.values[2]) ^
            (leftWord + sum) ^
            ((leftWord >> 5) + key.values[3]);

        leftWord -=
            ((rightWord << 4) + key.values[0]) ^
            (rightWord + sum) ^
            ((rightWord >> 5) + key.values[1]);

        sum -= delta;
    }
}

std::string encryptTEA(
    const std::string& text,
    const TeaKey& key)
{
    std::vector<unsigned char> data(text.begin(), text.end());

    // Pad to a multiple of 8 bytes
    while (data.size() % 8 != 0)
    {
        data.push_back(0);
    }

    for (size_t offset = 0; offset < data.size(); offset += 8)
    {
        uint32_t leftWord = bytesToUint32(&data[offset]);
        uint32_t rightWord = bytesToUint32(&data[offset + 4]);

        encryptTeaBlock(leftWord, rightWord, key);

        uint32ToBytes(leftWord, &data[offset]);
        uint32ToBytes(rightWord, &data[offset + 4]);
    }

    return std::string(data.begin(), data.end());
}

std::string decryptTEA(
    const std::string& text,
    const TeaKey& key)
{
    std::vector<unsigned char> data(text.begin(), text.end());

    for (size_t offset = 0; offset < data.size(); offset += 8)
    {
        uint32_t leftWord = bytesToUint32(&data[offset]);
        uint32_t rightWord = bytesToUint32(&data[offset + 4]);

        decryptTeaBlock(leftWord, rightWord, key);

        uint32ToBytes(leftWord, &data[offset]);
        uint32ToBytes(rightWord, &data[offset + 4]);
    }

    // Strip zero-padding added during encryption
    while (!data.empty() && data.back() == 0)
    {
        data.pop_back();
    }

    return std::string(data.begin(), data.end());
}