/*
 * Sigscanner
 *
 * Copyright (c) oxiKKK 2023
*/

//
// sigscanner.h -- Byte signature memory scanner.
// 
// Provides functionality to search for byte patterns inside memory.
//

#ifndef SIGSCANNER_H
#define SIGSCANNER_H
#pragma once

#include <cstdint>
#include <string>
#include <format>
#include <vector>
#include <algorithm>
#include <execution>

namespace sigscan
{

enum class sig_style
{
	code_style,
	ida
};

//
// settings
//

// opcode representing runtine that can be relocated.
inline constexpr uint8_t k_relocable_opcode_wildcard = 0xCC;

// mask wildcards
inline constexpr char k_mask_relocable_opcode_char = '?';
inline constexpr char k_mask_opcode_char = 'x';

//
// implementation
//

namespace detail
{

// true if character is in a hexadecimal notation
inline constexpr char is_hex_char(const char c)
{
	return (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9');
}

// convert hexadecimal character into actual number
inline constexpr char hexctoi(const char c)
{
	return (c >= 'A') ? (c - 'A' + 10) : (c - '0');
};

// converts IDA-like byte pattern to code-style pattern.
// e.g.: "44 3B C7 0F 8C A4 FD FF FF" to "\x44\x3B\xC7\x0F\x8C\xA4\xFD\xFF\xFF"
inline std::string ida_to_codestyle(const char* str, size_t length)
{
	_ASSERTE(length >= 2 && "IDA pattern too short."); // mustn't be odd
	_ASSERTE(is_hex_char(str[0]) && is_hex_char(str[1]) && "invalid IDA-style signature.");
	_ASSERTE(str[length - 1] != ' ' && "IDA-style sig cannot end with a whitespace.");

	std::vector<uint8_t> values;
	for (size_t i = 0; i < length;)
	{
		if (str[i] == ' ')
		{
			_ASSERT(length - i >= 2 && "Malformed IDA-style signature.");
			_ASSERT(is_hex_char(str[i + 1]) && is_hex_char(str[i + 2]) && "Malformed IDA-style signature.");
			i++;
		}
		else
		{
			_ASSERT(is_hex_char(str[i]) || str[i] == '?' && "Malformed IDA-style signature.");

			if (str[i] == '?' && str[i + 1] == '?') values.push_back(k_relocable_opcode_wildcard);
			else values.push_back(((uint8_t)hexctoi(str[i]) << 4) | (uint8_t)hexctoi(str[i + 1]));
			i += 2;
		}
	}

	std::string result{};
	std::for_each(values.begin(), values.end(), [&result](const auto& elem) { result += elem; });
	return result;
}

template<size_t N>
inline std::string ida_to_codestyle(const char(&sig)[N])
{
	return ida_to_codestyle(sig, N - 1);
}

// create a mask from sig
inline std::string mask_from_sig(const char* pattern, size_t length)
{
	std::string result;
	for (size_t i = 0; i < length; i++)
		result.push_back(((uint8_t)(pattern[i]) == k_relocable_opcode_wildcard) ? k_mask_relocable_opcode_char : k_mask_opcode_char);
	return result;
}

} // namespace detail

class BaseMemorySigScanImpl
{
public:
	BaseMemorySigScanImpl() = default;
	BaseMemorySigScanImpl(const BaseMemorySigScanImpl&) = default;
	BaseMemorySigScanImpl(BaseMemorySigScanImpl&&) = default;	

public:
	//
	// callables
	//

	// convert pattern to a friendly way
	std::string stringify_pattern(sig_style style = sig_style::code_style) const
	{
		std::string result;
		for (size_t k = 0; k < m_pattern.length(); k++)
		{
			const uint8_t b = m_pattern[k]; // NOTE: has to be an uint8_t!
			switch (style)
			{
				default:
				case sig_style::code_style:
					result += std::format("\\x{:02X}", b);
					break;
				case sig_style::ida:
					result += std::format("{:02X}", b);
					if (k != m_pattern.length() - 1)
						result.push_back(' ');
					break;
			}
		}
		return result;
	}

	// getters
	inline const std::string& pattern() const { return m_pattern; }
	inline const std::string& mask() const { return m_mask; }
	inline uintptr_t offset() const { return m_offset; }

	//
	// searching
	//

	virtual uintptr_t* search_in_address_space(uintptr_t start_addr, uintptr_t end_addr) = 0;

protected:
	//
	// instatiation
	//

	// alternative, to be used at runtime
	inline void instantiate(const char* pattern, size_t length, uintptr_t offset, sig_style style)
	{
		m_offset = offset;
		m_mask = detail::mask_from_sig(pattern, length);

		// NOTE: when using stringview, the string literal length doesn't include the null terminator.
		switch (style)
		{
			case sig_style::code_style:
				m_pattern = std::string(pattern, length);
				break;
			case sig_style::ida: // transform into code-style
				m_pattern = detail::ida_to_codestyle(pattern, length);
				break;
		}
	}

protected:
	std::string m_pattern{}, m_mask{};
	uintptr_t m_offset{};
};

class MemorySigScanSearch : public BaseMemorySigScanImpl
{
public:
	// linear search through memory, searches for the first occurence and returns an address to it.
	uintptr_t* search_in_address_space(uintptr_t start_addr, uintptr_t end_addr) override
	{
		_ASSERTE(start_addr != 0);
		_ASSERTE(end_addr != 0);
		_ASSERTE(end_addr > start_addr);

		bool match_found{ false };
		for (uintptr_t i = start_addr; i < end_addr - m_pattern.length(); i++)
		{
			match_found = true;
			for (size_t k = 0; k < m_pattern.length(); k++)
			{
				// don't match if this is a relocable opcode
				if (m_mask[k] != k_mask_opcode_char)
				{
					continue;
				}

				// NOTE the cast!
				if (m_pattern[k] != *(char*)(i + k))
				{
					match_found = false;
					break;
				}
			}

			if (match_found)
			{
				return reinterpret_cast<uintptr_t*>(i + m_offset);
			}
		}

		return nullptr;
	}
};

// hack
struct sigstr : public std::string_view
{
	constexpr sigstr(const char* p, size_t length) : std::string_view(p, length)
	{
	}
};

// accepts code-style-like signatures, e.g. "\xFF\xFF\xCC\xFF"
class SigSearch : public MemorySigScanSearch
{
public:
	SigSearch(sigstr pattern, uintptr_t offset = 0)
	{
		instantiate(pattern.data(), pattern.length(), offset, sig_style::code_style);
	}
};

// accepts IDA-like signatures, e.g. "FF FF ?? FF"
class SigSearchIDA : public MemorySigScanSearch
{
public:
	SigSearchIDA(sigstr pattern, uintptr_t offset = 0)
	{
		instantiate(pattern.data(), pattern.length(), offset, sig_style::ida);
	}
};

inline namespace literals
{

inline sigstr operator""sig(const char* str, size_t length)
{
	return sigstr(str, length);
}

} // namespace literals

} // namespace sigscan

#endif // SIGSCANNER_H