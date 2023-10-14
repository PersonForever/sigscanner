//
// main.cc
//
// Provides some testing functionality.
//

#include "sigscanner.h"

#include <iostream>
#include <chrono>
#include <algorithm>
#include <string>
#include <cassert>
#include <Windows.h>

#ifndef _WIN64
#error "This test tests only x64 binaries, hence all of the patterns will be incorrect on x86!"
#endif

// number of times we'll search for the pattern inside the memory region, just to gather some stable data.
#ifdef _DEBUG
#define MEASUREMENT_SAMPLES 15
#else
#define MEASUREMENT_SAMPLES 100
#endif

using namespace sigscan::literals;

class SigScanPerfTester
{
public:
	SigScanPerfTester(const std::string& module_name, sigscan::BaseMemorySigScanImpl* sigscanner) :
		m_module_name(module_name), m_sigscanner(sigscanner)
	{
		acquire_module_information();

		measure();
	}

	SigScanPerfTester() = delete;
	SigScanPerfTester(const SigScanPerfTester&) = delete;
	SigScanPerfTester(SigScanPerfTester&&) = delete;

	inline float duration() const { return m_avg_duration; }
	inline uintptr_t result() const { return (uintptr_t)m_scan_result; }

	inline uintptr_t module_base() const { return m_module_base; }
	inline uintptr_t module_size() const { return m_size_of_image; }

private:
	void measure()
	{
		for (size_t i = 0; i < MEASUREMENT_SAMPLES; i++)
		{
			if (!time_search_add_result())
			{
				return; // pattern not found, doesn't have to time.
			}
		}

		// compute average
		for (auto& sample : m_scan_duration_samples)
		{
			m_avg_duration += sample.count();
		}

		m_avg_duration /= m_scan_duration_samples.size();
	}

	inline bool time_search_add_result()
	{
		auto start = std::chrono::high_resolution_clock::now();
		m_scan_result = m_sigscanner->search_in_address_space(m_module_base, m_module_base + m_size_of_image);
		auto end = std::chrono::high_resolution_clock::now();

		if (!m_scan_result)
		{
			return false; // exit the scan early if not found
		}

		m_scan_duration_samples.push_back(end - start);
		return true;
	}

	void acquire_module_information()
	{
		HANDLE h_module = GetModuleHandleA(m_module_name.data());
		if (!h_module)
		{
			// try to load the module
			h_module = LoadLibraryA(m_module_name.data());
		}
		_ASSERTE(h_module != NULL);

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(h_module);
		auto nt_hdrs = reinterpret_cast<PIMAGE_NT_HEADERS>((uint8_t*)h_module + dos->e_lfanew);

		m_module_base = (uintptr_t)h_module;
		m_size_of_image = nt_hdrs->OptionalHeader.SizeOfImage;
		_ASSERTE(m_size_of_image != NULL);
	}

private:
	std::string m_module_name{};
	uintptr_t m_module_base{}, m_size_of_image{};

	std::vector<std::chrono::duration<float, std::ratio<1, 1>>> m_scan_duration_samples{};
	float m_avg_duration{};

	sigscan::BaseMemorySigScanImpl* m_sigscanner{};

	uintptr_t* m_scan_result{};
};

template<class T>
class BaseSigScanComparatorPerfTester
{
public:
	BaseSigScanComparatorPerfTester(sigscan::sigstr sig, std::string_view fn_name, const std::string& module_name)
	{
		T linearsig(sig);

		SigScanPerfTester sigscan(module_name, &linearsig);

		if (!sigscan.result())
		{
			std::cout << "\033[31m" << std::format("{:<65} not found",
												   fn_name) << std::endl;
		}
		else
		{
			std::cout << "\033[32m" << std::format("{:<65} {:<15} 0x{:016X} 0x{:016X} 0x{:016X} {}",
												   fn_name, sigscan.duration(), sigscan.result(),
												   sigscan.module_base(), sigscan.module_size(), module_name) << std::endl;
		}

		std::cout << "\033[0m"; // reset
	}

	BaseSigScanComparatorPerfTester() = delete;
};

using SigScanComparatorPerfTester = BaseSigScanComparatorPerfTester<sigscan::SigSearch>;
using SigScanComparatorPerfTesterIDA = BaseSigScanComparatorPerfTester<sigscan::SigSearchIDA>;

void test_conversion()
{
	sigscan::sigstr code_style = "\x44\x3B\xC7\x0F\x8C\xA4\xFD\xFF\xFF"sig;
	std::string ida = sigscan::detail::ida_to_codestyle("44 3B C7 0F 8C A4 FD FF FF");

	_ASSERTE(code_style == ida);

	//sigscan::detail::ida_to_codestyle("4"); // will assert, sig too short
	//sigscan::detail::ida_to_codestyle("44 3B "); // will assert, ends with a whitespace
	//sigscan::detail::ida_to_codestyle("44 3B X9"); // will assert, has invalid hexadecimal character
}

void test_pattern_stringification()
{
	sigscan::SigSearch sig("\x44\x3B\xC7\x0F\x8C\xA4\xFD\xFF\xFF"sig);

	std::string stringified = sig.stringify_pattern(sigscan::sig_style::code_style);
	_ASSERTE(stringified == "\\x44\\x3B\\xC7\\x0F\\x8C\\xA4\\xFD\\xFF\\xFF");

	std::string stringified1 = sig.stringify_pattern(sigscan::sig_style::ida);
	_ASSERTE(stringified1 == "44 3B C7 0F 8C A4 FD FF FF");
}

void test_pattern_search()
{
	std::cout << std::format("Running mesuarements on {} samples each.", MEASUREMENT_SAMPLES) << std::endl;
	std::cout << std::format("{:<65} {:<15} {:<18} {:<18} {:<18} {}", "module name and function name", "time (s)",
							 "address", "base", "size", "name") << std::endl;
	std::cout << std::format("{:->160}", "") << std::endl;

	// TEST CASE:
	// ntdll.dll!RtlpFcQueryAllFeatureUsageSubscriptionNotificationsFromBufferSet
	{
		SigScanComparatorPerfTester tester(
			"\x40\x53\x48\x83\xEC\x20\x4C\x8B\xCA\x33\xDB\x48\x8B\x51\x38\x48\x85\xD2\x75\x05\x49\x89\x18\xEB\x27\x8B\x0A\x49\x8B\x00"sig,
			"RtlpFcQueryAllFeatureUsageSubscriptionNotificationsFromBufferSet",
			"ntdll.dll");
	}

	// TEST CASE:
	// non-existing pattern inside ntdll.dll
	{
		SigScanComparatorPerfTester tester(
			"\x40\x53\x48\x83\xEF\x57\x4C\x8B\xCA\x32\xDB\x48\x8B\x51\x38\x40\x85\xD2\xFF\x05\x49\x47\x18\xEB\x27\x8B\x0A\x29\x8B\x00"sig,
			"NonExisting",
			"ntdll.dll");
	}

	// TEST CASE:
	// WindowsCodecsRaw.dll!CPentaxK5IIModelFactory__GetValidMakes
	{
		SigScanComparatorPerfTester tester(
			"\x48\x89\x5C\x24\x08\x48\x89\x7C\x24\x18\x55\x48\x8B\xEC\x48\x83\xEC\x60\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\x45\xF0\x48\x8B\xDA\x48\x89\x55\xC8\x33\xFF\x89\x7D\xC0\x48\x89\x3A"sig,
			"CPentaxK5IIModelFactory::GetValidMakes",
			"WindowsCodecsRaw.dll");
	}

	// TEST CASE:
	// ole32.dll!CComCat__GetCategoryDesc
	{
		SigScanComparatorPerfTester tester(
			"\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\xE1\x48\x81\xEC\xC8\x00\x00\x00\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\x45\x0F\x45\x33\xED\x48\x8D\x45\xC7\x4C\x89\x6C\x24\x58\x4D\x8B\xF9\x4C\x89\x6C\x24\x50\x49\x8B\xF0"sig,
			"CComCat::GetCategoryDesc",
			"ole32.dll");
	}

	// TEST CASE:
	// ole32.dll!GetRegistryValue
	{
		SigScanComparatorPerfTester tester(
			"\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x10\x44\x89\x48\x20\x57\x48\x83\xEC\x40\x48\x8B\xD9\x49\x8B\xF0\x48\x8D\x48\xE8\x48\xFF\x15"sig,
			"GetRegistryValue",
			"ole32.dll");
	}

	// TEST CASE:
	// ole32.dll!DestroyEventEntry
	{
		SigScanComparatorPerfTester tester(
			"\x48\x85\xC9\x74\x2E\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\xFF\x15\xCC\xCC\xCC\xCC\x0F\x1F\x44\x00\x00\x4C\x8B\x43\x10\x33\xD2\x48\x8B\xC8\x48\xFF\x15\xCC\xCC\xCC\xCC\x0F\x1F\x44\x00\x00\x48\x83\xC4\x20"sig,
			"DestroyEventEntry",
			"ole32.dll");
	}

	// TEST CASE:
	// combase.dll!COIDHashTable::Compare
	{
		SigScanComparatorPerfTester tester(
			"\x4D\x85\xC0\x74\x22\x49\x8D\x48\xE8\x48\x85\xC9\x74\x19\x4C\x8B\x02\x48\x8B\x41\x40\x49\x2B\x00\x75\x08\x48\x8B\x41\x48\x49\x2B\x40\x08\x48\x85\xC0\x74\x04"sig,
			"COIDHashTable::Compare",
			"combase.dll");
	}

	// TEST CASE:
	// combase.dll!InstrumentPrematureStubRundownFailure
	{
		SigScanComparatorPerfTester tester(
			"\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\x88\xFC\xFF\xFF\x48\x81\xEC\x78\x04\x00\x00\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\x85\x60\x03\x00\x00\x0F\x10\x01\x48\x8B\x05\xCC\xCC\xCC\xCC\x8B\xFA\x48\x8B\xB5\xF0\x03\x00\x00\x0F\x57\xC9\x4C\x8B\xBD\xF8\x03\x00\x00"sig,
			"InstrumentPrematureStubRundownFailure",
			"combase.dll");
	}

	// TEST CASE:
	// combase.dll!CChannelHandle::CChannelHandle
	{
		SigScanComparatorPerfTester tester(
			"\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x54\x41\x56\x41\x57\x48\x83\xEC\x30\xC7\x41\x08\x01\x00\x00\x00\x48\x8D\x05\xCC\xCC\xCC\xCC\x48\x89\x01"sig,
			"CChannelHandle::CChannelHandle",
			"combase.dll");
	}

	// TEST CASE:
	// combase.dll!CheckRefresh
	{
		SigScanComparatorPerfTester tester(
			"\x40\x55\x48\x81\xEC\x90\x00\x00\x00\x48\x8D\x6C\x24\x30\x48\x89\x5D\x70\x48\x89\x75\x78\x48\x89\xBD\x80\x00\x00\x00\x4C\x89\xB5\x88\x00\x00\x00\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x33\xC5\x48\x89\x45\x58\x33\xDB\x49\x8B\xF1\x48\x21\x5D\x08\x4D\x8B\xF0\x21\x5D\x04\x8B\xFA\x48\x85\xC9\x74\x47\x48\x8B\x01\x4C\x8D\x45\x08\x48\x8D\x15"sig,
			"CheckRefresh",
			"combase.dll");
	}

	// TEST CASE:
	// user32.dll!SLEditWndProc
	{
		SigScanComparatorPerfTester tester(
			"\x40\x53\x55\x56\x57\x41\x54\x41\x56\x41\x57\x48\x81\xEC\xA0\x00\x00\x00\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\x84\x24\x90\x00\x00\x00\x4C\x8B\xB4\x24\x00\x01\x00\x00\xB8\xC4\x00\x00\x00\x49\x8B\xE9"sig,
			"SLEditWndProc",
			"user32.dll");
	}

	// TEST CASE:
	// user32.dll!ParseDpiAwarenessElement
	{
		SigScanComparatorPerfTester tester(
			"\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x10\x48\x89\x78\x18\x55\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x68\xA1\x48\x81\xEC\xB0\x00\x00\x00\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\x45\x27"sig,
			"ParseDpiAwarenessElement",
			"user32.dll");
	}

	// TEST CASE:
	// user32.dll!SmoothScrollWindowEx
	{
		SigScanComparatorPerfTester tester(
			"\x48\x8B\xC4\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\xA8\x48\x81\xEC\x58\x01\x00\x00\x0F\x29\x70\xA8\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\x45\x30\x48\x8B\x85\xC0\x00\x00\x00\x4D\x8B\xF9\x83\x64\x24\x74\x00\x45\x8B\xE8\x48\x89\x45\xC8\x8B\xFA"sig,
			"SmoothScrollWindowEx",
			"user32.dll");
	}

	// TEST CASE: (IDA pattern)
	// user32.dll!WinHelpA
	{
		SigScanComparatorPerfTesterIDA tester(
			"48 89 5C 24 08 48 89 54 24 10 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC 50"sig,
			"WinHelpA",
			"user32.dll");
	}
}

int main()
{
	test_conversion();

	test_pattern_stringification();

	test_pattern_search();

	return 0;
}
