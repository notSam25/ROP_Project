#pragma once
#include <capstone/capstone.h>

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <vector>

constexpr std::uint8_t RETURN_OPCODE = 0xC3;
constexpr std::uint8_t CALL_OPCODE = 0xFF;
constexpr std::uint32_t MACHINE_CODE_64_BIT = 0x8664;
#ifndef ANNOUNCE_FAILURE_MESSAGES
#define ANNOUNCE_FAILURE_MESSAGES false
#endif // !ANNOUNCE_FAILURE_MESSAGES

class GadgetFinder {
public:

	/**
	* A filter for locating gadgets
	* @param gadgetLength: the length of instructions a gadget should have, including the 'ret'
	* @param maxLookbackLength: the length in bytes to find a gadget of gadgetLength
	* @param maxNumOfGadgets: the max number of gadgets to find, or zero if you want to find all of them
	* @param excludeIndirectCalls: a boolean value to exclude gadgets that use registers to return
	* @param otherExcludeInstructions: a vector of instructions to exclude if gadgets contain them
	*/
	struct GadgetFilter {
		size_t gadgetLength;
		size_t maxLookbackLength;
		size_t maxNumOfGadgets;
		bool excludeIndirectCalls;
		const std::vector<std::vector<std::uint8_t>> otherExcludeInstructions;
	};

	struct GadgetFinderCreateInfo {
		const std::string& executablePath;
		GadgetFilter* pGadgetFilter;
	};

	struct Gadget {
		std::uint64_t rva;
		std::vector<std::uint8_t> data;
		std::vector<cs_insn> instructions;
	};

	struct GadgetInfo {
		std::vector<Gadget> filteredGadgets;
		std::vector<Gadget> unfilteredGadgets;
	};
public:
	GadgetFinder(GadgetFinderCreateInfo* create_info);

	std::unique_ptr<GadgetInfo> AcquireGadgetInfo();
private:
	struct SectionHeaderEntry {
		IMAGE_SECTION_HEADER header;
		std::vector<std::uint8_t> data;
	};

	bool GadgetPassesFilter(Gadget gadget, GadgetFilter filter);
	std::pair<cs_insn*, size_t> DissasembleBytes(csh capstone_handle, std::vector<uint8_t> bytes, uint64_t rva);

	GadgetFinderCreateInfo* m_CreateInfo = nullptr;
	SectionHeaderEntry m_SectionEntry;
};