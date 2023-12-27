#pragma once
#include <capstone/capstone.h>

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <map>
#include <random>

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
	* gadgetLength: the length of instructions a gadget should have, including the 'ret'
	* maxLookbackLength: the length in bytes to find a gadget of gadgetLength
	* maxNumOfGadgets: the max number of gadgets to find, or zero if you want to find all of them
	* excludeIndirectCalls: a boolean value to exclude gadgets that use registers to return
	* otherExcludeInstructions: a vector of instructions to exclude if gadgets contain them
	*/
	struct GadgetFilter {
		size_t maxGadgetLength;
		size_t maxLookbackLength;
		size_t maxNumOfGadgets;
		bool excludeIndirectCalls;
		const std::vector<std::vector<x86_insn>> otherExcludeInstructions;
	};

	struct GadgetFinderCreateInfo {
		const std::string& executablePath;
		const std::string& sectionToSearch;
		GadgetFilter* pGadgetFilter;
	};

	/**
	* A container for Gadget data
	* rva: the virtual address of the bytes. Note that the byte 
			rva isn't the same as the first instruction rva always.
	* data: the vector of bytes
	* instructions: the instructions of the gadget. 
					Note that the instructions are not all of the instructions of the byte array due to the gadget filter
	*/
	struct Gadget {
		std::uint64_t rva;
		std::vector<cs_insn> instructions;
	};

	struct GadgetInfo {
		std::vector<Gadget> filteredGadgets;
		std::vector<Gadget> unfilteredGadgets;
	};
public:
	GadgetFinder(GadgetFinderCreateInfo* create_info);

	std::unique_ptr<GadgetInfo> AcquireGadgetInfo();
	Gadget* AqquireGadgetFromMap(std::string asm_code);

private:
	struct SectionHeaderEntry {
		IMAGE_SECTION_HEADER header;
		std::vector<std::uint8_t> buffer;
	};

	bool GadgetPassesFilter(Gadget gadget, GadgetFilter filter);
	std::vector<cs_insn> DissasembleBytes(csh capstone_handle, uint8_t* bytes, size_t length, uint64_t rva);
	GadgetFinderCreateInfo* m_CreateInfo = nullptr;
	SectionHeaderEntry m_SectionEntry;
	std::map<std::string, std::vector<GadgetFinder::Gadget>> m_GadgetMap;
};