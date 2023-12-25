#pragma once

#include <Windows.h>
#include <string>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

#define RETURN_OPCODE 0xC3
#define CALL_OPCODE 0xFF
#define MACHINE_CODE_64_BIT 0x8664

class GadgetFinder {
public:
	struct GadgetFilter {
		size_t gadgetLength;
		bool excludeIndirectCalls;
		std::vector<std::vector<std::uint8_t>> otherExcludeInstructions;
	};

	struct GadgetFinderCreateInfo {
		const std::string& executablePath;
		GadgetFilter* pGadgetFilter;
	};

	struct Gadget {
		std::uint64_t rva;
		std::vector<std::uint8_t> data;
	};

	struct GadgetInfo {
		std::vector<Gadget> filteredGadgets;
		std::vector<Gadget> unfilteredGadgets;
	};
public:
	GadgetFinder(GadgetFinderCreateInfo* create_info);

	std::unique_ptr<GadgetInfo> AqquireGadgetInfo();
private:
	struct SectionHeaderEntry {
		IMAGE_SECTION_HEADER header;
		std::vector<std::uint8_t> data;
	};

	bool GadgetPassesFilter(Gadget gadget, GadgetFilter filter);

	GadgetFinderCreateInfo* m_CreateInfo = nullptr;
	SectionHeaderEntry m_SectionEntry;
};