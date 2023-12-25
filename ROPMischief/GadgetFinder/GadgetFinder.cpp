#include "GadgetFinder.hpp"

GadgetFinder::GadgetFinder(GadgetFinderCreateInfo* create_info) : m_CreateInfo(create_info) {

    // check for valid ptr
    if (create_info == nullptr) {
        throw std::exception("invalid create info pointer");
    }

    // check for empty string
    if (create_info->executablePath.empty()) {
        throw std::exception("invalid file path specified");
    }

    // check if file exists
    if (!std::filesystem::exists(create_info->executablePath)) {
        throw std::exception("no such file exists");
    }

    // put the binary info of the file into a var
    std::ifstream file(create_info->executablePath, std::ios::binary);

    // check if we can open the file
    if (!file.is_open()) {
        throw std::exception("error opening file");
    }

    // read the DOS header of the file
    IMAGE_DOS_HEADER dosHeader{};
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));

    // check for MZ
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        throw std::exception("invalid DOS executable");
    }

    // go to beginning
    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    // read the NT headers
    IMAGE_NT_HEADERS ntHeaders{};
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));

    // compare signature
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        throw std::exception("invalid PE file");
    }

    for (size_t i = 0; i < ntHeaders.FileHeader.Characteristics; i++) {
        IMAGE_SECTION_HEADER sectionHeader{};
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER));

        if (_strcmpi(".text", reinterpret_cast<char*>(sectionHeader.Name)) == 0) {
            auto sectionHeaderEntry = SectionHeaderEntry{
                    .header = sectionHeader,
                    .data = std::vector<std::uint8_t>(sectionHeader.Misc.VirtualSize) 
            };

            // go to beginning of section
            file.seekg(sectionHeader.PointerToRawData, std::ios::beg);

            // read section bytes into vector
            file.read(reinterpret_cast<char*>(sectionHeaderEntry.data.data()), sectionHeader.Misc.VirtualSize);

            // save the data
            this->m_SectionEntry = sectionHeaderEntry;
            
            // break out the loop
            break;
        }
    }

    if (m_SectionEntry.data.empty()) {
        throw std::exception("failed to find section data");
    }

    file.close();
}

GadgetFinder::~GadgetFinder() {
}

GadgetFinder::GadgetInfo* GadgetFinder::AqquireGadgetInfo() {
    GadgetInfo* result = new GadgetInfo();

    // check if a gadget obeys the user's filters
    auto passFilter = [](Gadget gadget, GadgetFilter filterRules) -> bool {
        
        if (filterRules.excludeIndirectCalls == true) {
            for (std::uint64_t idx = 0; idx < gadget.data.size(); ++idx) {
                std::uint8_t opcode = gadget.data.at(idx);
                if (opcode == CALL_OPCODE) {
                    
                    // invalid call detected
                    if (idx + 1 >= gadget.data.size() - 2) {
                        return false;
                    }

                    // if the next opcode is a register, that means the gadget
                    // contains an indirect call
                    if (static_cast<int>(gadget.data.at(idx + 1)) >= 208
                         && static_cast<int>(gadget.data.at(idx + 1)) <= 215) {
                        return false;
                    }
                }
            }
        }
        
        for (std::vector<std::uint8_t> exclude : filterRules.otherExcludeInstructions) {
            if (exclude.size() > filterRules.gadgetLength) {
                throw std::exception("bad filter length");
            }

            if (std::search(gadget.data.begin(), gadget.data.end(),
                gadget.data.begin(), gadget.data.end()) != gadget.data.end()) {
                return false;
            }
        }

        return true;
    };

    // check for valid instruction array
    if (this->m_SectionEntry.data.empty()) {
        throw std::exception("no section data");
    }

    // check to see if max instructions is valid
    if (this->m_CreateInfo->pGadgetFilter->gadgetLength <= 0) {
        throw std::exception("gadget length cannot be zero or less");
    }

    // get all end indexs for return opcodes
    std::vector<std::uint64_t> vIdxRetOpcode;
    for (size_t idx = 0; idx < this->m_SectionEntry.data.size(); ++idx) {
        if (this->m_SectionEntry.data.at(idx) == RETURN_OPCODE) {
            vIdxRetOpcode.push_back(idx);
        }
    }
    
    // iterate and add gadgets to result
    for (std::uint64_t idx : vIdxRetOpcode) {
        std::uint64_t startIdx = idx - this->m_CreateInfo->pGadgetFilter->gadgetLength + 1;
        
        if (startIdx < 0) {
            continue;
        }

        Gadget unfilteredGadget = {
            .rva = this->m_SectionEntry.header.VirtualAddress + startIdx,
            .data = std::vector<std::uint8_t>(
                this->m_SectionEntry.data.begin() + startIdx,
                this->m_SectionEntry.data.begin() + idx + 1)
        };

        if (passFilter(unfilteredGadget, *this->m_CreateInfo->pGadgetFilter)) {
            result->filteredGadgets.push_back(unfilteredGadget);
        }
        
        result->unfilteredGadgets.push_back(unfilteredGadget);
    }

    return result;
}