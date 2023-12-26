#include "GadgetFinder.hpp"

GadgetFinder::GadgetFinder(GadgetFinderCreateInfo* create_info) : m_CreateInfo(create_info) {

    // check for valid ptr
    if (create_info == nullptr) {
        throw std::runtime_error("invalid create info pointer");
    }

    // check for empty string
    if (create_info->executablePath.empty()) {
        throw std::runtime_error("invalid file path specified");
    }

    // check if file exists
    if (!std::filesystem::exists(create_info->executablePath)) {
        throw std::runtime_error("no such file exists");
    }
    
    // put the binary info of the file into a var
    std::ifstream file(create_info->executablePath, std::ios::binary);
   
    printf("[INFO] Loading %s\n", std::filesystem::path(create_info->executablePath).filename().string().c_str());
    
    // check if we can open the file
    if (!file.is_open()) {
        throw std::runtime_error("error opening file");
    }

    // read the DOS header of the file
    IMAGE_DOS_HEADER dosHeader{};
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));

    printf("[INFO] Reading file's DOS header\n");

    // check for MZ
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        throw std::runtime_error("invalid DOS executable");
    }

    // go to beginning
    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    // read the NT headers
    IMAGE_NT_HEADERS ntHeaders{};
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));

    printf("[INFO] Reading file's NT headers\n");

    // compare signature
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        throw std::runtime_error("invalid PE file");
    }

    if (ntHeaders.FileHeader.Machine != MACHINE_CODE_64_BIT) {
        throw std::runtime_error("this program does not support 32bit");
    }

    printf("[INFO] Locating .TEXT section\n");

    for (size_t i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader{};
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER));

        if (_strcmpi(".text", reinterpret_cast<char*>(sectionHeader.Name)) == 0) {
            printf("[INFO] Found .TEXT section at [%x]\n", sectionHeader.VirtualAddress);

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
        throw std::runtime_error("failed to find section data");
    }

    file.close();
}

std::pair<cs_insn*, size_t> GadgetFinder::DissasembleBytes(csh capstone_handle, std::vector<uint8_t> bytes, uint64_t rva) {
    cs_insn* result = nullptr;

    if (bytes.empty()) {
        if (ANNOUNCE_FAILURE_MESSAGES) {
            printf("[FAIL] cannot disassemble invalid byte array\n");
        }
        return { nullptr, 0 };
    }

    size_t count = cs_disasm(capstone_handle, bytes.data(), bytes.size(), rva, 0, &result);
    if (count == 0) {
        if (ANNOUNCE_FAILURE_MESSAGES) {
            printf("[FAIL] failed to disassemble bytes\n");
        }
        return { nullptr, 0 };
    }

    return { result, count };
}

std::unique_ptr<GadgetFinder::GadgetInfo> GadgetFinder::AcquireGadgetInfo() {
    std::unique_ptr<GadgetInfo> result = std::make_unique<GadgetInfo>();

    // check for valid instruction array
    if (this->m_SectionEntry.data.empty()) {
        throw std::runtime_error("no section data");
    }

    // check to see if max instructions is valid
    if (this->m_CreateInfo->pGadgetFilter->gadgetLength <= 0) {
        throw std::runtime_error("gadget length cannot be zero or less");
    }

    if (this->m_CreateInfo->pGadgetFilter->maxNumOfGadgets < 0) {
        throw std::runtime_error("gadgets size cannot be less than zero");
    }

    if (this->m_CreateInfo->pGadgetFilter->maxLookbackLength < 0) {
        throw std::runtime_error("gadgets lookback length cannot be less than zero");
    }

    // establish a handle to the capstone dissasembly engine
    csh capstoneEngineHandle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstoneEngineHandle) != CS_ERR_OK) {
        cs_close(&capstoneEngineHandle);
        throw std::runtime_error("failed to initialize Capstone engine");
    }

    // don't get any data we don't need
    cs_option(capstoneEngineHandle, CS_OPT_SKIPDATA, CS_OPT_ON);

    // iterate over all bytes in the text section
    for (size_t idx = 0; idx < this->m_SectionEntry.data.size(); ++idx) {

        // identify return opcodes
        if (this->m_SectionEntry.data.at(idx) == RETURN_OPCODE 
            && (this->m_CreateInfo->pGadgetFilter->maxNumOfGadgets == 0 
            || (this->m_CreateInfo->pGadgetFilter->maxNumOfGadgets > 0
            && result->unfilteredGadgets.size() < this->m_CreateInfo->pGadgetFilter->maxNumOfGadgets))) {

            // establish a lookback length in bytes
            size_t lookbackLength = 0;
            while (lookbackLength <= this->m_CreateInfo->pGadgetFilter->maxLookbackLength) {
                size_t idxStart = idx - lookbackLength;
                auto bytesToDissasemble = std::vector<uint8_t>(m_SectionEntry.data.begin() + idxStart,
                    m_SectionEntry.data.begin() + idx + 1);

                std::pair<cs_insn*, size_t> dissassembledBytes = DissasembleBytes(
                    capstoneEngineHandle,
                    bytesToDissasemble,
                    this->m_SectionEntry.header.VirtualAddress + idxStart);

                if (dissassembledBytes.first == nullptr || dissassembledBytes.second <= this->m_CreateInfo->pGadgetFilter->gadgetLength) {
                    lookbackLength++;
                    continue;
                }

                if (dissassembledBytes.first[dissassembledBytes.second - 1].id != x86_insn::X86_INS_RET) {
                    break;
                }
                
                std::vector<cs_insn> instructions;
                for (size_t j = dissassembledBytes.second - this->m_CreateInfo->pGadgetFilter->gadgetLength;
                    j < dissassembledBytes.second; j++) {
                    instructions.push_back(dissassembledBytes.first[j]);
                }

                Gadget unfilteredGadget = {
                    .rva = this->m_SectionEntry.header.VirtualAddress + idxStart,
                     .data = bytesToDissasemble,
                     .instructions = instructions
                };

                // TODO: remake filter to utalize cs_insn
                if (GadgetPassesFilter(unfilteredGadget, *this->m_CreateInfo->pGadgetFilter)) {
                    result->filteredGadgets.push_back(unfilteredGadget);
                }

                result->unfilteredGadgets.push_back(unfilteredGadget);
                cs_free(dissassembledBytes.first, dissassembledBytes.second);
                break;
            }
        }
    }

    cs_close(&capstoneEngineHandle);
    return result;
}

bool GadgetFinder::GadgetPassesFilter(Gadget gadget, GadgetFilter filter) {
    // TODO: implementation
    return true;
}
