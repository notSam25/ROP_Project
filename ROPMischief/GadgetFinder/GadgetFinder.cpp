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

std::vector<cs_insn> GadgetFinder::DissasembleBytes(csh capstone_handle, std::vector<uint8_t> bytes, uint64_t rva) {
    std::vector<cs_insn> result;
    cs_insn* buff;
    size_t count = 0;

    // check for valid bytes to dissect
    if (bytes.empty()) {
        if (ANNOUNCE_FAILURE_MESSAGES) {
            printf("[FAIL] cannot disassemble invalid byte array\n");
        }
        return { };
    }

    // dissasemble instructions into buff
    count = cs_disasm(capstone_handle, bytes.data(), bytes.size(), rva, 0, &buff);
    if (count == 0) {
        if (ANNOUNCE_FAILURE_MESSAGES) {
            printf("[FAIL] failed to disassemble bytes\n");
        }
        return { };
    }

    // put buff into result
    for (size_t idx = 0; idx < count; idx++) {
        result.push_back(buff[idx]);
    }

    // cleanup & return
    cs_free(buff, count);
    return result;
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

    // don't skip out on instruction data
    if (cs_option(capstoneEngineHandle, CS_OPT_SKIPDATA, CS_OPT_OFF) != CS_ERR_OK) {
        cs_close(&capstoneEngineHandle);
        throw std::runtime_error("failed to initialize Capstone engine(1)");
    }
    
    // get details for instrucitons
    if (cs_option(capstoneEngineHandle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        cs_close(&capstoneEngineHandle);
        throw std::runtime_error("failed to initialize Capstone engine(1)");
    }

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

                std::vector<cs_insn> dissassembledBytes = DissasembleBytes(
                    capstoneEngineHandle,
                    bytesToDissasemble,
                    this->m_SectionEntry.header.VirtualAddress + idxStart);

                if (dissassembledBytes.size() == 0|| dissassembledBytes.size() <= this->m_CreateInfo->pGadgetFilter->gadgetLength) {
                    lookbackLength++;
                    continue;
                }

                if (dissassembledBytes.at(dissassembledBytes.size() - 1).id != x86_insn::X86_INS_RET) {
                    break;
                }
                
                Gadget unfilteredGadget = {
                    .rva = this->m_SectionEntry.header.VirtualAddress + idxStart,
                     .data = bytesToDissasemble,
                     .instructions = dissassembledBytes
                };

                if (GadgetPassesFilter(unfilteredGadget, *this->m_CreateInfo->pGadgetFilter)) {
                    result->filteredGadgets.push_back(unfilteredGadget);
                }

                result->unfilteredGadgets.push_back(unfilteredGadget);
                break;
            }
        }
    }

    cs_close(&capstoneEngineHandle);
    return result;
}

bool GadgetFinder::GadgetPassesFilter(Gadget gadget, GadgetFilter gadgetFilter) {

    if (gadgetFilter.excludeIndirectCalls) {
        for (const auto& insn : gadget.instructions) {
            if (insn.id == X86_INS_CALL) {
                cs_x86 detail = insn.detail->x86;
                if (detail.op_count == 0) {
                    continue;
                }

                // check if it's an indirect call with register indirection
                if (detail.operands[0].type == X86_OP_REG) {
                    return false;
                }

                // check if it's an indirect call with immediate value
                if (detail.operands[0].type == X86_OP_IMM) {
                    return false;
                }

                // check if it's an indirect call with memory operand
                if (detail.operands[0].type == X86_OP_MEM) {
                    return false;
                }

                // check if it's an indirect call with relative addressing
                if (detail.operands[0].type == X86_OP_MEM &&
                    detail.operands[0].mem.base == X86_REG_RIP) {
                    return false;
                }

                // check if it's an indirect call with multiple operands
                if (detail.op_count > 1) {
                    return false;
                }
            }
        }
    }

    
    for (const cs_insn& insn : gadget.instructions) {
        x86_insn insnID = static_cast<x86_insn>(insn.id);

        for (const std::vector<x86_insn>& filter : gadgetFilter.otherExcludeInstructions) {
            size_t filterIdx = 0; // index to track the progress in the filter sequence

            // iterate over the instructions in the gadget
            for (const cs_insn& gadgetInsn : gadget.instructions) {
                x86_insn gadgetInsnID = static_cast<x86_insn>(gadgetInsn.id);

                // if the current gadget instruction matches the current filter instruction
                if (gadgetInsnID == filter[filterIdx]) {
                    filterIdx++;

                    // if the entire filter sequence is matched, return false
                    if (filterIdx == filter.size()) {
                        return false;
                    }
                }
            }
        }
    }

    return true;
}
