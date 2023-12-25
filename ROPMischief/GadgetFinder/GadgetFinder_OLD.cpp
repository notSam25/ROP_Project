#include "GadgetFinder.hpp"
/*
GadgetFinder::GadgetFinder(const std::string& file_path) {
    
    // check for empty string
	if (file_path.empty()) {
		throw std::exception("invalid file path specified");
	}
	
    // check if file exists
	if (!std::filesystem::exists(file_path)) {
		throw std::exception("no such file exists");
	}

    // put the binary info of the file into a var
    std::ifstream file(file_path, std::ios::binary);

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

    // iterate over sections
    IMAGE_SECTION_HEADER textSectionHeader{};
    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        file.read(reinterpret_cast<char*>(&textSectionHeader), sizeof(IMAGE_SECTION_HEADER));

        if (strncmp(reinterpret_cast<char*>(textSectionHeader.Name), ".text", 8) == 0) {
            break;
        }
    }

    // check to see if text section was found
    if (strncmp(reinterpret_cast<char*>(textSectionHeader.Name), ".text", 8) != 0) {
        throw std::exception("filed to find .TEXT section header");
    }

    this->m_TextSectionStart = static_cast<std::uint64_t>(textSectionHeader.VirtualAddress);
    
    // go to beginning of text section
    file.seekg(textSectionHeader.PointerToRawData, std::ios::beg);

    // allocate size for data
    this->m_TextSectionInstructions = std::vector<std::uint8_t> (textSectionHeader.Misc.VirtualSize);
    
    // read section bytes into vector
    file.read(reinterpret_cast<char*>(this->m_TextSectionInstructions.data()), textSectionHeader.Misc.VirtualSize);

    // close the file
    file.close();
}

GadgetFinder::~GadgetFinder() {
    // nothing
}

std::vector<std::vector<std::uint8_t>> GadgetFinder::GetTextSectionGadgets(size_t gadget_length) {
    std::vector<std::uint64_t> vIdxGadgetRet;

    // check for valid instruction array
    if (this->m_TextSectionInstructions.empty()) {
        throw std::exception("invalid section provided");
    }

    // check to see if max instructions is valid
    if (gadget_length <= 0) {
        throw std::exception("max_gadget_length cannot be zero or less");
    }

    // iterate and find all indexs for return codes
    for (size_t i = 0; i < this->m_TextSectionInstructions.size(); i++) {
        if (this->m_TextSectionInstructions.at(i) == RETURN_OPCODE) {
            vIdxGadgetRet.push_back(i);
        }
    }

    // clear the gadget array and put in all new gadgets
    this->m_TextSectionGadgets.clear();
    for (std::uint64_t idxRet : vIdxGadgetRet) {
        std::uint64_t startIdx = idxRet - gadget_length;

        if (startIdx < 0) {
            continue;
        }

        this->m_TextSectionGadgets.push_back(std::vector<std::uint8_t>(
            this->m_TextSectionInstructions.begin() + startIdx + 1,
            this->m_TextSectionInstructions.begin() + idxRet + 1
        ));
    }

    // return array of gadgets
    return this->m_TextSectionGadgets;
}
*/