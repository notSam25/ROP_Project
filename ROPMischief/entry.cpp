#include "GadgetFinder/GadgetFinder.hpp"
#include <iostream>

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {

	GadgetFinder::GadgetFilter createInfoGadgetFilter = {
		.gadgetLength = 5,
		.maxLookbackLength = 100,
		.maxNumOfGadgets = 0,
		.excludeIndirectCalls = true,
		.otherExcludeInstructions = { {X86_INS_INSB, X86_INS_AND, X86_INS_MOV, X86_INS_ADD, X86_INS_POP, X86_INS_RET} }
	};
	
	GadgetFinder::GadgetFinderCreateInfo createInfo = {
		.executablePath = "C:\\Users\\Sam\\Desktop\\ntoskrnl.exe",
		.pGadgetFilter = &createInfoGadgetFilter
	};

	std::unique_ptr<GadgetFinder> gadgetFinder = std::make_unique<GadgetFinder>(&createInfo);
	auto startClock = std::chrono::high_resolution_clock::now();
	std::unique_ptr<GadgetFinder::GadgetInfo> pGadgetInfo = gadgetFinder->AcquireGadgetInfo();
	auto endClock = std::chrono::high_resolution_clock::now();

	printf("[INFO] Found %zd gadgets\n[INFO] Found %zd filtered gadgets\n",
		pGadgetInfo->unfilteredGadgets.size(),
		pGadgetInfo->filteredGadgets.size());

	auto clockDurationMili = std::chrono::duration_cast<std::chrono::milliseconds>(endClock - startClock);
	std::cout << "[INFO] Time elapsed: " << clockDurationMili.count() << " milliseconds." << std::endl << std::endl;

	// show the first three gadgets
	for (size_t idx = 0; idx < 3; idx++) {
		GadgetFinder::Gadget gadget = pGadgetInfo->filteredGadgets.at(idx);
		for (size_t i = 0; i < gadget.instructions.size(); ++i) {
			std::cout << "0x" << std::hex << gadget.instructions.at(i).address
				<< " " << gadget.instructions.at(i).mnemonic << " : " << gadget.instructions.at(i).op_str
				<< std::endl;
		}
		std::cout << "===" << std::endl;
	}

	return EXIT_SUCCESS;
}