#include "GadgetFinder/GadgetFinder.hpp"
#include <iostream>

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {

	GadgetFinder::GadgetFinderCreateInfo createInfo = {
		.executablePath = "C:\\Users\\Sam\\Desktop\\ntoskrnl.exe"
	};
	
	GadgetFinder::GadgetFilter createInfoGadgetFilter = {
		.gadgetLength = 5,
		.maxLookbackLength = 100,
		.maxNumOfGadgets = 10,
		.excludeIndirectCalls = true,
		.otherExcludeInstructions = {}
	};

	createInfo.pGadgetFilter = &createInfoGadgetFilter;
	std::unique_ptr<GadgetFinder> gadgetFinder = std::make_unique<GadgetFinder>(&createInfo);
	std::unique_ptr<GadgetFinder::GadgetInfo> pGadgetInfo = gadgetFinder->AcquireGadgetInfo();
	
	printf("[INFO] Found %zd gadgets\n[INFO] Found %zd filtered gadgets\n\n",
		pGadgetInfo->unfilteredGadgets.size(),
		pGadgetInfo->filteredGadgets.size());

	for (GadgetFinder::Gadget gadget : pGadgetInfo->filteredGadgets) {
		for (size_t i = 0; i < gadget.instructions.size(); ++i) {
			std::cout << "0x" << std::hex << gadget.instructions.at(i).address
				<< ": " << gadget.instructions.at(i).mnemonic << " : " << gadget.instructions.at(i).op_str
				<< std::endl;
		}
		std::cout << "===" << std::endl;
	}

	return EXIT_SUCCESS;
}