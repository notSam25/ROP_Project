#include "GadgetFinder/GadgetFinder.hpp"

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {

	GadgetFinder::GadgetFinderCreateInfo createInfo = {
		.executablePath = "C:\\Users\\Sam\\Desktop\\ntoskrnl.exe"
	};
	
	GadgetFinder::GadgetFilter createInfoGadgetFilter = {
		.gadgetLength = 5,
		.maxLookbackLength = 100,
		.maxNumOfGadgets = 0,
		.excludeIndirectCalls = true,
		.otherExcludeInstructions = {}
	};

	createInfo.pGadgetFilter = &createInfoGadgetFilter;
	
	// suggestion: make all pointers smart
	GadgetFinder* gadgetFinder = new GadgetFinder(&createInfo);
	std::unique_ptr<GadgetFinder::GadgetInfo> pGadgetInfo = gadgetFinder->AqquireGadgetInfo();
	
	printf("[INFO] Found %zd gadgets\n[INFO] Found %zd filtered gadgets\n",
		pGadgetInfo->unfilteredGadgets.size(),
		pGadgetInfo->filteredGadgets.size());

	/*for (GadgetFinder::Gadget gadget : pGadgetInfo->filteredGadgets) {
		for (size_t i = 0; i < gadget.instructions.size(); ++i) {
			std::cout << "0x" << std::hex << gadget.instructions.at(i).address
				<< ": " << gadget.instructions.at(i).mnemonic << " : " << gadget.instructions.at(i).op_str
				<< std::endl;
		}
		std::cout << "===" << std::endl;
	}*/

	delete gadgetFinder;
	return EXIT_SUCCESS;
}