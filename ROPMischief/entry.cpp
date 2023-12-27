#include "GadgetFinder/GadgetFinder.hpp"
#include <iostream>

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
	
	GadgetFinder::GadgetFilter createInfoGadgetFilter = {
		.maxGadgetLength = 5,
		.maxLookbackLength = 10,
		.maxNumOfGadgets = 50000,
		.excludeIndirectCalls = true,
		.otherExcludeInstructions = { }
	};
	
	GadgetFinder::GadgetFinderCreateInfo createInfo = {
		.executablePath = "C:\\Windows\\System32\\ntoskrnl.exe",
		.sectionToSearch = ".text",
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

	GadgetFinder::Gadget* retGadget = gadgetFinder->AqquireGadgetFromMap("ret");
	if (retGadget)
		std::cout << std::hex << retGadget->rva << std::endl;
	else
		std::cout << "failed to find gadget" << std::endl;

	return EXIT_SUCCESS;
}