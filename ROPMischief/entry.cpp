#include "GadgetFinder/GadgetFinder.hpp"

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
	GadgetFinder::GadgetFinderCreateInfo createInfo = {
		.executablePath = "C:\\Users\\Sam\\Desktop\\ntoskrnl.exe"
	};
	
	GadgetFinder::GadgetFilter createInfoGadgetFilter = {
		.gadgetLength = 5,
		.excludeIndirectCalls = true,
		.otherExcludeInstructions = {}
	};

	createInfo.pGadgetFilter = &createInfoGadgetFilter;
	
	GadgetFinder* gadgetFinder = new GadgetFinder(&createInfo);
	GadgetFinder::GadgetInfo* pGadgetInfo = gadgetFinder->AqquireGadgetInfo();
	
	printf("Found %zd gadgets\nFound %zd filtered gadgets\n",
		pGadgetInfo->unfilteredGadgets.size(),
		pGadgetInfo->filteredGadgets.size());

	delete gadgetFinder;
	return EXIT_SUCCESS;
}
// CFI indirect call checks