//Run auto-analysis on every binary in a folder
//@author Rirurin
//@category Game Modding
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;


public class AnalyzeAllBinariesInFolder extends GhidraScript {
	@Override
	protected void run() throws Exception {
		var programManager = state.getTool().getService(ProgramManager.class);
		if (programManager == null) {
			throw new IllegalArgumentException("Program Manager is missing");
		}
		var projectManager = state.getProject();
		if (projectManager == null) {
			throw new IllegalArgumentException("Project Manager is missing");
		}
		var currentFolder = projectManager.getProjectData().getRootFolder();
		var folderName = askString("Get Target Folder", "Folder Name");
		var folderParts = folderName.split("/");
		for (var folderPart : folderParts) {
			currentFolder = currentFolder.getFolder(folderPart);
			if (currentFolder == null) {
				throw new IllegalArgumentException("The folder path \"" + folderName + "\" does not exist");
			}
		}
		for (var projectFile : currentFolder.getFiles()) {
			Program currentProject = (Program)projectFile.getDomainObject(this, true, false, monitor);
			println(projectFile.getPathname());
			monitor.checkCancelled();
			var transId = currentProject.startTransaction("Perform auto analysis");
			analyzeAll(currentProject);
			currentProject.endTransaction(transId, true);
			currentProject.save("Performed auto analysis", monitor);
		}
	}
}
