//Quickly copy the contents of a vtable from one project to another. In the project that you want to add labels to,
// put your cursor at the start of the vtable.
//@author Rirurin
//@category Game Modding
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeMap;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;


public class CloneVTable extends GhidraScript {
	
	private static Listing GListing;
	private static SymbolTable GSymbol;
	private static Program GProgram;
	public static DecompileOptions GDecompileOptions;
	public static DecompInterface GDecompInterface;
	private static Pattern UnlabelledFunctionMatcher = Pattern.compile("(thunk_)?FUN_[\\da-f]{9}");
	
	public Function getOrCreateFunction(Listing listing, Address addr) {
		var func = listing.getFunctionAt(addr);
		if (func == null) func = createFunction(addr, null);
		return func;
	}
	
	private List<String> GetNamespaceParts(String fullName) {
		List<String> parts = new LinkedList<String>();
		int GenericStack = 0;
		int SearchIndex = 0;
		int NameIndex = 0;
		while (true) {
			var CurrNamespaceIndex = fullName.indexOf("::", SearchIndex);
			if (CurrNamespaceIndex == -1) {
				parts.add(fullName.substring(NameIndex, fullName.length()).replace(" ", "_"));
				break;
			} 
			var CurrentNamePart = fullName.substring(SearchIndex, CurrNamespaceIndex);
			GenericStack += (CurrentNamePart.length() - CurrentNamePart.replace("<", "").length());
			GenericStack -= (CurrentNamePart.length() - CurrentNamePart.replace(">", "").length());
			if (GenericStack == 0) {
				parts.add(fullName.substring(NameIndex, CurrNamespaceIndex).replace(" ", "_"));
				NameIndex = CurrNamespaceIndex + 2;
			}
			SearchIndex = CurrNamespaceIndex + 2;
		}
		return parts;
	}

	@Override
	protected void run() throws Exception {
		GListing = currentProgram.getListing();
		GSymbol = currentProgram.getSymbolTable();
		var projectManager = state.getProject();
		if (projectManager == null) {
			throw new IllegalArgumentException("Project Manager is missing");
		}
		var rootFolder = projectManager.getProjectData().getRootFolder();
		GDecompileOptions = new DecompileOptions();
		GDecompInterface = new DecompInterface();
		GDecompInterface.setOptions(GDecompileOptions);
		GDecompInterface.openProgram(currentProgram);
		GProgram = currentProgram;
		
		var programs = new TreeMap<String, DomainFile>();
		for (var projectFile : rootFolder.getFiles()) {
			programs.put(projectFile.getName(), projectFile);
		}
		var selectedTitle = askChoice(
				"Select Reference Project", "Project Name", 
				new ArrayList<>( programs.keySet()), programs.keySet().toArray()[0]);
		var selectedData = programs.get(selectedTitle);
		var programManager = state.getTool().getService(ProgramManager.class);
		var refProgram = programManager.openProgram(selectedData);
		programManager.setCurrentProgram(GProgram);
		var vtableNSName = askString("Specify VTable Namespace", "Namespace");
		var vtableNamespace = refProgram.getSymbolTable().getNamespace(vtableNSName, null);
		if (vtableNamespace == null) {
			throw new IllegalArgumentException("Could not find the namespace " + vtableNSName);
		}
		var vtableSym = refProgram.getSymbolTable().getSymbols("`vftable'", vtableNamespace);
		if (vtableSym.size() == 0) {
			throw new IllegalArgumentException("Could not find the vtable for " + vtableNSName);
		}
		var startAddress = vtableSym.get(0).getAddress();
		var addressCursor = startAddress;
		Data srcCurrPtr = null;
		while (true) {
			srcCurrPtr = refProgram.getListing().getDataAt(addressCursor);
			var distance = addressCursor.subtract(startAddress);
			addressCursor = addressCursor.add(8);
			if (!srcCurrPtr.isPointer() || (distance > 0 && refProgram.getSymbolTable().getSymbols(addressCursor.subtract(8)).length > 0)) break;
			var srcFuncAddr = toAddr(srcCurrPtr.getValue().toString());
			if (refProgram.getListing().getDataAt(srcFuncAddr) != null) break;
			Function srcFunc = getOrCreateFunction(refProgram.getListing(), srcFuncAddr);
			//println(funcAddr.toString() + " : " + currentFunc.getName(true));
			var targetCurrPtr = GListing.getDataAt(currentAddress.add(distance));
			var targetFuncAddr = toAddr(targetCurrPtr.getValue().toString());
			Function targetFunc = getOrCreateFunction(GListing, targetFuncAddr);
			var nameMatch = UnlabelledFunctionMatcher.matcher(targetFunc.getName());
			// filter out functions that have already been labelled so we don't overwrite those
			if (!nameMatch.find() || !nameMatch.group().equals(targetFunc.getName())) {
				continue;
			}
			targetFunc.setName(srcFunc.getName(), SourceType.ANALYSIS);
			if (!srcFunc.getParentNamespace().isGlobal()) {				
				var namespaceParts = GetNamespaceParts(srcFunc.getParentNamespace().getName(true));
				Namespace parentNamespace = null;
				for (var namespacePart : namespaceParts) {
					var childNamespace = GSymbol.getNamespace(namespacePart, parentNamespace);
					if (childNamespace == null) {
						childNamespace = GSymbol.createNameSpace(parentNamespace, namespacePart, SourceType.ANALYSIS);
					}
					parentNamespace = childNamespace;
				}
				targetFunc.setParentNamespace(parentNamespace);
			}
		}
		GDecompInterface.closeProgram();
		programManager.closeProgram(refProgram, true);
	}
}
