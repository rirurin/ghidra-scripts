//Compares the position of labelled functions against a reference project. Designed for Unreal Engine projects.
//@author Rirurin
//@category Game Modding
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;


public class CheckMatchedSymbols extends GhidraScript {
	
	public class NonMatchingFunction {
		public String SourceName;
		public String TargetName;
		public Address EntryPoint;
		
		public NonMatchingFunction(String SourceName, String TargetName, Address EntryPoint) {
			this.SourceName = SourceName;
			this.TargetName = TargetName;
			this.EntryPoint = EntryPoint;
		}
	}
	
	private static Listing GListing;
	private static SymbolTable GSymbol;
	private static Program GProgram;
	private static ReferenceManager GReferences;
	public static DecompileOptions GDecompileOptions;
	public static DecompInterface GDecompInterface;
	private static Pattern UnlabelledFunctionMatcher = Pattern.compile("(thunk_)?FUN_[\\da-f]{9}");
	
	public Function getOrCreateFunction(Address addr) {
		var func = GListing.getFunctionAt(addr);
		if (func == null) func = createFunction(addr, null);
		return func;
	}

	@Override
	protected void run() throws Exception {
		var projectManager = state.getProject();
		if (projectManager == null) {
			throw new IllegalArgumentException("Project Manager is missing");
		}
		var rootFolder = projectManager.getProjectData().getRootFolder();
		GListing = currentProgram.getListing();
		GSymbol = currentProgram.getSymbolTable();
		GReferences = currentProgram.getReferenceManager();
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
				new ArrayList<>(programs.keySet()), programs.keySet().toArray()[0]);
		var selectedData = programs.get(selectedTitle);
		var programManager = state.getTool().getService(ProgramManager.class);
		var refProgram = programManager.openProgram(selectedData);
		programManager.setCurrentProgram(GProgram);
		var namedFunctions = 0;
		var nonMatching = new ArrayList<NonMatchingFunction>();
		for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
			var nameMatch = UnlabelledFunctionMatcher.matcher(function.getName());
			if (nameMatch.find() && nameMatch.group().equals(function.getName())) {
				continue; // filter out functions that are auto-labelled by Ghidra (starts with FUN_ or thunk_FUN_)
			}
			namedFunctions++;
			var refFunction = refProgram.getFunctionManager().getFunctionAt(function.getEntryPoint());
			// function may have multiple names, so check them all
			var funcSymbols = currentProgram.getSymbolTable().getSymbols(function.getEntryPoint());
			var refSymbolsArr = refProgram.getSymbolTable().getSymbols(function.getEntryPoint());
			var refSymbols = new HashSet<String>();
			for (var refSymbol : refSymbolsArr) {
				refSymbols.add(refSymbol.getName());
			}
			var found = false;
			for (var funcSymbol : funcSymbols) {
				if (refSymbols.contains(funcSymbol.getName())) {
					found = true;
					break;
				}
			}
			if (!found) {
				
				if (
						// ignore check for constructors
						function.getName().startsWith("InternalConstructor") || 
						// ignore check for destructors - we label them as ~ClassName instead of scalar/vector deleting destructor
						(refFunction.getName().equals("`scalar_deleting_destructor'") || refFunction.getName().equals("`vector_deleting_destructor'")) ||
						// ignore check for CppStructOps Construct
						(function.getName().startsWith("Construct") && function.getParentNamespace().getName().startsWith("TCppStructOps"))
					) {
					found = true;
				}
			}
			//if (!refFunction.getName().equals(function.getName())) {
			if (!found) {
				//println("=====");
				var decomp = GDecompInterface.decompileFunction(function, 10, monitor);
				// Ignore functions that are thunks to external functions
				// This will usually be a function from MSVC's C++ stdlib 
				var opCount = 0;
				var callIsExternal = false;
				for (Iterator<PcodeOpAST> ops = decomp.getHighFunction().getPcodeOps(); ops.hasNext();) {
					PcodeOpAST op = ops.next();
					if (op.getOpcode() == PcodeOp.CALL) {
						var callAddress = op.getInput(0);
						for (var refFrom : GReferences.getReferencesFrom(callAddress.getAddress())) {
							if (refFrom.getToAddress().isExternalAddress()) {
								callIsExternal = true;
							}
						}
					}
					//println(op.toString());
					opCount++;
				}
				var ignoreNonMatching = opCount == 2 && callIsExternal;
				if (!ignoreNonMatching) {					
					nonMatching.add(new NonMatchingFunction(function.getName(), refFunction.getName(), function.getEntryPoint()));
				}
			}
		}
		if (nonMatching.size() == 0) {
			println("All functions match!");
		} else {
			println("Non-matching functions");
			for (var nonMatch : nonMatching) {
				println(nonMatch.SourceName + "/" + nonMatch.TargetName + " @ " + nonMatch.EntryPoint.toString());
			}
			println(nonMatching.size() + "/" + namedFunctions + " functions do not match");
		}
		GDecompInterface.closeProgram();
		programManager.closeProgram(refProgram, true);
	}
}
