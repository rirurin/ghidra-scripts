//
//@author Rirurin
//@category Rirurin/Test
//@keybinding
//@menupath
//@toolbar

import java.util.LinkedList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

public class TestChangeFunctionSignature extends GhidraScript {
	
	// Replace the parameter list for the target function with a single void*
	@Override
	protected void run() throws Exception {
		var listing = currentProgram.getListing();
		var targetFunction = listing.getFunctionAt(currentAddress);
		if (targetFunction == null) {
			throw new Exception("Cursor must be highlighted on a function in the listing!");
		}
		var Params = new LinkedList<Variable>();
		var VoidPtr = new PointerDataType(new VoidDataType());
		Params.add(new ParameterImpl("param_1", VoidPtr, currentProgram));
		targetFunction.replaceParameters(
				Params, 
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, 
				true, 
				SourceType.USER_DEFINED
		);
	}
}
