//
//@author Rirurin
//@category Rirurin/Labelling
//@keybinding
//@menupath
//@toolbar

import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.ConsoleTaskMonitor;

public class ExtractChildFunctionCalls extends GhidraScript {

	@Override
	protected void run() throws Exception {
		var listing = currentProgram.getListing();
		var targetFunction = listing.getFunctionAt(currentAddress);
		if (targetFunction == null) {
			throw new Exception("Cursor must be highlighted on a function in the listing!");
		}
		var taskMonitor = new ConsoleTaskMonitor();
		var decompilerOptions = new DecompileOptions();
		var decompInterface = new DecompInterface();
		decompInterface.setOptions(decompilerOptions);
		decompInterface.openProgram(currentProgram);
		var decompResults = decompInterface.decompileFunction(targetFunction, 10, taskMonitor);
		if (!decompResults.decompileCompleted()) {
			throw new Exception("Could not complete decompilation: " + decompResults.getErrorMessage());
		}
		for (Iterator<PcodeOpAST> ops = decompResults.getHighFunction().getPcodeOps(); ops.hasNext();) {
			PcodeOpAST op = ops.next();
			switch (op.getOpcode()) {
			case PcodeOp.CALL:
				println(op.toString());
				break;
			default:
				break;
			}
		}
		//println(decompResults.getDecompiledFunction().getSignature());
		
		//println("TODO: " + targetFunction.getName());
		decompInterface.closeProgram();
	}
}
