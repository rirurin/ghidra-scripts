//
//@author Rirurin
//@category Rirurin/Labelling
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.ConsoleTaskMonitor;

public class ExtractChildFunctionCalls extends GhidraScript {
	
	private Gson gson;
	
	public static Listing GListing;
	
	public class FunctionCall {
		public String Name;
		public LinkedList<FunctionParameter> Parameters;
		
		public FunctionCall(String Name, LinkedList<FunctionParameter> Parameters) {
			this.Name = Name;
			this.Parameters = Parameters;
		}
		
		@Override
		public String toString() {
			var Fmt = Name + "(";
			for (var Parameter : Parameters) {
				Fmt += Parameter.toString() + ", ";
			}
			Fmt += ");";
			return Fmt;
		}
	}
	
	public class FunctionParameter {
		public String TypeName;
		public String Space;
		public long Offset;
		public int Size;
		
		public FunctionParameter(String TypeName, String Space, long Offset, int Size) {
			this.TypeName = TypeName;
			this.Space = Space;
			this.Offset = Offset;
			this.Size = Size;
		}
		
		@Override
		public String toString() {
			return TypeName + " [ " + Space + Offset + ", " + Size + "]";
		}
	}

	@Override
	protected void run() throws Exception {
		GListing = currentProgram.getListing();
		gson = new GsonBuilder()
				.create();
		var targetFunction = GListing.getFunctionAt(currentAddress);
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
		
		var FunctionCalls = new ArrayList<FunctionCall>();
		
		for (Iterator<PcodeOpAST> ops = decompResults.getHighFunction().getPcodeOps(); ops.hasNext();) {
			PcodeOpAST op = ops.next();
			switch (op.getOpcode()) {
			case PcodeOp.CALL:
				var callerLocation = op.getInput(0);
				var callerFunction = GListing.getFunctionAt(callerLocation.getAddress());
				var ParamsOut = new LinkedList<FunctionParameter>();
				var callerParams = callerFunction.getParameters();
				for (int i = 1; i < op.getNumInputs(); i++) {
					var Input = op.getInput(i);
					ParamsOut.add(new FunctionParameter(
							callerParams[i - 1].getDataType().getName(), 
							Input.getAddress().getAddressSpace().toString(), 
							Input.getOffset(),
							Input.getSize()));
				}
				var NewCall = new FunctionCall(callerFunction.getName(true), ParamsOut);
				println(NewCall.toString());
				FunctionCalls.add(NewCall);
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
