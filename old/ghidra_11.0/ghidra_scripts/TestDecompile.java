//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import docking.options.OptionsService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Function;

public class TestDecompile extends GhidraScript {
	
	private DecompInterface Decompiler;
	
	private DecompInterface setUpDecompiler() {
		DecompInterface decomplib = new DecompInterface();

		DecompileOptions options = new DecompileOptions();
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, currentProgram);
		}
		decomplib.setOptions(options);

		decomplib.toggleCCode(true);
		decomplib.toggleSyntaxTree(true);
		decomplib.setSimplificationStyle("decompile");

		return decomplib;
	}

	@Override
	protected void run() throws Exception {
		Decompiler = setUpDecompiler();
		if (!Decompiler.openProgram(currentProgram)) {
			println("Decompile Error: " + Decompiler.getLastMessage());
			return;
		}
		disassemble(currentAddress);
		Function func = createFunction(currentAddress, "test");
		DecompileResults res = Decompiler.decompileFunction(func, 60, monitor);
		var pcodeOps = res.getHighFunction().getPcodeOps();
		while (pcodeOps.hasNext()) {
			var currPcode = pcodeOps.next();
			println(currPcode.getMnemonic());
		}
		println(res.getErrorMessage());
	}
}
