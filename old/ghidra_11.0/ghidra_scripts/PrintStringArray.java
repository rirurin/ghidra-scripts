//
//@author Rirurin
//@category 
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;

public class PrintStringArray extends GhidraScript {

	@Override
	protected void run() throws Exception {
		var data = currentProgram.getListing().getDataAt(currentAddress);
		for (int i = 0; i < data.getNumComponents(); i++) {
			var comp = data.getComponent(i);
			var addr = toAddr(comp.getValue().toString());
			var str_data = currentProgram.getListing().getDataAt(addr);
			println(str_data.getValue().toString());
		}
	}
}
