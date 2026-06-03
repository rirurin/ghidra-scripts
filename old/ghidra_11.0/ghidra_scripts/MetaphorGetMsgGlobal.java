//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;

public class MetaphorGetMsgGlobal extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Data currAddr = currentProgram.getListing().getDataAt(currentAddress);
		for (int i = 0; i < currAddr.getNumComponents(); i++ ) {
			Data currComp = currAddr.getComponent(i);
			String Name = currComp.getComponent(0).getValue().toString();
			String Value = currComp.getComponent(1).getValue().toString();
			println(Name + " = " + Value);
		}
	}
}
