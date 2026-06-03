import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;

public class NameMessageScriptFunctions extends GhidraScript {

	@Override
	public void run() throws Exception {
		var msgScriptFuncDef = getDataAt(currentAddress);
		String typePath = askString("Set file path for message script struct", "OK");
		//var msgStruct = new StructureDataType();
		/*
		for (int i = 0; i < msgScriptFuncDef.getNumComponents(); i++) {
			
		}
		*/
	}
}
