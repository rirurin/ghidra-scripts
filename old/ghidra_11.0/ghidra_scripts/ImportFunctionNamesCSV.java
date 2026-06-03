//
//@author Rirurin
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ImportFunctionNamesCSV extends GhidraScript {

	@Override
	protected void run() throws Exception {
		File header = askFile("Select csv file", "Ok");
		try (BufferedReader file_read = new BufferedReader(new FileReader(header))) {
			String line = file_read.readLine();
			while (line != null) {
				String[] parts = line.split(",");
				Address target = toAddr(parts[1]);
				Function fn = currentProgram.getListing().getFunctionAt(target);
				if (fn == null) {
					createFunction(target, parts[0]);
				} else {
					fn.setName(parts[0], SourceType.ANALYSIS);
				}
				line = file_read.readLine();
			}
		}
	}
}
