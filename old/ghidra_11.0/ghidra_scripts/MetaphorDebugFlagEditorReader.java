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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;

public class MetaphorDebugFlagEditorReader extends GhidraScript {

	@Override
	protected void run() throws Exception {
		File dir = askDirectory("Select test flag folder", "Ok");
		EnumDataType new_enum = new EnumDataType(new CategoryPath("/xrd759/flag"), "datFlagID", 4);
		for (var flag_file : dir.listFiles()) {
			println(flag_file.getName());
			try (var reader = new BufferedReader(new FileReader(flag_file))) {
				String current_line = reader.readLine();
				while (current_line != null) {
					String[] header_parts = current_line.split("(\\s+= +)|(, +//)");
					if (header_parts.length == 3) {			
						String name = header_parts[0];
						long value = Long.parseLong(header_parts[1]);
						String comment = header_parts[2];
						println(name + ": " + value);
						new_enum.add(name, value, comment);
					}
					current_line = reader.readLine();
				}
			}
		}
		currentProgram.getDataTypeManager().addDataType(new_enum, null);
	}
}
