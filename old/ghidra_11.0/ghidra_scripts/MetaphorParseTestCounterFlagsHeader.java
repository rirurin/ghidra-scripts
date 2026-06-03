//
//@author Rirurin
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;

public class MetaphorParseTestCounterFlagsHeader extends GhidraScript {

	@Override
	protected void run() throws Exception {
		File header = askFile("Select header file", "Ok");
		BufferedReader file_read = new BufferedReader(new FileReader(header));
		String structName = header.getName().substring(0, header.getName().lastIndexOf("."));
		EnumDataType new_enum = new EnumDataType(new CategoryPath("/xrd759/flag"), structName, 4);
		String current_line = file_read.readLine();
		while (current_line != null) {
			String[] header_parts = current_line.split("(\\s+= +)|, ");
			if (header_parts.length == 3) {				
				String name = header_parts[0];
				long value = Long.parseLong(header_parts[1]);
				String comment = header_parts[2];
				println(name + ": " + value);
				new_enum.add(name, value, comment);
			}
			current_line = file_read.readLine();
		}
		currentProgram.getDataTypeManager().addDataType(new_enum, null);
		file_read.close();
	}
}
 