import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;

public class P5DebugSymbolsExport extends GhidraScript {

	@Override
	public void run() throws Exception {
		// compile base type for
		Pattern p = Pattern.compile("\\[\\d+\\]|\\*");
		var p5_files = currentProgram.getDataTypeManager().getCategory(new CategoryPath("/DWARF"));
		var cat_count = p5_files.getCategories().length;
		println("Structs/methods defined for " + cat_count + " files");
		for (var p5_file : p5_files.getCategories()) {
			var p5_file_types = p5_file.getDataTypes();
			for (int i = 0; i < p5_file_types.length; i++) {
				var curr_file_type = p5_file_types[i];
				println(curr_file_type.getClass().getName());
			}
		}
	}
}
