//
//@author Rirurin
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.HashSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class MetaphorReadMsgText extends GhidraScript {
	
	public HashSet<String> ExistingNames;
	
	private String RemoveTags(String line) {
		String current = line;
		while (current.indexOf("<") != -1) {
			int tagStart = current.indexOf("<");
			int endTagIndex = current.indexOf(">", tagStart);
			endTagIndex = endTagIndex == current.length() - 1 ? endTagIndex : endTagIndex + 1;
			current = current.substring(0, tagStart) + current.substring(endTagIndex, current.length() - 1);
		}
		return current;
	}
	
	private String RemoveSpecialCharacters(String line) {
		String underscores = line.replaceAll("_|\\[| |\\]", "_");
		return underscores.replaceAll("'|@", "");
	}

	@Override
	protected void run() throws Exception {
		File header = askFile("Select csv file", "Ok");
		ExistingNames = new HashSet<>();
		String MessageEntryName = null;
		boolean InBlock = false;
		int lineCount = 0;
		EnumDataType new_enum = new EnumDataType(new CategoryPath("/xrd759/btl/skill"), "datSkillName", 4);
		try (BufferedReader file_read = new BufferedReader(new FileReader(header))) {
			String line = file_read.readLine();
			while (line != null) {
				if (line.startsWith("//")) { // comment, skip
					line = file_read.readLine();
					continue;
				}
				if (line.startsWith("@")) {
					MessageEntryName = line.substring(1);
				} else if (line.startsWith("{")) {
					if (MessageEntryName != null) { 
						InBlock = true;
						// and go to the next one
						line = file_read.readLine();
						continue;
					}
					throw new Exception("Invalid msg: Got beginning of block before name");
				}
				if (line.startsWith("}")) {
					InBlock = false;
					MessageEntryName = null;
				}
				if (InBlock) {
					String line_no_tags = RemoveTags(line);
					line_no_tags = RemoveSpecialCharacters(line_no_tags);
					if (line_no_tags.length() > 0) {
						if (MessageEntryName.equals("SkillName_Auto_01")) {
							lineCount = 1000;
						}
						boolean added = ExistingNames.add(line_no_tags);
						if (!added) line_no_tags += "_" + lineCount;
						new_enum.add(line_no_tags, lineCount, MessageEntryName);
						lineCount++;
						//println(line_no_tags);
					}
				}
				line = file_read.readLine();
			}
		}
		println(lineCount + " lines");
		currentProgram.getDataTypeManager().addDataType(new_enum, null);
	}
}
