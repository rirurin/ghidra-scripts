import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;

public class CreateSkillIdEnum extends GhidraScript {

	@Override
	public void run() throws Exception {
		File skillsTxt = askFile("Get skills.txt file", "OK");
		String typePath = askString("Set file path for new enum", "OK");
		var new_enum = new EnumDataType(new CategoryPath(typePath), "Skills", 4); // sizeof(uint)
		BufferedReader fileReader = new BufferedReader(new FileReader(skillsTxt));
		int skill_id = 0;
		String curr_skill;
		while ((curr_skill = fileReader.readLine()) != null) {
			new_enum.add(curr_skill, skill_id);
			skill_id++;
		}
		currentProgram.getDataTypeManager().addDataType(new_enum, null);
	}
}
