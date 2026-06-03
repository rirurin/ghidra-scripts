/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Writes "Hello World" to console.
//@category    Examples
//@menupath    Help.Examples.Hello World
//@keybinding  ctrl shift COMMA
//@toolbar    world.png

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class BitfieldTest extends GhidraScript {

	@Override
	public void run() throws Exception {
		CategoryPath new_path = new CategoryPath("/Hibiki");
		/*
		StructureDataType struct_a = new StructureDataType(new_path, "InnerType", 32);
		StructureDataType struct_b = new StructureDataType(new_path, "OuterType", 8);
		struct_b.replaceAtOffset(0, new Pointer64DataType(struct_a), 8, "ptr", null);
		currentProgram.getDataTypeManager().addDataType(struct_b, null);
		currentProgram.getDataTypeManager().addDataType(struct_b, null);
		currentProgram.getDataTypeManager().addDataType(struct_b, null);
		//currentProgram.getDataTypeManager().addDataType(struct_a, null);
		*/
		StructureDataType new_struct = new StructureDataType(new_path, "TestType", 16);
		DataType int_type = currentProgram.getDataTypeManager().getDataType(CategoryPath.ROOT, "int");
		new_struct.insertBitFieldAt(8, int_type.getLength(), 0, int_type, 1, "test_comp", null); // add 1 bit size at 0x8, offset 0
		// when added to DTM, StructureDataType is converted into Structure
		// and can be edited from there
		var dtm_struct = (Structure)currentProgram.getDataTypeManager().addDataType(new_struct, null);
		dtm_struct.insertBitFieldAt(8, int_type.getLength(), 1, int_type, 2, "test_comp_2", null);
		dtm_struct.insertBitFieldAt(8, int_type.getLength(), 3, int_type, 27, "test_comp_3", null);
	}
}
