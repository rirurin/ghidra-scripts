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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;

import com.google.gson.Gson;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.listing.Data;

public class P3REFlowscript extends GhidraScript {
	
	public class FlowscriptParameter {
		public String Type;
		public String Name;
		public String Description;
		
		public FlowscriptParameter(String Type, String Name, String Description) {
			this.Type = Type;
			this.Name = Name;
			this.Description = Description;
		}
	}

	public class FlowscriptFunction {
		public String Index;
		public String ReturnType;
		public String Name;
		public String Description;
		public FlowscriptParameter[] Parameters;
		
		public FlowscriptFunction(String Index, String ReturnType, 
				String Name, String Description, FlowscriptParameter[] Parameters) {
			this.Index = Index;
			this.ReturnType = ReturnType;
			this.Name = Name;
			this.Description = Description;
			this.Parameters = Parameters;
		}
	}
	@Override
	public void run() throws Exception {
		// Place on start of a flowscript function array
		//var startValue = 0x5000;
		var startValue = 0x5000;
		File json_export = askFile("Save result to", "OK");
		var currData = getDataAt(currentAddress);
		var gson = new Gson();
		var functions = new FlowscriptFunction[0x74];
		for (int i = 0; i < currData.getNumComponents(); i++) {
			var currcomp = currData.getComponent(i);
			var funcPtr = currcomp.getComponent(0);
			var paramCount = currcomp.getComponent(1);
			var returnType = currcomp.getComponent(2);
			// get name
			var namePtr = currcomp.getComponent(3);
			var targetAddr = toAddr(namePtr.getValue().toString());
			//clearListing(targetAddr);
			//var name = createData(targetAddr, getDataTypes("string")[0]);
			var name = getDataAt(targetAddr);
			if (name == null) {
				clearListing(targetAddr);
				name = createData(targetAddr, getDataTypes("string")[0]);
			}
			var params = currcomp.getComponent(4);
			//println(name.toString() + ", " + ValueToType(ToInt(returnType)) + ", " + ToInt(paramCount) + " params");
			var params_FLOW = new FlowscriptParameter[ToInt(paramCount)];
			for (int j = 0; j < ToInt(paramCount); j++) {
				var paramType = ValueToType(ToInt(params.getComponent(j)));
				params_FLOW[j] = new FlowscriptParameter(
						paramType,
						("param" + j),
						""
				);
			}
			functions[i] = new FlowscriptFunction(
				String.format("0x%04x", i + startValue),
				ValueToType(ToInt(returnType)),
				name.getValue().toString(),
				"",
				params_FLOW
			);
		}
		FileOutputStream writer = new FileOutputStream(json_export);
		byte[] bytes = gson.toJson(functions).getBytes();
		writer.write(bytes);
		writer.close();
	}
	
	public int ToInt(Data Value) {
		return Integer.parseInt(Value.getValue().toString().substring(2), 16);
	}
	
	public String ValueToType(int Index) {
		switch (Index) {
			case 0:
				return "void";
			case 1:
				return "int";
			case 2:
				return "float";
			case 3:
				return "string";
			default:
				throw new IllegalArgumentException("Unhandled param type " + Index);
		}
	}
}
