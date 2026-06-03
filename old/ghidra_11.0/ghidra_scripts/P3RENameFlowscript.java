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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.lang.Register;

public class P3RENameFlowscript extends GhidraScript {
	
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
		var currData = getDataAt(currentAddress);
		for (int i = 0; i < currData.getNumComponents(); i++) {
			var funcMeta = currData.getComponent(i);
			var funcPtr = funcMeta.getComponent(0);
			var namePtr = funcMeta.getComponent(3);
			var name = getDataAt(toAddr(namePtr.getValue().toString()));
			var funcMaybe = getFunctionAt(toAddr(funcPtr.getValue().toString()));
			Function func;
			if (funcMaybe != null) {
				func = funcMaybe;
				func.setName(name.getValue().toString(), SourceType.ANALYSIS);
			} else {
				func = createFunction(toAddr(funcPtr.getValue().toString()), name.getValue().toString());
			}
			var scriptIntepreterType = getDataTypes("ScriptInterpreter")[0];
			if (func.getParameterCount() > 0) {
				//func.updateFunc
				//new ParameterImpl("this", new Pointer64DataType(scriptIntepreterType), Register.);
				func.getParameters()[0].setDataType(new Pointer64DataType(scriptIntepreterType), SourceType.ANALYSIS);
			} else {
				println("TODO: param count for " + name);
			}
		}
	}
	
	public int ToInt(Data Value) {
		return Integer.parseInt(Value.getValue().toString().substring(2), 16);
	}
}
