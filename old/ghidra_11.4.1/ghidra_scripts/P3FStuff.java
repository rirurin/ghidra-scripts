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
//An example of asking for user input.
//Note the ability to pre-populate values for some of these variables when AskScript.properties file exists.
//Also notice how the previous input is saved.
//@category Examples

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class P3FStuff extends GhidraScript {

	@Override
	public void run() throws Exception {
		/*
		Data CodeFunc = currentProgram.getListing().getDataAt(currentAddress);
		for (int i = 0; i < CodeFunc.getNumComponents(); i++) {
			Data FuncEntry = CodeFunc.getComponent(i);
			Data Pointer = currentProgram.getListing().getDataAt(toAddr(FuncEntry.getValue().toString()));
			println(Pointer.getLabel());
		}
		*/
		/*
		File file = askFile("CodeFunc.txt", "ok");
		Data CodeFunc = currentProgram.getListing().getDataAt(currentAddress);
		int Line = 0;
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			String CurrentLine = br.readLine();
			while (CurrentLine != null) {
				Data FuncEntry = CodeFunc.getComponent(Line);
				Address FuncAddr = toAddr(FuncEntry.getValue().toString());
				Function Func = currentProgram.getListing().getFunctionAt(FuncAddr);
				// for (Symbol sym : currentProgram.getSymbolTable().getSymbols(FuncAddr)) {
				// 	currentProgram.getSymbolTable().removeSymbolSpecial(sym);
				// }
				Func.setName(CurrentLine, SourceType.ANALYSIS);
				Line++;
				CurrentLine = br.readLine();
			}
		}
		*/
		/*
		Data CodeFunc = currentProgram.getListing().getDataAt(currentAddress);
		for (int i = 0; i < CodeFunc.getNumComponents(); i++) {
			Data FuncEntry = CodeFunc.getComponent(i);
			Data FuncPtr = FuncEntry.getComponent(0);
			Address PointerAddress = toAddr(FuncPtr.getValue().toString());
			Function Function = currentProgram.getListing().getFunctionAt(PointerAddress);
			String Name = "scrFunction" + i;
			if (Function == null && PointerAddress.getOffset() != 0) {
				createFunction(PointerAddress, Name);
			}
			else if (Function != null) {
				Function.setName(Name, SourceType.ANALYSIS);
			}
		}
		*/
		/*
		File file = askFile("tasklist.csv", "ok");
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			String CurrentLine = br.readLine();
			while (CurrentLine != null) {
				String[] Task = CurrentLine.split(",");
				Address UpdateAddress = toAddr(Task[1]);
				String TaskName = (Task[0].substring(1, Task[0].length() - 1)).replace(" ", "_") + "_update";
				Function func = currentProgram.getListing().getFunctionAt(UpdateAddress);
				if (func == null) {
					createFunction(UpdateAddress, TaskName);
				} else {
					func.setName(TaskName, SourceType.ANALYSIS);
				}
				CurrentLine = br.readLine();
			}
		}
		*/
		// currentProgram.setExecutablePath("P3R.exe");
		Options pl = currentProgram.getOptions(Program.PROGRAM_INFO);
		pl.setString("FSRL", "...");
	}
}
