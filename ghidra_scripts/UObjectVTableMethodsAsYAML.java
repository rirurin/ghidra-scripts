//Convert methods in vtable with the same namespace as the vtable into offsets in a YAML format
//@author Rirurin
//@category Game Modding
//@keybinding
//@menupath
//@toolbar

import java.util.HashMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.NotFoundException;

public class UObjectVTableMethodsAsYAML extends GhidraScript {
	
	private static Listing GListing;
	private static SymbolTable GSymbol;
	
	public Function getOrCreateFunction(Address addr) {
		var func = GListing.getFunctionAt(addr);
		if (func == null) func = createFunction(addr, null);
		return func;
	}

	@Override
	protected void run() throws Exception {
		GListing = currentProgram.getListing();
		GSymbol = currentProgram.getSymbolTable();
		
		var symbolsAtStart = GSymbol.getSymbols(currentAddress);
		Namespace targetNamespace = null;
		for (var symbol : symbolsAtStart) {
			if (!symbol.getName().equals("vtable") && !symbol.getName().equals("`vftable'")) continue;
			targetNamespace = symbol.getParentNamespace();
		}
		if (targetNamespace == null) {
			throw new NotFoundException("Could not find a vtable symbol at this address");
		}
		println("UObject_VTable:");
		var addressCursor = currentAddress;
		Data currentPtr = null;
		var duplicates = new HashMap<String, Integer>();
		while (true) {
			currentPtr = GListing.getDataAt(addressCursor);
			addressCursor = addressCursor.add(8);
			if (!currentPtr.isPointer()) break;
			Function currentFunc = getOrCreateFunction(toAddr(currentPtr.getValue().toString()));
			if (!currentFunc.getParentNamespace().toString().startsWith("UObject")) continue;
			var duplicate = duplicates.get(currentFunc.getName());
			if (duplicate != null) {
				duplicates.put(currentFunc.getName(), duplicate + 1);
			} else {				
				duplicates.put(currentFunc.getName(), 2);
			}
			
			println("\t" + currentFunc.getName() + (duplicate != null ? "_" + duplicate : "") + ": 0x" + Long.toHexString(addressCursor.subtract(currentAddress) - 8));
		}
	}
}
