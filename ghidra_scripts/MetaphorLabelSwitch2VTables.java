//Labels VTables in Switch 2 exefs (designed for Metaphor Refantazio, probably works for other Switch 2 games)
//@author Rirurin
//@category Game Modding
//@keybinding
//@menupath
//@toolbar
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.gnu.GnuDemangler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class MetaphorLabelSwitch2VTables extends GhidraScript {
	
	private static Listing GListing;
	private static Memory GMemory;
	private static SymbolTable GSymbols;
	private static HashMap<String, MemoryRange> MemoryBlocks;
	private static Address TypeInfoStart;
	private static Address TypeInfoEnd;
	
	public class MemoryRange {
		public Address Start;
		public Address End;
		
		public MemoryRange(Address Start, Address End) {
			this.Start = Start;
			this.End = End;
		}
		
		public long GetSize() {
			return this.End.subtract(this.Start);
		}
	}
	
	private List<String> GetNamespaceParts(String fullName) {
		List<String> parts = new LinkedList<String>();
		int GenericStack = 0;
		int SearchIndex = 0;
		int NameIndex = 0;
		while (true) {
			var CurrNamespaceIndex = fullName.indexOf("::", SearchIndex);
			if (CurrNamespaceIndex == -1) {
				parts.add(fullName.substring(NameIndex, fullName.length()).replace(" ", "_"));
				break;
			} 
			var CurrentNamePart = fullName.substring(SearchIndex, CurrNamespaceIndex);
			GenericStack += (CurrentNamePart.length() - CurrentNamePart.replace("<", "").length());
			GenericStack -= (CurrentNamePart.length() - CurrentNamePart.replace(">", "").length());
			if (GenericStack == 0) {
				parts.add(fullName.substring(NameIndex, CurrNamespaceIndex).replace(" ", "_"));
				NameIndex = CurrNamespaceIndex + 2;
			}
			SearchIndex = CurrNamespaceIndex + 2;
		}
		return parts;
	}
	
	private Namespace GetOrMakeNamespace(String fullName) throws InvalidInputException, DuplicateNameException {
		Namespace ParentNamespace = currentProgram.getGlobalNamespace();
		for (var part : GetNamespaceParts(fullName)) {
			Namespace CurrNamespace = currentProgram.getSymbolTable().getOrCreateNameSpace(ParentNamespace, part, SourceType.ANALYSIS);
			ParentNamespace = CurrNamespace;
		}
		if (!(ParentNamespace instanceof GhidraClass)) {
			ParentNamespace = currentProgram.getSymbolTable().convertNamespaceToClass(ParentNamespace);
		}
		return ParentNamespace;
	}
	
	// check that it's a valid ASCII string
	private int checkStringValid(Address startAddr) throws MemoryAccessException {
		var charLen = 0;
		byte currChar = getByte(startAddr);
		while (currChar != 0) {
			charLen++;
			if (currChar < 0 || charLen > 255) return -1;
			currChar = getByte(startAddr.add(charLen));
		}
		return charLen;
	}
	
	private void labelVtable(Address currAddr, String namespaceStr) throws CodeUnitInsertionException, DuplicateNameException, InvalidInputException {
		var namespace = GetOrMakeNamespace(namespaceStr);
		var typeInfoExist = GSymbols.getSymbols("typeinfo", namespace);
		Address foundTypeInfo;
		if (typeInfoExist.size() > 0) {
			foundTypeInfo = typeInfoExist.get(0).getAddress();
		} else {
			var foundRef = GMemory.findBytes(
					currAddr, TypeInfoEnd, 
					ByteBuffer.allocate(8).putLong(Long.reverseBytes(currAddr.getOffset())).array(), 
					null, true, monitor);
			
			if (foundRef == null || foundRef.getOffset() % 8 != 0 || GListing.getInstructionContaining(foundRef) != null) return;
			foundTypeInfo = foundRef.subtract(8);
			GSymbols.createLabel(foundTypeInfo, "typeinfo", namespace, SourceType.ANALYSIS);				
		}
		println("\tfound typeinfo at " + foundTypeInfo.toString());
		
		var vtableExist = GSymbols.getSymbols("vtable", namespace);
		Address foundVtable;
		if (vtableExist.size() > 0) {
			foundVtable = typeInfoExist.get(0).getAddress();
		} else {
			var foundVt = GMemory.findBytes(
					foundTypeInfo, TypeInfoStart, 
					ByteBuffer.allocate(8).putLong(Long.reverseBytes(foundTypeInfo.getOffset())).array(), 
					null, false, monitor);
			if (foundVt == null || foundVt.getOffset() % 8 != 0 || GListing.getInstructionContaining(foundVt) != null) return;
			var existTypeInfoRef = GListing.getDataAt(foundVt);
			if (existTypeInfoRef == null || !(existTypeInfoRef.getDataType() instanceof Pointer)) {				
				GListing.createData(foundVt, new PointerDataType()); // create ref for typeinfo
			}
			foundVtable = foundVt.add(8);
			GSymbols.createLabel(foundVtable, "vtable", namespace, SourceType.ANALYSIS);				
		}
		println("\tfound vtable at " + foundVtable.toString());
	}
	
	private void demangleSymbols(GnuDemangler demangler, byte[] bytes, boolean isClass) 
			throws CancelledException, CodeUnitInsertionException, DuplicateNameException, InvalidInputException, MemoryAccessException {
		var addressCursor = currentProgram.getMinAddress();
		//var limit = 5000;
		while (addressCursor.compareTo(currentProgram.getMaxAddress()) == -1 /*&& limit > 0*/) {
			var currAddr = GMemory.findBytes(addressCursor, bytes, null, true, monitor);
			if (currAddr == null) break;
			addressCursor = currAddr.add(1);
			var strLen = checkStringValid(currAddr);
			// must be data, not an instruction
			// also stop candidates in the middle of an existing string
			if (GListing.getInstructionContaining(currAddr) != null || strLen == -1 || GListing.getDataAt(currAddr) == null) continue;
			//limit--;
			if (!(GListing.getDataAt(currAddr).getDataType() instanceof StringDataType)) {
				clearListing(currAddr, currAddr.add(strLen - 1));
				GListing.createData(currAddr, new StringDataType());
			}
			var name = GListing.getDataAt(currAddr).getValue().toString();
			try {
				var demangled = demangler.demangle("_Z" + name);
				println(currAddr.toString() + " - " + demangled.getSignature());
				if (isClass) {				
					labelVtable(currAddr, demangled.getSignature());
				}
			} catch (DemangledException | ClassCastException e) {
				//println(currAddr.toString() + " - Could not demangle the string \"" + name + "\": " + e.getMessage());
			}
		}
	}

	@Override
	protected void run() throws Exception {
		GListing = currentProgram.getListing();
		GMemory = currentProgram.getMemory();
		GSymbols = currentProgram.getSymbolTable();
		//GReferences = currentProgram.getReferenceManager();
		MemoryBlocks = new HashMap<>();
		for (var block : GMemory.getBlocks()) {
			MemoryBlocks.put(block.getName(), new MemoryRange(block.getStart(), block.getEnd()));
		}
		TypeInfoEnd = MemoryBlocks.get(".data").End;
		TypeInfoStart = MemoryBlocks.get(".data").Start;
		var demangler = new GnuDemangler();
		demangleSymbols(demangler, new byte[] { 0x4E, 0x53, 0x74, 0x33, 0x5F, 0x5F }, true); // NSt3__ (std::function)
		//demangleSymbols(demangler, new byte[] { 0x5a, 0x4e, 0x33 }, false); // ZN3 (function)
		demangleSymbols(demangler, new byte[] { 0x4e, 0x33 }, true); // N3 (class declaration)
		demangleSymbols(demangler, new byte[] { 0x4e, 0x32 }, true); // N2 (struct declaration)
	}
}
