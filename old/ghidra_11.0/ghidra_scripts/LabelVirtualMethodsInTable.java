//
//@author Rirurin
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.LinkedList;
import java.util.List;
import java.util.Stack;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class LabelVirtualMethodsInTable extends GhidraScript {
	
private Memory GMemory;
	
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
	
	private boolean IsMemoryLocationValid(Address address) {
		MemoryBlock[] Blocks = currentProgram.getMemory().getBlocks();
		for (var Block : Blocks) {
			if (Block.contains(address)) return true;
		}
		return false;
	}
	
	private Function GetOrMakeFunction(Address addr, String name, Namespace ns) {
		if (!IsMemoryLocationValid(addr)) {
			return null;
		}
		Instruction instr = currentProgram.getListing().getInstructionAt(addr);
		// instructino is null, diassemble it first
		if (instr == null) {
			disassemble(addr);
			instr = currentProgram.getListing().getInstructionAt(addr);
		}
		Function func = currentProgram.getListing().getFunctionAt(addr);
		if (func == null) {
			func = createFunction(addr, name);
		} else if (!func.getName().equals(name)) {
			try {
				func.setName(name, SourceType.ANALYSIS);				
			} catch (InvalidInputException | DuplicateNameException e) {
				println("ERROR: Can't rename the function at " + addr + " to " + name);
			}
		}
		// Add to namespace if provided
		if (ns != null) {
			try {
				func.setParentNamespace(ns);	
			} catch (InvalidInputException | DuplicateNameException | CircularDependencyException e) {
				println("ERROR: Can't set the namespace of " + name + " to " + ns.getName());
			}
		}
		// check if it's a thunk function, in which case we'll have to rename the inner function too
		if (instr.getMnemonicString().equals("JMP")) {
			var instrLength = 0;
			try {
				instrLength = instr.getBytes().length;
			} catch (MemoryAccessException e) {
				throw new NullPointerException("Tried to read bytes at unknown location " + addr);
			}
			Cursor c = new Cursor(addr);
			var jmpFirstByte = c.DerefByte();
			if (jmpFirstByte == -23) { // near jump, 32 bit branch pointer
				var jmpRel = c.DerefInt();
				Address thunkAddr = addr.add(jmpRel + instrLength);
				println(thunkAddr.toString());
				GetOrMakeFunction(thunkAddr, name, ns);
			} else {
				println("Unknown first byte " + jmpFirstByte + " at " + addr);
			}
		}
		return func;
	}
	
	public class Ref<T> {
		T val;
		public Ref(T _val) {
			val = _val;
		}
		public Ref() {
			val = null;
		}
		public T get() { return val; }
		public void set(T _val) { val = _val; }
		public String ToString() {
			return val.toString();
		}
	}
	
	public class Cursor {
		private Address CurrentPoint;
		private Stack<Address> PositionStack;
		public Cursor(Address _CurrentPoint) {
			CurrentPoint = _CurrentPoint;
			PositionStack = new Stack<>();
		}
		
		// Wrapper to read any arbitrary part of the program's memory without
		// setting the data type at that location in the listing
		public byte DerefByte() {
			try {
				byte Result = GMemory.getByte(CurrentPoint);
				CurrentPoint = CurrentPoint.add(1);
				return Result;
			} catch (MemoryAccessException e) {
				throw new NullPointerException("Tried to access memory at an unknown location: " + CurrentPoint.getOffset());
			}
		}
		public short DerefShort() {
			try {
				short Result = GMemory.getShort(CurrentPoint);
				CurrentPoint = CurrentPoint.add(2);
				return Result;
			} catch (MemoryAccessException e) {
				throw new NullPointerException("Tried to access memory at an unknown location: " + CurrentPoint.getOffset());
			}
		}
		public int DerefInt() {
			try { 
				int Result = GMemory.getInt(CurrentPoint);
				CurrentPoint = CurrentPoint.add(4);
				return Result;
			} catch (MemoryAccessException e) {
				throw new NullPointerException("Tried to access memory at an unknown location: " + CurrentPoint.getOffset());
			}
		}
		public long DerefLong() {
			try {
				long Result = GMemory.getLong(CurrentPoint);
				CurrentPoint = CurrentPoint.add(8);
				return Result;
			} catch (MemoryAccessException e) {
				throw new NullPointerException("Tried to access memory at an unknown location: " + CurrentPoint.getOffset());
			}
		}
		public float DerefFloat() {
			try {
				float Result = Float.intBitsToFloat(GMemory.getInt(CurrentPoint));
				CurrentPoint = CurrentPoint.add(4);
				return Result;
			} catch (MemoryAccessException e) {
				throw new NullPointerException("Tried to access memory at an unknown location: " + CurrentPoint.getOffset());
			}
		}
		public double DerefDouble() {
			try {
				double Result = Double.longBitsToDouble(GMemory.getLong(CurrentPoint));
				CurrentPoint = CurrentPoint.add(8);
				return Result;
			} catch (MemoryAccessException e) {
				throw new NullPointerException("Tried to access memory at an unknown location: " + CurrentPoint.getOffset());
			}
		}
		public boolean Seek(int amount) {
			CurrentPoint = CurrentPoint.add(amount);
			return true;
		}
		public Address Tell() {
			return CurrentPoint;
		}
		public boolean IsPointerInRange(Address Address) {
			MemoryBlock[] Blocks = GMemory.getBlocks();
			for (var Block : Blocks) {
				if (Block.contains(Address)) return true;
			}
			return false;
		}
		public boolean DerefPointer(Ref<Address> OutAddress) {
			try {			
				if (currentProgram.getDefaultPointerSize() == 8) {
					Address Result = toAddr(Long.toHexString(GMemory.getLong(CurrentPoint)));
					CurrentPoint = CurrentPoint.add(8);
					OutAddress.set(Result);
					return IsPointerInRange(Result);
				} else if (currentProgram.getDefaultPointerSize() == 4) {
					Address Result = toAddr(Integer.toHexString(GMemory.getInt(CurrentPoint)));
					CurrentPoint = CurrentPoint.add(4);
					OutAddress.set(Result);
					return IsPointerInRange(Result);
				} else {
					OutAddress.set(null);
					return false;
				}
			} catch (MemoryAccessException e) {
				OutAddress.set(null);
				return false;
			}
		}
		// Push and pop methods
		public void Push() {
			PositionStack.add(CurrentPoint);
		}
		public void Pop() {
			if (!PositionStack.isEmpty()) {
				CurrentPoint = PositionStack.pop();	
			}
		}
		public Address Peek() {
			if (!PositionStack.isEmpty()) {				
				return PositionStack.peek();
			}
			return null;
		}
	}

	@Override
	protected void run() throws Exception {
		GMemory = currentProgram.getMemory();
		var vtableSymbols = currentProgram.getSymbolTable().getSymbols("vtable");
		while (vtableSymbols.hasNext()) {
			Symbol currSymbol = vtableSymbols.next();
			int vtableMethods = 0;
			Cursor c = new Cursor(currSymbol.getAddress());
			while (true) {
				Ref<Address> Addr = new Ref<>(null);
				c.DerefPointer(Addr);
				Instruction instr = currentProgram.getListing().getInstructionAt(Addr.val);
				if (!IsMemoryLocationValid(Addr.val) || instr == null || vtableMethods > 1000) {
					break;
				}
				vtableMethods++;
			}
			Data existingData = currentProgram.getListing().getDataAt(currSymbol.getAddress());
			if (existingData != null && existingData.getDataType() instanceof Array) {
				//println("Already declared for " + currSymbol.getAddress().toString());	
			} else {
				if (vtableMethods == 0) vtableMethods = 1; // has to be at least one virtual func
				currentProgram.getListing().clearCodeUnits(currSymbol.getAddress(), currSymbol.getAddress().add(8 * vtableMethods - 1), false);
				Data vtable = currentProgram.getListing().createData(currSymbol.getAddress(), new ArrayDataType(new PointerDataType(), vtableMethods, 0));
				println("Created data for " + currSymbol.getName() + " at " + currSymbol.getAddress().toString());
				
				Namespace targetSpace = currSymbol.getParentNamespace();
				for (int i = 0; i < vtable.getNumComponents(); i++) {
					String fnName = targetSpace.getName(true).replace("::", "_") + "_" + i;
					Address tgtFn = toAddr(vtable.getComponent(i).getValue().toString());
					println("Function " + fnName + " at " + tgtFn.toString());
					Function existingFn = currentProgram.getListing().getFunctionAt(tgtFn);
					if (existingFn != null && !existingFn.getName().startsWith("FUN_"))
						continue;
					GetOrMakeFunction(tgtFn, fnName, targetSpace);
				}
			}
			//if (existingData != null && existingData.getBaseDataType().toString().equals("pointer")) {
			//}
			//if (vtableMethods > 1000)
				//println("ERROR");
			// println(currSymbol.getName(true) + ", " + vtableMethods + " methods");
		}
		/*
		GMemory = currentProgram.getMemory();
		Data vtable = currentProgram.getListing().getDataAt(currentAddress);
		Symbol vtableSym = currentProgram.getSymbolTable().getPrimarySymbol(currentAddress);
		Namespace targetSpace = vtableSym.getParentNamespace();
		for (int i = 0; i < vtable.getNumComponents(); i++) {
			String fnName = targetSpace.getName(true).replace("::", "_") + "_" + i;
			Address tgtFn = toAddr(vtable.getComponent(i).getValue().toString());
			println("Function " + fnName + " at " + tgtFn.toString());
			Function existingFn = currentProgram.getListing().getFunctionAt(tgtFn);
			if (existingFn != null && !existingFn.getName().startsWith("FUN_"))
				continue;
			GetOrMakeFunction(tgtFn, fnName, targetSpace);
		}
		*/
	}
}
