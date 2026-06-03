import java.util.LinkedList;
import java.util.List;
import java.util.Stack;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
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
import ghidra.program.model.data.CategoryPath;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class Persona5LabelWidgetFunctions extends GhidraScript {

    static String[] WIDGET_NAMES = {
        "NULL",
        "Panel",
        "Button",
        "Label",
        "Image",
        "PopupMenu",
        "ListBox",
        "CheckBox",
        "ScrollBar",
        "Slider",
        "ColorPicker",
        "Spin",
        "GroupBox",
        "Tab",
        "TreeView",
        "ColumnBar",
        "Rollout",
        "Edit",
        "TimeLine",
        "RadioButton",
        "Range",
        "Curve",
        "Curve4",
        "ComboBox",
        "Fade",
        "ProgressBar",
        "Splitter",
        "Brush",
    };

    static String[] FUNCTION_NAMES = {
        "Create",
        "Release",
        "Update",
        "Render",
        "SetID",
        "GetID",
        "Selected",
        "Resize",
        "Func8"
    };

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

	public boolean IsPointerInRange(Address Address) {
		MemoryBlock[] Blocks = GMemory.getBlocks();
		for (var Block : Blocks) {
			if (Block.contains(Address)) return true;
		}
		return false;
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
	public void run() throws Exception {
        GMemory = currentProgram.getMemory();
        var currData = getDataAt(currentAddress);
        for (int i = 0; i < currData.getNumComponents(); i++) {
            var currComp = currData.getComponent(i);
            for (int j = 0; j < currComp.getNumComponents(); j++) {
                var address = toAddr(currComp.getComponent(j).getValue().toString());
                var functionName = "gfdWidget" + WIDGET_NAMES[i] + FUNCTION_NAMES[j];
                GetOrMakeFunction(address, functionName, null);
            }
        }
    }
}
