import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Stack;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.CategoryPath;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class PrintFunctionsInVtable extends GhidraScript {
    private Memory GMemory;

	private List<String> GetNamespaceParts(String fullName) {
		List<String> parts = new LinkedList<String>();
		int GenericStack = 0;
		int SearchIndex = 0;
		int NameIndex = 0;
		while (true) {
			int CurrNamespaceIndex = fullName.indexOf("::", SearchIndex);
			if (CurrNamespaceIndex == -1) {
				parts.add(fullName.substring(NameIndex, fullName.length()).replace(" ", "_"));
				break;
			} 
			String CurrentNamePart = fullName.substring(SearchIndex, CurrNamespaceIndex);
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
		for (String part : GetNamespaceParts(fullName)) {
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
		for (MemoryBlock Block : Blocks) {
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
			int instrLength = 0;
			try {
				instrLength = instr.getBytes().length;
			} catch (MemoryAccessException e) {
				throw new NullPointerException("Tried to read bytes at unknown location " + addr);
			}
			Cursor c = new Cursor(addr);
			byte jmpFirstByte = c.DerefByte();
			if (jmpFirstByte == -23) { // near jump, 32 bit branch pointer
				int jmpRel = c.DerefInt();
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
		for (MemoryBlock Block : Blocks) {
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
			for (MemoryBlock Block : Blocks) {
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

    // private CategoryPath RootPath = new CategoryPath("/xrd759/fld/fldChara");


	// https://stackoverflow.com/a/1143979

	static String toCamelCase(String s){
	   String[] parts = s.split("_");
	   String camelCaseString = "";
	   for (String part : parts){
	      camelCaseString = camelCaseString + toProperCase(part);
	   }
	   return camelCaseString;
	}

	static String toProperCase(String s) {
	    return s.substring(0, 1).toUpperCase() +
	               s.substring(1).toLowerCase();
	}

	static String TransformDataTypeName(String name) {
		Boolean containsPointer = false;
		if (name.endsWith("*")) {
			containsPointer = true;
			//name = "*const " + name.substring(0, name.length() - 2);
		} else if (name.equals("UUIC_Parts_Base")) {
			return "PartsBase";
		} else if (
				name.equals("undefined") ||
				name.equals("byte") || 
				name.equals("char")
		) {
			return "u8";
		} else if (name.equals("pointer")) {
			return "usize";
		} else if (name.equals("ulonglong") || name.equals("undefined8")) {
			return "u64";
		} else if (name.equals("longlong")) {
			return "i64";
		} else if (name.equals("uint") || name.equals("undefined4")) {
			return "u32";
		} else if (name.equals("int")) {
			return "i32";
		} else if (name.equals("ushort") || name.equals("undefined2")) {
			return "u16";
		} else if (name.equals("short")) {
			return "i16";
        } else if (name.equals("uchar") || name.equals("undefined1")) {
			return "u8";
		} else if (name.equals("float")) {
            return "f32";
        } else if (name.equals("double")) {
            return "f64";
        }
		if (containsPointer) {
			name = "*const " + name.substring(0, name.length() - 2);
		}
		return name;
	}

    public class VtableFunction {
    	public LinkedList<String> ParamTypes;
    	public LinkedList<String> ParamNames;
    	public String ReturnType;
        public String FunctionName;
        public int Index;
    	
    	public VtableFunction(Address address, int index) {
    		Function function = currentProgram.getListing().getFunctionAt(address);
    		ParamTypes = new LinkedList<String>();
    		ParamNames = new LinkedList<String>();
            FunctionName = convertCamelCaseToSnakeRegex(function.getName());
            Index = index;
    		ReturnType = TransformDataTypeName(function.getReturnType().getName().trim());
    		if (function.getParameterCount() > 1) {
    			for (int i = 1; i < function.getParameterCount(); i++) {
    				Parameter param = function.getParameter(i);
    				String dataTypeName = TransformDataTypeName(param.getDataType().getName().trim());
    				ParamTypes.add(dataTypeName);
    				String paramName = param.getName();
    				ParamNames.add(paramName);
    			}
    		}
    	}
    	
    	@Override
    	public String toString() {
    		String funcDef = "pub fn " + FunctionName + "(&self";
    		for (int i = 0; i < ParamTypes.size(); i++) {
    			String paramName = ParamNames.get(i);
    			String paramType = ParamTypes.get(i);
				funcDef += ", " + paramName + ": " + paramType;
			}
    		funcDef += ")";
    		if (!ReturnType.equals("void")) {
    			funcDef += " -> " + ReturnType;
    		}
    		funcDef += " {\n\tunsafe {\n";
    		funcDef += "\t\tlet vtable_func = self.get_cpp_vtable().add(" + Index + " * size_of::<usize>());\n";
    		funcDef += "\t\tlet vtable_func = *std::mem::transmute::<_, *const fn(&Self";
    		for (String param : ParamTypes) {
    			funcDef += ", " + param;
    		}
    		funcDef += ")";
    		if (!ReturnType.equals("void")) {
    			funcDef += " -> " + ReturnType;
    		}
    		funcDef += ">(vtable_func);\n";
    		funcDef += "\t\t(vtable_func)(self";
    		for (String param : ParamNames) {
    			funcDef += ", " + param;
    		}
    		funcDef += ")\n";
    		funcDef += "\t}\n";
    		funcDef += "}\n";
    		return funcDef;
    	}
    	
    	public Boolean IsSelfOnly() {
    		return ParamTypes.isEmpty() && ParamNames.isEmpty();
    	}
    	
    	public void SetParamTypes(LinkedList<String> _ParamTypes ) {
    		ParamTypes = _ParamTypes;
    	}
    	public void SetParamNames(LinkedList<String> _ParamNames ) {
    		ParamNames = _ParamNames;
    	}
    	public void SetReturnType(String _ReturnType ) {
    		ReturnType = _ReturnType;
    	}
    }

    static String convertCamelCaseToSnakeRegex(String input) {
        return input
          .replaceAll("([A-Z])(?=[A-Z])", "$1_")
          .replaceAll("([a-z])([A-Z])", "$1_$2")
          .toLowerCase();
    }

    @Override
	public void run() throws Exception {
		Data functionTable = currentProgram.getListing().getDataAt(currentAddress);
        LinkedList<VtableFunction> Functions = new LinkedList<>();
        for (int i = 0; i < functionTable.getNumComponents(); i++) {
            Data functionEntry = functionTable.getComponent(i);
            Address functionAddr = toAddr(functionEntry.getValue().toString());
            Functions.add(new VtableFunction(functionAddr, i));
        }
        for (VtableFunction Function : Functions) {
            println(Function.toString());
        }
	}
}
