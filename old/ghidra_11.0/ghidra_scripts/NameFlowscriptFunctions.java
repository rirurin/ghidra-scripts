//
//@author Rirurin
//@category Persona Modding
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.Stack;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.DataConverter;
import ghidra.util.bytesearch.DummyMatchAction;
import ghidra.util.bytesearch.GenericByteSequencePattern;
import ghidra.util.bytesearch.GenericMatchAction;
import ghidra.util.bytesearch.Match;
import ghidra.util.bytesearch.MemoryBytePatternSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class NameFlowscriptFunctions extends GhidraScript {
	
	private Memory GMemory;
	public static int SECTION_FUNC_COUNT_THRESHOLD = 4000; 
	private DataTypeManager BuiltinDTM;
	private DataTypeManager ProgramDTM;
	private DTMStructureFactory StructFactory;
	
	// Function signatures
	public HashMap<String, String> FunctionLocations;
	public static String PTR_FLOWSCRIPT_MODULES = "4C 8D 3D ?? ?? ?? ?? 8B F5";
	public static String INTERPRETER_GETINTARG = "4C 8B 05 ?? ?? ?? ?? 41 8B 50 ?? 29 CA";
	public static String INTERPRETER_GETFLOATARG = "4C 8B 05 ?? ?? ?? ?? 41 8B 50 ?? 2B D1 8D 42 ?? 83 F8 2F 77 ??";
	
	// Section names
	public static String[] Persona5SectionNames = new String[] { "Common", "Field", "AI", "Social", "Facility", "Net" };
	public static String[] Persona3ReloadSectionNames = new String[] { "Common", "Battle", "Field", "Community", "Event", "Facility" };
	public static String[] MetaphorRefantazioSectionNames = new String[] { };
	
	// Workaround for Java's lack of pass-by-reference.
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
	// From https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/FindDataTypeScript.java
	private DataTypeManager getDataTypeManagerByName(String name) {
		PluginTool tool = state.getTool();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
		for (DataTypeManager manager : dataTypeManagers) {
			String managerName = manager.getName();
			if (name.equals(managerName)) {
				return manager;
			}
		}
		return null;
	}
	// From Examples/PrintStructureScript.java
	private DataType findDataTypeByName(String name) {
		PluginTool tool = state.getTool();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
		for (DataTypeManager manager : dataTypeManagers) {
			DataType dataType = manager.getDataType(name);
			if (dataType != null) {
				return dataType;
			}
		}
		return null;
	}
	// Split a nested namespace (btl::boss::AKECHI) into a list of strings [btl, boss, AKECHI]
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
	
	private Symbol MakeSymbol(Address addr, String name) {
		var TypeSyms = currentProgram.getSymbolTable().getSymbols(addr);
		Symbol SymOut = null;
		for (int i = 0; i < TypeSyms.length; i++) {
			if (TypeSyms[i].getName().equals(name)) {
				SymOut = TypeSyms[i];
				break;
			}
		}
		if (SymOut == null) {
			try {
				SymOut = currentProgram.getSymbolTable().createLabel(addr, name, SourceType.ANALYSIS);
			} catch (InvalidInputException e) {
				throw new IllegalArgumentException("Couldn't name a symbol with the name " + name);
			}
		}
		return SymOut;
	}
	public Address DerefPointer(Address PointerToPointer) {
		try {			
			if (currentProgram.getDefaultPointerSize() == 8) {
				return toAddr(Long.toHexString(GMemory.getLong(PointerToPointer)));
			} else if (currentProgram.getDefaultPointerSize() == 4) {
				return toAddr(Integer.toHexString(GMemory.getInt(PointerToPointer)));
			} else {
				throw new IllegalArgumentException("");
			}
		} catch (MemoryAccessException e) {
			throw new NullPointerException("Tried to access memory at an unknown location: " + PointerToPointer.getOffset());
		}
	}
	
	// Get an advanced data type consisting of a base type + pointer and array modifiers
	// Based on implementation in UnrealGen.java
	// https://github.com/rirurin/Unreal.ObjectDumpToJson/blob/master/ghidra_scripts/UnrealGen.java
	private DataType AddDataTypeModifier(DataType curr, String token) {
		DataType res;
		switch (token.charAt(0)) {
			case '*':
				res = new Pointer64DataType(curr);
				break;
			case '[':
				Pattern p = Pattern.compile("\\d+");
				Matcher m = p.matcher(token);
				m.find();
				int arrayEntries = Integer.parseInt(m.group()); // this operation should be safe
				res = new ArrayDataType(curr, arrayEntries, curr.getLength());
				break;
			default:
				throw new IllegalArgumentException("Invalid starting character " + token.charAt(0) + " (this error should not appear)");
		}
		return res;
	}
	private DataType MakeBaseDataType(CategoryPath Category, String dtPure) {
		DataType res;
		switch (dtPure) {
			// Built in types
			case "char" : res = new CharDataType(); break;
			case "byte" : res = new ByteDataType(); break;
			case "short" : res = new ShortDataType(); break;
			case "ushort": res = new UnsignedShortDataType(); break;
			case "int" : res = new IntegerDataType(); break;
			case "uint" : res = new UnsignedIntegerDataType(); break;
			case "long" : case "longlong" : res = new LongLongDataType(); break;
			case "ulong" : case "ulonglong" : res = new UnsignedLongLongDataType(); break;
			case "void": res = new VoidDataType(); break;
			case "string": res = new StringDataType(); break;
			case "float": res = new FloatDataType(); break;
			case "double": res = new DoubleDataType(); break;
			// Note: the type to look for might not exist yet, so we'll need to register it.
			default: 
				if (Category == null) {
					throw new IllegalArgumentException("Only valid to pass a null category if you're getting a basic type!");
				}
				res = currentProgram.getDataTypeManager().getDataType(Category, dtPure);
				break;
		}
		return res;
	}
	
	private DataType GetDataType(String cat, String dt) {
		DataType res;
		CategoryPath Category = cat != null ? new CategoryPath(cat) : null;
		Pattern p = Pattern.compile("\\[\\d+\\]|\\*");
		Matcher m = p.matcher(dt);
		String dtPure = p.split(dt)[0]; // base type name
		Queue<String> modifiers = new ArrayDeque<>();
		modifiers.add(dtPure);
		while (m.find()) {
			modifiers.add(m.group());
		}
		res = MakeBaseDataType(Category, modifiers.poll());
		if (res != null) {				
			while (!modifiers.isEmpty()) {
				res = AddDataTypeModifier(res, modifiers.poll());
			}
		}
		return res;
	}
	
	private boolean IsMemoryLocationValid(Address address) {
		MemoryBlock[] Blocks = currentProgram.getMemory().getBlocks();
		for (var Block : Blocks) {
			if (Block.contains(address)) return true;
		}
		return false;
	}
	private int GetStringLength(Address address) {
		Cursor c = new Cursor(address);
		byte currByte = -1;
		int len = 0;
		do {
			currByte = c.DerefByte();
			len++;
		} while (currByte != 0);
		return len;
	}
	
	// From WindowsRttiAnalyze.java
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
	// From WindowsRttiAnalyze.java
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
	
	// ------------------------------------------------------------------
	// ==================================================================
	// ------------------------------------------------------------------
	
	public class DTMStructureFactory {
		public HashMap<DataTypePath, DTMStructure> Structs;
		public DTMStructureFactory(List<DTMStructure> _Structs) {
			//Structs = _Structs; // Create data types for all the registered classes
			Structs = new HashMap<>();
			for (var _Struct : _Structs) {
				Structs.put(GetDTPath(_Struct.GetDataTypePath(), _Struct.GetDataTypeName()), _Struct);
			}
			for (DTMStructure Struct : Structs.values()) {
				Struct.Register(this);
			}
		}
		public static DataTypePath GetDTPath(String Path, String Type) {
			String PathT = (Path.charAt(0) == '/' ? "" : "/") + Path;
			return new DataTypePath(new CategoryPath(PathT), Type);
		}
	}
	
	public abstract class DTMStructure {
		protected DTMStructureFactory Factory;
		protected Structure Struct;
		protected boolean TypeAlreadyExists;
		public DTMStructure() {
			// Check that the type already exists, so that we don't need to make it again.
			Struct = (Structure)ProgramDTM.getDataType(new CategoryPath(GetDataTypePath()), GetDataTypeName());
			TypeAlreadyExists = Struct != null;
			if (!TypeAlreadyExists) {
				//Add the data type to DTM before adding fields so that all other types are aware of it.
				Struct = (Structure)ProgramDTM.addDataType(new StructureDataType(new CategoryPath(GetDataTypePath()), GetDataTypeName(), GetDataTypeSize()), null);	
			}
		}
		public void Register(DTMStructureFactory _Factory) {
			Factory = _Factory;
			if (!TypeAlreadyExists) MakeStructureFields(Struct);
			TypeAlreadyExists = true;
		}
		public Structure GetStructure() { return Struct; }
		public abstract void MakeStructureFields(Structure _Struct);
		public abstract String GetDataTypeName();
		public abstract int GetDataTypeSize();
		public abstract String GetDataTypePath();
	}
	
	public class FlowscriptSectionType extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0, GetDataType("/scr", "FlowscriptFunctionV3*"), 0, "ScriptCommands", null);
			_Struct.replaceAtOffset(8, GetDataType(null, "ulong"), 0, "Count", null);
		}
		@Override public String GetDataTypeName() { return "FlowscriptSection"; }
		@Override public int GetDataTypeSize() { return 0x10; } 
		@Override public String GetDataTypePath() { return "/scr"; }
	}
	public class FlowscriptFunctionTypeV3 extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0, GetDataType(null, "void*"), 0, "Function", null);
			_Struct.replaceAtOffset(8, GetDataType(null, "ulong"), 0, "ParameterCount", null);
			_Struct.replaceAtOffset(0x10, GetDataType(null, "char*"), 0, "Name", null);
		}
		@Override public String GetDataTypeName() { return "FlowscriptFunctionV3"; }
		@Override public int GetDataTypeSize() { return 0x18; } 
		@Override public String GetDataTypePath() { return "/scr"; }
	}
	public class FlowscriptFunctionTypeV4 extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType(null, "void*"), 0, "Function", null);
			_Struct.replaceAtOffset(0x8, GetDataType(null, "int"), 0, "ParameterCount", null);
			_Struct.replaceAtOffset(0xc, GetDataType(null, "int"), 0, "ReturnType", null);
			_Struct.replaceAtOffset(0x10, GetDataType(null, "char*"), 0, "Name", null);
			_Struct.replaceAtOffset(0x18, GetDataType(null, "int[10]"), 0, "ParameterType", null);
		}
		@Override public String GetDataTypeName() { return "FlowscriptFunctionV4"; }
		@Override public int GetDataTypeSize() { return 0x40; } 
		@Override public String GetDataTypePath() { return "/scr"; }
	}
	public class FlowscriptSection {
		public Address PointerToFunctionEntries;
		public int FunctionCount;
		public List<FlowscriptFunctionV3> Functions;
		public Namespace SectionNamespace;
		public FlowscriptSection(Address _PointerToFunctionEntries, int _FunctionCount, String _SectionName) {
			PointerToFunctionEntries = _PointerToFunctionEntries;
			FunctionCount = _FunctionCount;
			Functions = new ArrayList<>();
			try {
				SectionNamespace = GetOrMakeNamespace("ScriptInterpreter::" + _SectionName);
			} catch (InvalidInputException | DuplicateNameException e) {
				println("Error: Couldn't set a namespace");
			}
		}
		public void ClearCodeListing() {
			DataType FlowscriptType = GetDataType("/scr", "FlowscriptFunctionV3[" + FunctionCount + "]");
			Data ExistingData = currentProgram.getListing().getDataAt(PointerToFunctionEntries);
			if (!ExistingData.getDataType().isEquivalent(FlowscriptType)) {
				//println("Clear! " + ExistingData.getDataType().toString() + " vs " + FlowscriptType.toString() + " at " + PointerToFunctionEntries.toString());
				currentProgram.getListing().clearCodeUnits(PointerToFunctionEntries, PointerToFunctionEntries.add(FlowscriptType.getLength()-1), false);
			}
		}
		
		public void PopulateFunctionList() throws CodeUnitInsertionException {
			DataType FlowscriptType = GetDataType("/scr", "FlowscriptFunctionV3[" + FunctionCount + "]");
			Data FlowscriptData = currentProgram.getListing().getDataAt(PointerToFunctionEntries);
			if (!FlowscriptData.getDataType().isEquivalent(FlowscriptType)) {
				FlowscriptData = currentProgram.getListing().createData(PointerToFunctionEntries, FlowscriptType);
			}
			println("Populate " + FunctionCount + " components, clear " + FlowscriptType.getLength() + " bytes: made data " + FlowscriptData.getDataType().getName() + " at " + PointerToFunctionEntries.toString());
			for (int i = 0; i < FlowscriptData.getNumComponents(); i++) {
				Functions.add(new FlowscriptFunctionV3(new FieldedData(FlowscriptData.getComponent(i)), i, SectionNamespace));
				
			}
		}
	}
	public abstract class FlowscriptFunctionBase {
		public String Name;
		public List<ParameterType> Parameters;
		public ParameterType ReturnParam;
		public Function FlowFunction;
		public Namespace ParentNamespace;
	}
	public class FlowscriptFunctionV3 extends FlowscriptFunctionBase {
		public FlowscriptFunctionV3(FieldedData FlowscriptFunctionEntry, int index, Namespace _ParentNamespace) throws CodeUnitInsertionException {
			// Get function name, and rename the function to it.
			ParentNamespace = _ParentNamespace;
			Address NameLocation = toAddr(FlowscriptFunctionEntry.Get("Name").getValue().toString());
			Name = "FUNC" + index;
			if (IsMemoryLocationValid(NameLocation) ) {
				Data NameData = currentProgram.getListing().getDataAt(NameLocation);
				if (!NameData.getDataType().isEquivalent(new StringDataType())) {
					currentProgram.getListing().clearCodeUnits(NameLocation, NameLocation.add(GetStringLength(NameLocation)-1), false);
					NameData = currentProgram.getListing().createData(NameLocation, new StringDataType());
				}
				Name = NameData.getValue().toString();
			}
			Address FunctionLocation = toAddr(FlowscriptFunctionEntry.Get("Function").getValue().toString());
			FlowFunction = GetOrMakeFunction(FunctionLocation, Name, ParentNamespace);
			// Determine return type and parameters - we'll need to decompile the function
			Parameters = new LinkedList<>(); // Defaults
			ReturnParam = ParameterType.VOID;
		}
	}
	public class FlowscriptFunctionV4 extends FlowscriptFunctionBase {
		
	}
	
	public enum ParameterType {
		VOID,
		INT,
		FLOAT,
		STRING
	}
	
	public List<FlowscriptSection> GetSuitableFlowscriptSections(Address PointerToSection) {
		// Look for suitable Section name:
		List<String> SectionNames = new ArrayList<>();
		String execName = currentProgram.getName();
		if (execName.equals("P5R.exe")) {
			println("Using Persona 5 Royal Section Names");
			for (var sec : Persona5SectionNames) {
				SectionNames.add(sec);
			}
		} else if (execName.equals("P3R.exe") ) {
			println("Using Persona 3 Reload Section Names");
			for (var sec : Persona3ReloadSectionNames) {
				SectionNames.add(sec);
			}
		} else if (execName.equals("METAPHOR.exe") ) {
			println("Using Metaphor: Refantazio Section Names");
			for (var sec : MetaphorRefantazioSectionNames) {
				SectionNames.add(sec);
			}
		}
		Cursor cur = new Cursor(PointerToSection);
		Ref<Address> SecPtr = new Ref<>();
		List<FlowscriptSection> Sections = new ArrayList<FlowscriptSection>();
		Address NextClosestPointer = currentProgram.getMaxAddress(); // Track where the closest pointer is after our array
		while (cur.DerefPointer(SecPtr)) {
			if (
				NextClosestPointer != null &&  
				cur.Tell().compareTo(NextClosestPointer) == 1
			) {
				// We're overlapping with a pointer to a flowscript function array, stop now
				break;
			}
			// If this pointer is closer to us, but after the pointer we're reading
			if (
				SecPtr.get().compareTo(NextClosestPointer) == -1 &&
				SecPtr.get().compareTo(cur.Tell()) == 1
			) {
				NextClosestPointer = SecPtr.get();
			}
			int FunctionCount = (int)cur.DerefLong();
			if (FunctionCount > SECTION_FUNC_COUNT_THRESHOLD || FunctionCount == 0) {
				break; // got a nonsensical function count, stop here
			}
			// Add the new section!
			String SectionName = "Section" + Sections.size();
			if (Sections.size() < SectionNames.size()) {
				SectionName = SectionNames.get(Sections.size());
			}
			Sections.add(new FlowscriptSection(SecPtr.get(), FunctionCount, SectionName));
		}
		return Sections;
	}
	private boolean IsPointerAligned(Address addr) {
		return (addr.getOffset() % currentProgram.getDefaultPointerSize()) == 0;
	}
	
	private void Initialize() {
		GMemory = currentProgram.getMemory();
		BuiltinDTM = getDataTypeManagerByName("BuiltInTypes");
		ProgramDTM = currentProgram.getDataTypeManager();
		// Make data types
		List<DTMStructure> Structs = new ArrayList<>();
		Structs.add(new FlowscriptSectionType());
		Structs.add(new FlowscriptFunctionTypeV3());
		Structs.add(new FlowscriptFunctionTypeV4());
		StructFactory = new DTMStructureFactory(Structs);
	}
	
	public class SignatureScanner {
		public List<SignatureScanPattern> Patterns;
		// Hack for GenericMatchAction lambda to capture SignatureScanPattern instance (this) 
		// instead of the GenericMatchAction instance (fuck Java, all my homies hate Java)
		public Ref<SignatureScanner> RefSelf;
		public GenericMatchAction<Ref<SignatureScanner>> MatchAction;
		public Ref<Address> Bind;
		public BiConsumer<Address, Ref<Address>> TransformCallback;
		public boolean HasBeenFound;
		
		public SignatureScanner(String[] patterns, BiConsumer<Address, Ref<Address>> _TransformCallback, Ref<Address> _Bind) {
			RefSelf = new Ref<>(this);
			Patterns = new LinkedList<>();
			for (var pattern : patterns) {
				Patterns.add(new SignatureScanPattern(pattern));
			}
			HasBeenFound = false;
			TransformCallback = _TransformCallback;
			Bind = _Bind;
			MatchAction = new GenericMatchAction<>(RefSelf) {
				@Override
				public void apply(Program prog, Address addr, Match match) {
					synchronized(this) {
						if (HasBeenFound) {
							return;
						}
						HasBeenFound = true;
					}
					RefSelf.get().TransformCallback.accept(addr, Bind);
				}
			};
		}
		public void AddToSearcher(MemoryBytePatternSearcher Searcher) {
			for (var Pattern : Patterns) {
				Searcher.addPattern(new GenericByteSequencePattern<Ref<SignatureScanner>>(Pattern.ByteSequence, Pattern.Mask, MatchAction));
			}
		}
	}
	
	public class SignatureScanPattern {
		public byte[] ByteSequence;
		public byte[] Mask;
		
		public SignatureScanPattern(String strPattern) {
			String[] StringBytes = strPattern.split(" "); // one byte per string
			ByteSequence = new byte[StringBytes.length];
			Mask = new byte[StringBytes.length];
			for (int i = 0; i < StringBytes.length; i++) {
				if (StringBytes[i].contains("?")) {
					ByteSequence[i] = 0;
					Mask[i] = 0;
				} else {
					ByteSequence[i] = (byte)Integer.parseInt(StringBytes[i], 16);
					Mask[i] = -1;
				}
			}
		}
	}
	
	// Refer to each component of the data type by it's name
	public class FieldedData {
		private HashMap<String, Data> NamesToFields;
		public FieldedData(Data TargetData) {
			NamesToFields = new HashMap<>();
			for (int i = 0; i < TargetData.getNumComponents(); i++) {
				Data Field = TargetData.getComponent(i);
				NamesToFields.put(Field.getFieldName(), Field);
			}
		}
		public Set<String> FieldNames() { return NamesToFields.keySet(); }
		public Data Get(String name) { return NamesToFields.get(name); }
	}
	
	@Override
	protected void run() throws Exception {
		Initialize();
		// Look for Signature Scans
		MemoryBytePatternSearcher SigscanSearch = new MemoryBytePatternSearcher("Sigscan Searcher");
		MemoryBlock[] MemoryBlocks = currentProgram.getMemory().getBlocks();
		AddressSet searchSet = new AddressSet();
		for (MemoryBlock block : MemoryBlocks) {
			searchSet.add(block.getStart(), block.getEnd());
		}
		Ref<Address> PointerToSection = new Ref<>(null);
		SignatureScanner GetFlowscriptModules = new SignatureScanner(new String[] {PTR_FLOWSCRIPT_MODULES}, (x, p) -> {
			try {
				int addBy = 7 + currentProgram.getMemory().getInt(x.add(3));
				p.set(x.add(addBy));
				println("Got Flowscript Modules: " + p.get().toString());
			} catch (MemoryAccessException e) {}
		}, PointerToSection);
		GetFlowscriptModules.AddToSearcher(SigscanSearch);
		SigscanSearch.search(currentProgram, searchSet, monitor); // This blocks so we can chill here
		
		if (PointerToSection.get() == null) {
			throw new IllegalArgumentException("Skill Issue! Couldn't find the signature for Flowscript Modules.");
		}
		if (!IsPointerAligned(PointerToSection.get())) {
			throw new IllegalArgumentException("Cursor needs to be aligned to nearest pointer address");
		}
		// Make Flowscript Sections
		List<FlowscriptSection> Sections = GetSuitableFlowscriptSections(PointerToSection.get());
		DataType SectionType = GetDataType("/scr", "FlowscriptSection[" + Sections.size() + "]");
		currentProgram.getListing().clearCodeUnits(PointerToSection.get(), PointerToSection.get().add(SectionType.getLength()-1), false);
		currentProgram.getListing().createData(PointerToSection.get(), SectionType);
		for (var Section : Sections) {
			Section.ClearCodeListing();
		}
		for (var Section : Sections) {
			Section.PopulateFunctionList();	
		}
	}
}