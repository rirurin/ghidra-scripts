//
//@author Rirurin
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.Stack;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.options.OptionsService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.EnumDataType;
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
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.bytesearch.GenericByteSequencePattern;
import ghidra.util.bytesearch.GenericMatchAction;
import ghidra.util.bytesearch.Match;
import ghidra.util.bytesearch.MemoryBytePatternSearcher;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class MetaphorCreateDataTypes extends GhidraScript {
	
	private Memory GMemory;
	private DataTypeManager BuiltinDTM;
	private DataTypeManager ProgramDTM;
	private DataTypeManager WindowsDTM;
	private DTMStructureFactory StructFactory;
	private CategoryPath RootPath = new CategoryPath("/");
	private HashMap<String, DataType> RttiTypes = new HashMap<>();
	
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
	private DataTypeManager getDataTypeManagerStartingWith(String name) {
		PluginTool tool = state.getTool();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
		for (DataTypeManager manager : dataTypeManagers) {
			String managerName = manager.getName();
			if (managerName.startsWith(name)) {
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
	
	private DataType GetDataType(String dt) { return GetDataType(null, dt); }
	
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
	
	public class DTMStructureFactory {
		public HashMap<DataTypePath, DTMDataType> Structs;
		public DTMStructureFactory(List<DTMDataType> _Structs) {
			//Structs = _Structs; // Create data types for all the registered classes
			Structs = new HashMap<>();
			for (var _Struct : _Structs) {
				Structs.put(GetDTPath(_Struct.GetDataTypePath(), _Struct.GetDataTypeName()), _Struct);
			}
			for (DTMDataType Struct : Structs.values()) {
				Struct.Register(this);
			}
		}
		public static DataTypePath GetDTPath(String Path, String Type) {
			String PathT = (Path.charAt(0) == '/' ? "" : "/") + Path;
			return new DataTypePath(new CategoryPath(PathT), Type);
		}
	}
	
	public interface DTMDataType {
		public void Register(DTMStructureFactory _Factory);
		public String GetDataTypeName();
		public int GetDataTypeSize();
		public String GetDataTypePath();
	}
	
	public abstract class DTMStructure implements DTMDataType {
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
			//if (!TypeAlreadyExists) MakeStructureFields(Struct);
			// replace the fields anyway so that we can update the struct
			MakeStructureFields(Struct);
			TypeAlreadyExists = true;
		}
		public abstract void MakeStructureFields(Structure _Struct);
		public abstract String GetDataTypeName(); 
		public abstract int GetDataTypeSize();
		public abstract String GetDataTypePath();
	}
	
	public abstract class DTMEnum implements DTMDataType {
		protected DTMStructureFactory Factory;
		protected ghidra.program.model.data.Enum DTEnum;
		protected boolean TypeAlreadyExists;
		public DTMEnum() {
			DTEnum = (ghidra.program.model.data.Enum)ProgramDTM.getDataType(new CategoryPath(GetDataTypePath()), GetDataTypeName());
			TypeAlreadyExists = DTEnum != null;
			if (!TypeAlreadyExists) {
				DTEnum = (ghidra.program.model.data.Enum)ProgramDTM.addDataType(new EnumDataType(new CategoryPath(GetDataTypePath()), GetDataTypeName(), GetDataTypeSize()), null);
			}
		}
		public void Register(DTMStructureFactory _Factory) {
			Factory = _Factory;
			if (!TypeAlreadyExists) MakeEnumFields(DTEnum);
			TypeAlreadyExists = true;
		}
		public abstract void MakeEnumFields(ghidra.program.model.data.Enum _Enum);
		public abstract String GetDataTypeName(); 
		public abstract int GetDataTypeSize();
		public abstract String GetDataTypePath();
	}
	
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
	
	// Decompiler stuff - cache some information about the last decompilation
		// From ShowConstantUse.java
		
	private DecompInterface decomplib;
	DecompileResults lastResults = null;
	
	private HighFunction hfunction = null;
	
	private Address lastDecompiledFuncAddr = null;
	
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		// call it to get results
		if (!decompInterface.openProgram(currentProgram)) {
			println("Decompile Error: " + decompInterface.getLastMessage());
			return null;
		}

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, program);
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	public DecompileResults decompileFunction(Function f) {
		// don't decompile the function again if it was the same as the last one
		//
		if (!f.getEntryPoint().equals(lastDecompiledFuncAddr)) {
			lastResults = decomplib.decompileFunction(f,
					decomplib.getOptions().getDefaultTimeout(), monitor);
		}
		hfunction = lastResults.getHighFunction();
		lastDecompiledFuncAddr = f.getEntryPoint();

		return lastResults;
	}
	
	private boolean CheckFunctionIsFreeSized(Address testAddress) {
		return testAddress.equals(toAddr("0x1403e3960")) || 
				testAddress.equals(toAddr("0x14146fe00")) || 
				testAddress.equals(toAddr("0x14149a560")); 
	}
	
	private void GetRttiTypes() {
		// https://www.lukaszlipski.dev/post/rtti-msvc/
		RttiTypes.put("TypeDescriptor", BuiltinDTM.getDataType(RootPath, "RTTI_0"));
		RttiTypes.put("BaseClassDescriptor", BuiltinDTM.getDataType(RootPath, "RTTI_1"));
		RttiTypes.put("BaseClassArray", BuiltinDTM.getDataType(RootPath, "RTTI_2"));
		RttiTypes.put("ClassHierachy", BuiltinDTM.getDataType(RootPath, "RTTI_3"));
		RttiTypes.put("CompleteObjectLocator", BuiltinDTM.getDataType(RootPath, "RTTI_4"));
	}
	
	private void Initialize() {
		GMemory = currentProgram.getMemory();
		BuiltinDTM = getDataTypeManagerByName("BuiltInTypes");
		ProgramDTM = currentProgram.getDataTypeManager();
		WindowsDTM = getDataTypeManagerByName("windows");
		decomplib = setUpDecompiler(currentProgram);
		GetRttiTypes();
		NamespaceToVtable = new HashMap<>();
		NamespaceToObjectLocator = new HashMap<>();
		NamespaceToStructSize = new HashMap<>();
		NamespaceToClassHierarchy = new HashMap<>();
		ClassHierarchy = new HashMap<>();
	}
	
	private boolean NamespaceProbablyContainsFreeSized(String namespaceNameFull) {
		return !namespaceNameFull.startsWith("std") &&
				!namespaceNameFull.startsWith("app::dataStructuresForFileIO")
				;
	}
	
	private boolean CheckDataTypeEquality(DataType a, DataType b) {
		return a.getPathName().equals(b.getPathName());
	}
	
	private Data GetOrCreateClassHierarchyData(Data rttiLocator) throws CodeUnitInsertionException {
		Data rttiHierarchy = currentProgram.getListing().getDataAt(toAddr(rttiLocator.getComponent(4).getValue().toString()));
		if (!CheckDataTypeEquality(rttiHierarchy.getDataType(), RttiTypes.get("ClassHierachy"))) {
			currentProgram.getListing().clearCodeUnits(rttiHierarchy.getAddress(), rttiHierarchy.getAddress().add(RttiTypes.get("ClassHierachy").getLength() - 1), false);
			rttiHierarchy = currentProgram.getListing().createData(rttiHierarchy.getAddress(), RttiTypes.get("ClassHierachy"));
		}
		return rttiHierarchy;
	}
	
	private Data GetOrCreateBaseClassArray(Data rttiHierarchy, int NumBaseClasses) throws CodeUnitInsertionException {
		Data rttiBaseDataArray = currentProgram.getListing().getDataAt(toAddr(rttiHierarchy.getComponent(3).getValue().toString()));
		if (!CheckDataTypeEquality(rttiBaseDataArray.getDataType(), RttiTypes.get("BaseClassArray"))) {
			currentProgram.getListing().clearCodeUnits(rttiBaseDataArray.getAddress(), rttiBaseDataArray.getAddress().add(4 * NumBaseClasses - 1), false);
			rttiBaseDataArray = currentProgram.getListing().createData(rttiBaseDataArray.getAddress(), RttiTypes.get("BaseClassArray"));
		}
		return rttiBaseDataArray;
	}
	
	private Data GetOrCreateBaseClassDescriptor(Data classArrayEntry) throws CodeUnitInsertionException {
		Data baseClassDesc = currentProgram.getListing().getDataAt(toAddr(classArrayEntry.getValue().toString()));
		if (!CheckDataTypeEquality(baseClassDesc.getDataType(), RttiTypes.get("BaseClassDescriptor"))) {
			currentProgram.getListing().clearCodeUnits(baseClassDesc.getAddress(), baseClassDesc.getAddress().add(RttiTypes.get("BaseClassDescriptor").getLength() - 1), false);
			baseClassDesc = currentProgram.getListing().createData(baseClassDesc.getAddress(), RttiTypes.get("BaseClassDescriptor"));
		}
		return baseClassDesc;
	}
	
	private Namespace GetTypeDescriptor(Data classDesc) {
		Symbol typeDescSym = currentProgram.getSymbolTable().getPrimarySymbol(toAddr(classDesc.getComponent(0).getValue().toString()));
		return typeDescSym.getParentNamespace();
	}
	
	public HashMap<Namespace, Address> NamespaceToVtable;
	public HashMap<Namespace, Address> NamespaceToObjectLocator;
	public HashMap<Namespace, Address> NamespaceToClassHierarchy;
	public HashMap<Namespace, Integer> NamespaceToStructSize;
	
	private Integer GetStructSizeFromZeroOffsetTable(HighFunction hf) {
		Integer structSize = null; 
		var pcodeOps = hf.getPcodeOps();
		while (pcodeOps.hasNext()) {
			var currPcodeOp = pcodeOps.next();
			var varnodes = currPcodeOp.getInputs();
			switch (currPcodeOp.getOpcode()) {
				case PcodeOp.CALL:
					if (
							varnodes.length == 3 && 
							varnodes[0].isAddress() && 
							CheckFunctionIsFreeSized(varnodes[0].getAddress()) &&
							varnodes[2].isConstant()
							) {
						structSize = (int)varnodes[2].getOffset();
					}
				break;
			}
		}
		return structSize;
	}
	
	private Integer FindThunkFunctionForOffsetedTable(HighFunction hf) {
		var pcodeOps = hf.getPcodeOps();
		Integer registerId = null;
		Integer offset = null;
		Integer structSize = null;
		int instrCount = 0;
		while (pcodeOps.hasNext()) {
			var currPcodeOp = pcodeOps.next();
			var varnodes = currPcodeOp.getInputs();
			switch (currPcodeOp.getOpcode()) {
				case PcodeOp.INT_ADD:
					if (varnodes.length == 2 && varnodes[0].isRegister() && varnodes[1].isConstant()) {
						registerId = (int)varnodes[0].getOffset();
						offset = (int)(0 - varnodes[1].getOffset());
					}
				break;
				case PcodeOp.CALL:
					if (registerId != null && varnodes.length == 2 && varnodes[0].isAddress() && varnodes[1].getOffset() == registerId) {
						//println("Found function: " + varnodes[0].getAddress());
						Function actualFunc = currentProgram.getListing().getFunctionAt(varnodes[0].getAddress());
						DecompileResults res = decompileFunction(actualFunc);
						structSize = GetStructSizeFromZeroOffsetTable(res.getHighFunction());
					}
				break;
			}
			if (instrCount > 2 || structSize != null) break; // too long, fallback to zero offset table func ()
			instrCount++;
		}
		return structSize;
	}
	
	private void GetStructSizes() {
		var vtableSymbolsIter = currentProgram.getSymbolTable().getSymbols("vtable");
		int count = 0;
		while (vtableSymbolsIter.hasNext()) {
			var currVtable = vtableSymbolsIter.next();
			Namespace classNamespace = currVtable.getParentNamespace();
			var rttiLocatorSym = currentProgram.getSymbolTable().getSymbols("RTTI_Complete_Object_Locator", classNamespace);
			var vtableMetaPtr = currentProgram.getSymbolTable().getSymbols("vtable_meta_ptr", classNamespace);
			if (
				!NamespaceProbablyContainsFreeSized(classNamespace.getName(true)) || // check by name 
				currVtable.getAddress().equals(toAddr("0x14178c230")) || // ignore purecall
				rttiLocatorSym.size() == 0 || // has ptr to rtti data
				vtableMetaPtr.size() == 0 // same thing
			) continue;
			// Look for the RTTI locator that matches the data pointed to in vtable_meta_ptr
			Cursor vtableMeta = new Cursor(vtableMetaPtr.get(0).getAddress());
			Ref<Address> vtableMetaAddr = new Ref<>();
			vtableMeta.DerefPointer(vtableMetaAddr);
			Data rttiLocator = currentProgram.getListing().getDataAt(vtableMetaAddr.get());
			int offset = Integer.parseInt(rttiLocator.getComponent(1).getValue().toString().substring(2), 16);
			NamespaceToObjectLocator.put(classNamespace, rttiLocator.getAddress());
			Data rttiHierarchy = null;
			try { rttiHierarchy = GetOrCreateClassHierarchyData(rttiLocator); } catch (CodeUnitInsertionException ex) { continue; }
			NamespaceToClassHierarchy.put(classNamespace, rttiHierarchy.getAddress());
			var currVtableData = currentProgram.getListing().getDataAt(currVtable.getAddress());
			if (currVtableData == null || currVtableData.getNumComponents() == 0) continue;
			NamespaceToVtable.put(classNamespace, currVtable.getAddress());
			Function firstFunc = currentProgram.getListing().getFunctionAt(toAddr(currVtableData.getComponent(0).getValue().toString()));
			DecompileResults res = decompileFunction(firstFunc);
			HighFunction hf = res.getHighFunction();
			if (hf == null) continue;
			Integer structSize = offset > 0 ? FindThunkFunctionForOffsetedTable(hf) : GetStructSizeFromZeroOffsetTable(hf);
			if (structSize != null) {
				NamespaceToStructSize.put(classNamespace, structSize);
				if ((NamespaceToStructSize.size() % 100) == 0) {
					println("Found struct size for " + NamespaceToStructSize.size() + " classes");
				}
			}
		}
	}
	
	public class ClassHierarchy {
		public String ClassName;
		public CategoryPath Path;
		public Namespace Namespace;
		public HashMap<Integer, LinkedList<ClassHierarchy>> BaseClasses;
		public Address HierarchyAddress;
		public Structure StructType;
		public boolean bIsNewStructType;
		public int StructSize;
		
		public ClassHierarchy(String _ClassName, Namespace _Namespace, int _StructSize, Address _HierarchyAddress) {
			ClassName = _ClassName;
			Namespace = _Namespace;
			StructSize = _StructSize;
			HierarchyAddress = _HierarchyAddress;
			List<String> nsPath = Namespace.getPathList(true);
			String catPath = "";
			for (int i = 0; i < nsPath.size() - 1; i++) {
				if (nsPath.get(i).equals("app")) catPath += "/xrd759";
				else catPath += "/" + nsPath.get(i);	
			}
			Path = new CategoryPath(catPath);
			DataType existingType = ProgramDTM.getDataType(Path, ClassName);
			if (existingType != null) {
				StructType = (Structure)existingType;
				bIsNewStructType = false;
			} else {
				StructType = new StructureDataType(Path, ClassName, StructSize);
				bIsNewStructType = true;
			}
			BaseClasses = new HashMap<>();
		}
	}
	
	public HashMap<Namespace, ClassHierarchy> ClassHierarchy;
	
	private void BuildClassHierarchy() {
		// A couple of requirements for adding a class to the hierarchy:
		// A vtable for it must exist (gfw::MemObject is excluded from this)
		// For each offset, add a new entry to the base class linked list until we hit an entry with a different offset
		NamespaceToVtable.forEach((k , v) -> {
			Integer structSizeMaybe = NamespaceToStructSize.get(k);
			if (structSizeMaybe == null) structSizeMaybe = 8; // default to 8 - enough to fit a vtable
			var hierarchy = NamespaceToClassHierarchy.get(k);
			if (hierarchy != null)
				ClassHierarchy.put(k, new ClassHierarchy(k.getName(), k, structSizeMaybe, hierarchy));
		});
		ClassHierarchy.forEach((k ,v) -> {
			Data classHierarchy = currentProgram.getListing().getDataAt(v.HierarchyAddress);
			int rttiHierarchyBaseClassCount = Integer.parseInt(classHierarchy.getComponent(2).getValue().toString().substring(2), 16);
			Data rttiBaseDataArray = null;
			try { rttiBaseDataArray = GetOrCreateBaseClassArray(classHierarchy, rttiHierarchyBaseClassCount); } catch (CodeUnitInsertionException ex) { return; }
			//if (v.Namespace.getName(true).startsWith("fw::ArrayBase<void"))
			//	println(v.Namespace.getName(true) + " : " + rttiBaseDataArray.getAddress().toString());
			//println("Base class count for " + v.Namespace.getName(true) + " ( " + classHierarchy.getAddress().toString() + " ), count " + rttiHierarchyBaseClassCount);
			for (int i = 1; i < rttiHierarchyBaseClassCount; i++) {
				Data currentBaseClassDesc = null;
				try { currentBaseClassDesc = GetOrCreateBaseClassDescriptor(rttiBaseDataArray.getComponent(i)); } catch (CodeUnitInsertionException ex) { return; }
				// get offset
				Data PMD = currentBaseClassDesc.getComponent(2);
				int mDisp = Integer.parseInt(PMD.getComponent(0).getValue().toString().substring(2), 16);
				// get namespace
				Namespace baseClassNs = GetTypeDescriptor(currentBaseClassDesc);
				ClassHierarchy BaseClass = ClassHierarchy.get(baseClassNs);
				if (BaseClass == null) continue;
				//if (v.Namespace.getName(true).startsWith("fw::ArrayBase<void"))
				//	println(i + " : " + baseClassNs.getName(true));
				// add to hierarchy
				var BaseClassForOffset = v.BaseClasses.get(mDisp);
				if (BaseClassForOffset == null) {
					v.BaseClasses.put(mDisp, new LinkedList<>());
					BaseClassForOffset = v.BaseClasses.get(mDisp);
				}
				BaseClassForOffset.add(BaseClass);
			}
		});
	}
	private void CreateDataStructures() {
		ClassHierarchy.forEach((k, v) -> {
			// Add base classes to struct type
			if (v.bIsNewStructType) {
				v.BaseClasses.forEach((offset, base) -> {
					// we only need to get the first to set that as the super class
					//println("Base class for " + v.Namespace.getName(true) + " : size " + v.StructSize + " at offset " + offset);
					//println("Base class: " + base.getFirst().Namespace.getName(true) + " size " + base.getFirst().StructSize + " at offset " + offset);
					//println("For class " + v.Namespace.getName(true) + " : first base class at offset " + offset + " is " + base.getFirst().Namespace.getName(true));
					int oldStructSize = v.StructSize; 
					if (offset + base.getFirst().StructSize > oldStructSize) {
						v.StructType.growStructure(offset + base.getFirst().StructSize - oldStructSize); // grow struct by the difference
						v.StructSize = v.StructType.getLength();
						println("WARNING: Resizing class " + v.Namespace.getName(true) + " from " + oldStructSize + " to " + v.StructSize);
					}
					v.StructType.replaceAtOffset(offset, base.getFirst().StructType, base.getFirst().StructSize, "_super" + offset, null);
					//v.StructType.add(base.getFirst().StructType, offset);
				});
			}
		});
		ClassHierarchy.forEach((k, v) -> {
			//println("Create data structure for " + v.Namespace.getName(true));
			if (v.bIsNewStructType) ProgramDTM.addDataType(v.StructType, null);
		});
	}
	
	private void FindFuncImplNoAlloc(HighFunction hf) {
		var pcodeOps = hf.getPcodeOps();
		while (pcodeOps.hasNext()) {
			var currPcodeOp = pcodeOps.next();
			var varnodes = currPcodeOp.getInputs();
			println(currPcodeOp.toString());
		}
	}

	@Override
	protected void run() throws Exception {
		Initialize();
		GetStructSizes();
		BuildClassHierarchy();
		CreateDataStructures();
	}
}
