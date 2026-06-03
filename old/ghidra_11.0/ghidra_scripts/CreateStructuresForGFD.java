//
//@author Rirurin
//@category Persona Modding
//@keybinding
//@menupath
//@toolbar

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.Stack;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
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
import ghidra.util.bytesearch.GenericByteSequencePattern;
import ghidra.util.bytesearch.GenericMatchAction;
import ghidra.util.bytesearch.Match;
import ghidra.util.bytesearch.MemoryBytePatternSearcher;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class CreateStructuresForGFD extends GhidraScript {
	private Memory GMemory;
	private DataTypeManager BuiltinDTM;
	private DataTypeManager ProgramDTM;
	private DataTypeManager WindowsDTM;
	private DTMStructureFactory StructFactory;
	
	private GameType Game;
	
	public enum GameType {
		UNKNOWN,
		PERSONA5ROYAL,
		METAPHOR
	}
	
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
	
	public class SignatureScanner {
		public List<SignatureScanPattern> Patterns;
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
	
	// ------------------------------------------------------------------
	// COMMON TYPES
	// ------------------------------------------------------------------
	
	public class Vector2 extends DTMStructure {
		@Override public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("float"), 0, "x", null);
			_Struct.replaceAtOffset(0x4, GetDataType("float"), 0, "y", null);
		}
		@Override public String GetDataTypeName() { return "gfdCommonVec2"; }
		@Override public int GetDataTypeSize() { return 0x8; } 
		@Override public String GetDataTypePath() { return "/gfd/platform_math"; }
	}
	public class CommonVector3 extends DTMStructure {
		@Override public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("float"), 0, "x", null);
			_Struct.replaceAtOffset(0x4, GetDataType("float"), 0, "y", null);
			_Struct.replaceAtOffset(0x8, GetDataType("float"), 0, "z", null);
		}
		@Override public String GetDataTypeName() { return "gfdCommonVec3"; }
		@Override public int GetDataTypeSize() { return 0xc; } 
		@Override public String GetDataTypePath() { return "/gfd/platform_math"; }
	}
	public class CommonVector4 extends DTMStructure {
		@Override public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("float"), 0, "x", null);
			_Struct.replaceAtOffset(0x4, GetDataType("float"), 0, "y", null);
			_Struct.replaceAtOffset(0x8, GetDataType("float"), 0, "z", null);
			_Struct.replaceAtOffset(0xc, GetDataType("float"), 0, "w", null);
		}
		@Override public String GetDataTypeName() { return "gfdCommonVec4"; }
		@Override public int GetDataTypeSize() { return 0x10; } 
		@Override public String GetDataTypePath() { return "/gfd/platform_math"; }
	}
	public class MathVector3 extends DTMStructure {
		@Override public void MakeStructureFields(Structure _Struct) {
			_Struct.setExplicitMinimumAlignment(8);
			_Struct.replaceAtOffset(0x0, GetDataType("float"), 0, "x", null);
			_Struct.replaceAtOffset(0x4, GetDataType("float"), 0, "y", null);
			_Struct.replaceAtOffset(0x8, GetDataType("float"), 0, "z", null);
		}
		@Override public String GetDataTypeName() { return "VmathVector3"; }
		@Override public int GetDataTypeSize() { return 0x10; } 
		@Override public String GetDataTypePath() { return "/gfd/platform_math"; }
	}
	public class MathVector4 extends DTMStructure {
		@Override public void MakeStructureFields(Structure _Struct) {
			_Struct.setExplicitMinimumAlignment(8);
			_Struct.replaceAtOffset(0x0, GetDataType("float"), 0, "x", null);
			_Struct.replaceAtOffset(0x4, GetDataType("float"), 0, "y", null);
			_Struct.replaceAtOffset(0x8, GetDataType("float"), 0, "z", null);
			_Struct.replaceAtOffset(0xc, GetDataType("float"), 0, "w", null);
		}
		@Override public String GetDataTypeName() { return "VmathVector4"; }
		@Override public int GetDataTypeSize() { return 0x10; } 
		@Override public String GetDataTypePath() { return "/gfd/platform_math"; }
	}
	public class Quaternion extends DTMStructure {
		@Override public void MakeStructureFields(Structure _Struct) {
			_Struct.setExplicitMinimumAlignment(8);
			_Struct.replaceAtOffset(0x0, GetDataType("float"), 0, "x", null);
			_Struct.replaceAtOffset(0x4, GetDataType("float"), 0, "y", null);
			_Struct.replaceAtOffset(0x8, GetDataType("float"), 0, "z", null);
			_Struct.replaceAtOffset(0xc, GetDataType("float"), 0, "w", null);
		}
		@Override public String GetDataTypeName() { return "gfdQuat"; }
		@Override public int GetDataTypeSize() { return 0x10; } 
		@Override public String GetDataTypePath() { return "/gfd/platform_math"; }
	}
	public class MathMatrix3 extends DTMStructure {
		@Override public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("/gfd/platform_math", "VmathVector4"), 0, "r0", null);
			_Struct.replaceAtOffset(0x10, GetDataType("/gfd/platform_math", "VmathVector4"), 0, "r1", null);
			_Struct.replaceAtOffset(0x20, GetDataType("/gfd/platform_math", "VmathVector4"), 0, "r2", null);
		}
		@Override public String GetDataTypeName() { return "VmathMatrix3"; }
		@Override public int GetDataTypeSize() { return 0x30; } 
		@Override public String GetDataTypePath() { return "/gfd/platform_math"; }
	}
	public class MathMatrix4 extends DTMStructure {
		@Override public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("/gfd/platform_math", "VmathVector4"), 0, "r0", null);
			_Struct.replaceAtOffset(0x10, GetDataType("/gfd/platform_math", "VmathVector4"), 0, "r1", null);
			_Struct.replaceAtOffset(0x20, GetDataType("/gfd/platform_math", "VmathVector4"), 0, "r2", null);
			_Struct.replaceAtOffset(0x30, GetDataType("/gfd/platform_math", "VmathVector4"), 0, "r3", null);
		}
		@Override public String GetDataTypeName() { return "VmathMatrix4"; }
		@Override public int GetDataTypeSize() { return 0x40; } 
		@Override public String GetDataTypePath() { return "/gfd/platform_math"; }
	}
	public class ByteColorRGB extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("byte"), 0, "r", null);
			_Struct.replaceAtOffset(0x1, GetDataType("byte"), 0, "g", null);
			_Struct.replaceAtOffset(0x2, GetDataType("byte"), 0, "b", null);
		}
		@Override public String GetDataTypeName() { return "gfdRGB"; }
		@Override public int GetDataTypeSize() { return 0x3; } 
		@Override public String GetDataTypePath() { return "/gfd/types"; }
	}
	public class ByteColorRGBA extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("byte"), 0, "r", null);
			_Struct.replaceAtOffset(0x1, GetDataType("byte"), 0, "g", null);
			_Struct.replaceAtOffset(0x2, GetDataType("byte"), 0, "b", null);
			_Struct.replaceAtOffset(0x3, GetDataType("byte"), 0, "a", null);
		}
		@Override public String GetDataTypeName() { return "gfdRGBA"; }
		@Override public int GetDataTypeSize() { return 0x4; } 
		@Override public String GetDataTypePath() { return "/gfd/types"; }
	}
	public class FloatColorRGB extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("float"), 0, "r", null);
			_Struct.replaceAtOffset(0x4, GetDataType("float"), 0, "g", null);
			_Struct.replaceAtOffset(0x8, GetDataType("float"), 0, "b", null);
		}
		@Override public String GetDataTypeName() { return "gfdRGBFloat"; }
		@Override public int GetDataTypeSize() { return 0xc; } 
		@Override public String GetDataTypePath() { return "/gfd/types"; }
	}
	public class FloatColorRGBA extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("float"), 0, "r", null);
			_Struct.replaceAtOffset(0x4, GetDataType("float"), 0, "g", null);
			_Struct.replaceAtOffset(0x8, GetDataType("float"), 0, "b", null);
			_Struct.replaceAtOffset(0xc, GetDataType("float"), 0, "a", null);
		}
		@Override public String GetDataTypeName() { return "gfdRGBAFloat"; }
		@Override public int GetDataTypeSize() { return 0x10; } 
		@Override public String GetDataTypePath() { return "/gfd/types"; }
	}
	public class GfdName extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("int"), 0, "flags", null);
			_Struct.replaceAtOffset(0x8, GetDataType("char*"), 0, "string", null);
			_Struct.replaceAtOffset(0x10, GetDataType("int"), 0, "length", null);
			_Struct.replaceAtOffset(0x14, GetDataType("int"), 0, "hash", null);
		}
		@Override public String GetDataTypeName() { return "gfdName"; }
		@Override public int GetDataTypeSize() { return 0x18; } 
		@Override public String GetDataTypePath() { return "/gfd/types"; }
	}
	
	public class GfdBoundingBox extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("/gfd/platform_math", "gfdCommonVec3"), 0, "min", null);
			_Struct.replaceAtOffset(0xc, GetDataType("/gfd/platform_math", "gfdCommonVec3"), 0, "max", null);
		}
		@Override public String GetDataTypeName() { return "gfdBoundingBox"; }
		@Override public int GetDataTypeSize() { return 0x18; } 
		@Override public String GetDataTypePath() { return "/gfd/types"; }
	}
	public class GfdBoundingSphere extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("/gfd/platform_math", "gfdCommonVec3"), 0, "center", null);
			_Struct.replaceAtOffset(0xc, GetDataType("float"), 0, "radius", null);
		}
		@Override public String GetDataTypeName() { return "gfdBoundingSphere"; }
		@Override public int GetDataTypeSize() { return 0x10; } 
		@Override public String GetDataTypePath() { return "/gfd/types"; }
	}
	
	// ------------------------------------------------------------------
	// ARRAY TYPES
	// ------------------------------------------------------------------
	
	public class GfdItemArray extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("int"), 0, "capacity", null);
			_Struct.replaceAtOffset(0x4, GetDataType("int"), 0, "type_size", null);
			_Struct.replaceAtOffset(0x8, GetDataType("int"), 0, "count", null);
			_Struct.replaceAtOffset(0x10, GetDataType("void*"), 0, "data", null);
			_Struct.replaceAtOffset(0x20, GetDataType("void*"), 0, "destructor", null);
		}
		@Override public String GetDataTypeName() { return "gfdItemArray"; }
		@Override public int GetDataTypeSize() { return 0x28; } 
		@Override public String GetDataTypePath() { return "/gfd/array"; }
	}
	
	// ------------------------------------------------------------------
	// MATERIAL TYPES
	// ------------------------------------------------------------------
	
	public class GfdMaterialDrawMethod extends DTMEnum {
		@Override
		public void MakeEnumFields(ghidra.program.model.data.Enum _Enum) {
			_Enum.add("Opaque", 0);
			_Enum.add("Translucent", 1);
			_Enum.add("BlackAsAlpha", 2);
		}
		@Override public String GetDataTypeName() { return "gfdMaterialDrawMethod"; }
		@Override public int GetDataTypeSize() { return 0x1; } 
		@Override public String GetDataTypePath() { return "/gfd/material"; }
	}
	
	public class GfdMaterialFlags extends DTMEnum {
		@Override
		public void MakeEnumFields(ghidra.program.model.data.Enum _Enum) {
			_Enum.add("Mat2HasAmbientColor", 1 << 0);
			_Enum.add("Mat2HasDiffuseColor", 1 << 1);
			_Enum.add("Mat2HasEmissiveColor", 1 << 2);
			_Enum.add("HasVertexColors", 1 << 4);
			_Enum.add("Mat2HasOutline", 1 << 6);
			_Enum.add("EnableLight", 1 << 7);
			_Enum.add("Mat2HasSpecularColor", 1 << 8);
			_Enum.add("Mat2HasReflectivity", 1 << 9);
			_Enum.add("EnableLight2", 1 << 11);
			_Enum.add("PurpleWireframe", 1 << 12);
			_Enum.add("AlphaTestEnabled", 1 << 13);
			_Enum.add("ReceiveShadow", 1 << 14);
			_Enum.add("CastShadow", 1 << 15);
			_Enum.add("HasAttributes", 1 << 16);
			_Enum.add("HasOutline", 1 << 17);
			_Enum.add("DisableBloom", 1 << 19);
			_Enum.add("HasDiffuseMap", 1 << 20);
			_Enum.add("HasNormalMap", 1 << 21);
			_Enum.add("HasSpecularMap", 1 << 22);
			_Enum.add("HasReflectionMap", 1 << 23);
			_Enum.add("HasHighlightMap", 1 << 24);
			_Enum.add("HasGlowMap", 1 << 25);
			_Enum.add("HasNightMap", 1 << 26);
			_Enum.add("HasDetailMap", 1 << 27);
			_Enum.add("HasShadowMap", 1 << 28);
			_Enum.add("UVTransform", 1 << 31);
		}
		@Override public String GetDataTypeName() { return "gfdMaterialFlags"; }
		@Override public int GetDataTypeSize() { return 0x4; } 
		@Override public String GetDataTypePath() { return "/gfd/material"; }
	}
	
	public class GfdMaterialFlags2 extends DTMEnum {
		@Override
		public void MakeEnumFields(ghidra.program.model.data.Enum _Enum) {
			_Enum.add("EnableBloom", 1 << 0);
			_Enum.add("LightMapModulateMode", 1 << 1);
			_Enum.add("LightMapModulate2", 1 << 2);
			_Enum.add("DisableCharacterOutline", 1 << 5);
			_Enum.add("FogDisable", 1 << 10);
			_Enum.add("ShadowDisable", 1 << 11);
		}
		@Override public String GetDataTypeName() { return "gfdMaterialFlags2"; }
		@Override public int GetDataTypeSize() { return 0x2; } 
		@Override public String GetDataTypePath() { return "/gfd/material"; }
	}
	
	// WARNING: Unverified, copied from Persona 3 Reload
	public class GfdGuiBlendFactor extends DTMEnum {
		@Override
		public void MakeEnumFields(ghidra.program.model.data.Enum _Enum) {
			_Enum.add("Zero", 0);
			_Enum.add("One", 1);
			_Enum.add("SourceColor", 2);
			_Enum.add("InverseSourceColor", 3);
			_Enum.add("SourceAlpha", 4);
			_Enum.add("InverseSourceAlpha", 5);
			_Enum.add("DestAlpha", 6);
			_Enum.add("InverseDestAlpha", 7);
			_Enum.add("DestColor", 8);
			_Enum.add("InverseDestColor", 9);
			_Enum.add("ConstantBlendFactor", 10);
			_Enum.add("InverseConstantBlendFactor", 11);
			_Enum.add("Source1Color", 12);
			_Enum.add("InverseSource1Color", 13);
			_Enum.add("Source1Alpha", 14);
			_Enum.add("InverseSource1Alpha", 15);
		}
		@Override public String GetDataTypeName() { return "gfdGuiBlendFactor"; }
		@Override public int GetDataTypeSize() { return 0x1; } 
		@Override public String GetDataTypePath() { return "/gfd/material"; }
	}
	
	public class GfdMaterialAttributeType extends DTMEnum {
		@Override
		public void MakeEnumFields(ghidra.program.model.data.Enum _Enum) {
			if (Game == Game.PERSONA5ROYAL) {
				_Enum.add("ToonShading", 0);
				_Enum.add("InnerGlow", 1);
				_Enum.add("Outline", 2);
				_Enum.add("Water", 3);
				_Enum.add("ScrollingTexture", 4);
				_Enum.add("AlphaCrunch", 8);
			} else if (Game == Game.METAPHOR) {
				
			}	
		}
		@Override public String GetDataTypeName() { return "gfdMaterialAttributeType"; }
		@Override public int GetDataTypeSize() { return 0x2; } 
		@Override public String GetDataTypePath() { return "/gfd/material"; }
	}
	
	public class GfdMaterialBlend extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("/gfd/material", "gfdMaterialDrawMethod"), 0, "drawMethod", null);
			_Struct.replaceAtOffset(0x1, GetDataType("/gfd/material", "gfdGuiBlendFactor"), 0, "srcColor", null);
			_Struct.replaceAtOffset(0x2, GetDataType("/gfd/material", "gfdGuiBlendFactor"), 0, "dstColor", null);
			_Struct.replaceAtOffset(0x3, GetDataType("/gfd/material", "gfdGuiBlendFactor"), 0, "srcAlpha", null);
			_Struct.replaceAtOffset(0x4, GetDataType("/gfd/material", "gfdGuiBlendFactor"), 0, "dstAlpha", null);
			_Struct.replaceAtOffset(0x5, GetDataType("byte"), 0, "multiple", null);
			_Struct.replaceAtOffset(0x6, GetDataType("/gfd/material", "gfdMaterialDrawMethod"), 0, "control", null);
		}
		@Override public String GetDataTypeName() { return "gfdMaterialBlend"; }
		@Override public int GetDataTypeSize() { return 0x8; } 
		@Override public String GetDataTypePath() { return "/gfd/material"; }
	}
	
	public class GfdTexture extends DTMStructure {
		
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("int"), 0, "flags", null);
			_Struct.replaceAtOffset(0x8, GetDataType("void*"), 0, "handle", null);
			_Struct.replaceAtOffset(0x10, GetDataType("int"), 0, "ref", null);
			_Struct.replaceAtOffset(0x18, GetDataType("/gfd/types", "gfdName"), 0, "name", null);
			_Struct.replaceAtOffset(0x30, GetDataType("byte"), 0, "min", null);
			_Struct.replaceAtOffset(0x31, GetDataType("byte"), 0, "mag", null);
			_Struct.replaceAtOffset(0x32, GetDataType("byte"), 0, "wraps", null);
			_Struct.replaceAtOffset(0x33, GetDataType("byte"), 0, "wrapt", null);
			_Struct.replaceAtOffset(0x38, GetDataType("/gfd/texture", "gfdTexture*"), 0, "prev", null);
			_Struct.replaceAtOffset(0x40, GetDataType("/gfd/texture", "gfdTexture*"), 0, "next", null);
			_Struct.replaceAtOffset(0x48, GetDataType("int"), 0, "flags", null);
		}
		
		@Override public String GetDataTypeName() { return "gfdTexture"; }
		@Override public int GetDataTypeSize() { return 0x50; } 
		@Override public String GetDataTypePath() { return "/gfd/texture"; }
	}
	
	public class GfdTextureMap extends DTMStructure {
		
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("/gfd/platform_math", "VmathMatrix4"), 0, "tm", null);
			_Struct.replaceAtOffset(0x40, GetDataType("/gfd/texture", "gfdTexture*"), 0, "texture", null);
			_Struct.replaceAtOffset(0x48, GetDataType("int"), 0, "flags", null);
			_Struct.replaceAtOffset(0x4c, GetDataType("byte"), 0, "min", null);
			_Struct.replaceAtOffset(0x4d, GetDataType("byte"), 0, "mag", null);
			_Struct.replaceAtOffset(0x4e, GetDataType("byte"), 0, "wraps", null);
			_Struct.replaceAtOffset(0x4f, GetDataType("byte"), 0, "wrapt", null);
		}
		
		@Override public String GetDataTypeName() { return "gfdMaterialTexture"; }
		@Override public int GetDataTypeSize() { return 0x50; } 
		@Override public String GetDataTypePath() { return "/gfd/material"; }
	}
	
	public class GfdMaterial extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("/gfd/types", "gfdRGBAFloat"), 0, "ambient", null);
			_Struct.replaceAtOffset(0x10, GetDataType("/gfd/types", "gfdRGBAFloat"), 0, "diffuse", null);
			_Struct.replaceAtOffset(0x20, GetDataType("/gfd/types", "gfdRGBAFloat"), 0, "emissive", null);
			_Struct.replaceAtOffset(0x30, GetDataType("/gfd/types", "gfdRGBAFloat"), 0, "specular", null);
			_Struct.replaceAtOffset(0x40, GetDataType("float"), 0, "reflectivity", null);
			_Struct.replaceAtOffset(0x44, GetDataType("float"), 0, "diffusivity", null);
			_Struct.replaceAtOffset(0x48, GetDataType("/gfd/material", "gfdMaterialBlend"), 0, "blend", null);
			_Struct.replaceAtOffset(0x50, GetDataType("short"), 0, "disableBackfaceCulling", null);
			_Struct.replaceAtOffset(0x52, GetDataType("short"), 0, "isMaterialDirty", null);
			_Struct.replaceAtOffset(0x54, GetDataType("/gfd/material", "gfdMaterialFlags"), 0, "flags", null);
			_Struct.replaceAtOffset(0x58, GetDataType("/gfd/material", "gfdMaterialTexture*"), 0, "textures", null);
			_Struct.replaceAtOffset(0x98, GetDataType("/gfd/types", "gfdName"), 0, "name", null);
		}
		@Override public String GetDataTypeName() { return "gfdMaterial"; }
		@Override public int GetDataTypeSize() { return 0xf0; } 
		@Override public String GetDataTypePath() { return "/gfd/material"; }
	}
	
	// ------------------------------------------------------------------
	// ANIMATION TYPES
	// ------------------------------------------------------------------
	
	// ------------------------------------------------------------------
	// NODE TYPES
	// ------------------------------------------------------------------
	public class GfdObject extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("int"), 0, "id", null);
			_Struct.replaceAtOffset(0x8, GetDataType("/gfd/object", "gfdNode*"), 0, "parent", null);
			_Struct.replaceAtOffset(0x10, GetDataType("/gfd/object", "gfdObject*"), 0, "prev", null);
			_Struct.replaceAtOffset(0x18, GetDataType("/gfd/object", "gfdObject*"), 0, "next", null);
		}
		@Override public String GetDataTypeName() { return "gfdObject"; }
		@Override public int GetDataTypeSize() { return 0x20; } 
		@Override public String GetDataTypePath() { return "/gfd/object"; }
	}
	
	public class GfdAnimInterpolator extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			
		}
		@Override public String GetDataTypeName() { return "gfdAnimInterpolator"; }
		@Override public int GetDataTypeSize() { return 0x480; } 
		@Override public String GetDataTypePath() { return "/gfd/object/mesh"; }
	}
	public class GfdAnimController extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			
		}
		@Override public String GetDataTypeName() { return "gfdAnimController"; }
		@Override public int GetDataTypeSize() { return 0x2e0; } 
		@Override public String GetDataTypePath() { return "/gfd/anim"; }
	}
	public class GfdAnimEffector extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			
		}
		@Override public String GetDataTypeName() { return "gfdAnimEffector"; }
		@Override public int GetDataTypeSize() { return 0x68; } 
		@Override public String GetDataTypePath() { return "/gfd/anim"; }
	}
	public class GfdPhysicsSector extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			
		}
		@Override public String GetDataTypeName() { return "gfdPhysicsSector"; }
		@Override public int GetDataTypeSize() { return 0xd0; } 
		@Override public String GetDataTypePath() { return "/gfd/object/physics"; }
	}
	public class GfdCullLocalOBB extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			
		}
		@Override public String GetDataTypeName() { return "gfdMesh"; }
		@Override public int GetDataTypeSize() { return 0x80; } 
		@Override public String GetDataTypePath() { return "/gfd/object/mesh"; }
	}
	
	public class GfdMesh extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("/gfd/object", "gfdObject"), 0, "super", null);
			_Struct.replaceAtOffset(0x20, GetDataType("int"), 0, "flags", null);
			_Struct.replaceAtOffset(0x24, GetDataType("int"), 0, null, null);
			_Struct.replaceAtOffset(0x28, GetDataType("/gfd/object", "gfdNode*"), 0, "hierarchy", null);
			_Struct.replaceAtOffset(0x30, GetDataType("/gfd/array", "gfdItemArray*"), 0, "nodeArray", null);
			_Struct.replaceAtOffset(0x38, GetDataType("/gfd/array", "gfdItemArray*"), 0, "geometryArray", null);
			_Struct.replaceAtOffset(0x40, GetDataType("/gfd/array", "gfdItemArray*"), 0, "materialArray", null);
			_Struct.replaceAtOffset(0x48, GetDataType("/gfd/array", "gfdItemArray*"), 0, "morphArray", null);
			_Struct.replaceAtOffset(0x50, GetDataType("/gfd/array", "gfdItemArray*"), 0, "cameraArray", null);
			_Struct.replaceAtOffset(0x58, GetDataType("/gfd/array", "gfdItemArray*"), 0, "lightArray", null);
			_Struct.replaceAtOffset(0x60, GetDataType("/gfd/array", "gfdItemArray*"), 0, "effectArray", null);
		}
		@Override public String GetDataTypeName() { return "gfdMesh"; }
		@Override public int GetDataTypeSize() { return 0x128; } 
		@Override public String GetDataTypePath() { return "/gfd/object"; }
	}
	public class GfdNode extends DTMStructure {
		@Override
		public void MakeStructureFields(Structure _Struct) {
			_Struct.replaceAtOffset(0x0, GetDataType("/gfd/object", "gfdObject"), 0, "super", null);
		}
		@Override public String GetDataTypeName() { return "gfdNode"; }
		@Override public int GetDataTypeSize() { return 0x128; } 
		@Override public String GetDataTypePath() { return "/gfd/object"; }
	}
	
	// ------------------------------------------------------------------
	// EPL TYPES
	// ------------------------------------------------------------------
	
	// ------------------------------------------------------------------
	// Find node and EPL attachment vtables and label them
	// ------------------------------------------------------------------
	
	// ------------------------------------------------------------------
	// DRAWING PRIMITIVE TYPES
	// ------------------------------------------------------------------
	
	// ------------------------------------------------------------------
	// Document all the basic drawing functions
	// ------------------------------------------------------------------
	
	private void Initialize() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException {
		GMemory = currentProgram.getMemory();
		BuiltinDTM = getDataTypeManagerByName("BuiltInTypes");
		ProgramDTM = currentProgram.getDataTypeManager();
		WindowsDTM = getDataTypeManagerByName("windows");
		if (currentProgram.getName().equals("P5R.exe")) {
			Game = GameType.PERSONA5ROYAL;
		} else if (currentProgram.getName().equals("METAPHOR.exe")) {
			Game = GameType.METAPHOR;
		} else {
			Game = GameType.UNKNOWN;
		}
		// Make data types
		List<DTMDataType> Structs = new ArrayList<>();
		// Retrieve all structs and enums using reflection
		for (var Innerclass : getClass().getClasses()) {
			//Innerclass.getSuperclass()
			if (
				DTMDataType.class.isAssignableFrom(Innerclass) &&
				!Innerclass.equals(DTMDataType.class) &&
				!Innerclass.isInterface() &&
				!Modifier.isAbstract(Innerclass.getModifiers())
			) {
				Structs.add((DTMDataType)Innerclass.getConstructor(CreateStructuresForGFD.class).newInstance(this));
			}
		}
		StructFactory = new DTMStructureFactory(Structs);
	}

	@Override
	protected void run() throws Exception {
		Initialize();
	}
}
