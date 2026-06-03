//
//@author Rirurin
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.Stack;
import java.util.function.BiConsumer;
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
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.bytesearch.GenericByteSequencePattern;
import ghidra.util.bytesearch.GenericMatchAction;
import ghidra.util.bytesearch.Match;
import ghidra.util.bytesearch.MemoryBytePatternSearcher;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class D3D11CreateByteArrayFromDXBC extends GhidraScript {
	
	private Memory GMemory;
	private DataTypeManager BuiltinDTM;
	private DataTypeManager ProgramDTM;
	private DataTypeManager WindowsDTM;
	private DTMStructureFactory StructFactory;
	
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
		
		public boolean IsPointerInRange(Address Address) {
			MemoryBlock[] Blocks = GMemory.getBlocks();
			for (var Block : Blocks) {
				if (Block.contains(Address)) return true;
			}
			return false;
		}
		
		private Data GetOrCreateData(Address addr, DataType type, int structSize) throws CodeUnitInsertionException {
			Data dataOut = currentProgram.getListing().getDataAt(addr);
			if (dataOut == null) {
				// in the middle of some other data, clear stuff out
				currentProgram.getListing().clearCodeUnits(addr, addr.add(structSize), false);
				dataOut = currentProgram.getListing().getDataAt(addr);
			}
			currentProgram.getListing().clearCodeUnits(addr, addr.add(structSize), false);
			dataOut = currentProgram.getListing().createData(addr, type);
			return dataOut;
		}
		
		private Function RenameFunctionIfReal(String Name, Data data) {
			Address addr = toAddr(data.getValue().toString());
			if (!IsPointerInRange(addr)) {
				return null;
			}
			Function newFn = GetOrMakeFunction(addr, Name, null);
			return newFn;
		}
		private String GetFormattedName(String str) {
			return (char)(str.charAt(0) & 0xdf) + str.substring(1);
		}

	@Override
	protected void run() throws Exception {
		GMemory = currentProgram.getMemory();
		BuiltinDTM = getDataTypeManagerByName("BuiltInTypes");
		ProgramDTM = currentProgram.getDataTypeManager();
		WindowsDTM = getDataTypeManagerByName("windows");
		MemoryBlock[] MemoryBlocks = currentProgram.getMemory().getBlocks();
		int shaderCount = 0;
		// DXBC
		/*
		for (var MemoryBlock : MemoryBlocks) {
			Address[] builtinShaders = findBytes(new AddressSet(MemoryBlock.getAddressRange()), "\\x44\\x58\\x42\\x43", 25000, 8); // DXBC
			for (var builtinShader : builtinShaders) {
				Cursor c = new Cursor(builtinShader.add(0x18));
				var shaderSize = c.DerefInt();
				println("shader size at " + builtinShader.toString() + " (" + shaderCount + ") : " + shaderSize);
				currentProgram.getListing().clearCodeUnits(builtinShader, builtinShader.add(shaderSize - 1), false);
				currentProgram.getListing().createData(builtinShader, new ArrayDataType(new ByteDataType(), shaderSize, 0));
				currentProgram.getSymbolTable().createLabel(builtinShader, "builtinShader" + shaderCount, SourceType.ANALYSIS);
				shaderCount++;
			}
		}
		*/
		// 0HLG
		for (var MemoryBlock : MemoryBlocks) {
			Address[] builtinShaders = findBytes(new AddressSet(MemoryBlock.getAddressRange()), "\\x30\\x48\\x4c\\x47", 25000, 8); // 0HLG
			for (var builtinShader : builtinShaders) {
				Cursor c = new Cursor(builtinShader.add(0x10));
				var shaderSize = c.DerefInt();
				println("HLG size at " + builtinShader.toString() + " (" + shaderCount + ") : " + shaderSize);
				currentProgram.getListing().clearCodeUnits(builtinShader, builtinShader.add(shaderSize - 1), false);
				currentProgram.getListing().createData(builtinShader, new ArrayDataType(new ByteDataType(), shaderSize, 0));
				currentProgram.getSymbolTable().createLabel(builtinShader, "builtinHLG" + shaderCount, SourceType.ANALYSIS);
				shaderCount++;
			}
		}
	}
}
