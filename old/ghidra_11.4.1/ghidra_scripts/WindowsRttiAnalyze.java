//RTTI analyzer that works for me lol
//@author Rirurin
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import docking.options.OptionsService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.Demangler;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.DataConverter;
import ghidra.util.bytesearch.GenericByteSequencePattern;
import ghidra.util.bytesearch.GenericMatchAction;
import ghidra.util.bytesearch.Match;
import ghidra.util.bytesearch.MemoryBytePatternSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class WindowsRttiAnalyze extends GhidraScript {
	
	private CategoryPath RootPath = new CategoryPath("/");
	private Demangler MSVCDemangler = new MicrosoftDemangler();
	private List<RttiTypeDescriptorBuilder> rtti0Addresses = new ArrayList<>();
	private HashMap<String, DataType> RttiTypes = new HashMap<>();
	private List<GeneratedClass> Classes = new ArrayList<GeneratedClass>();
	private HashMap<Address, GeneratedClass> ClassesByTypeDescriptor = new HashMap<>();
	
	private DecompInterface Decompiler;
	private Address FuncPtrForOperatorDelete = null;
	
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
		if (fullName.length() > 2000) {
			return null;
		}
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
	
	private Symbol MakeSymbol(Address addr, String name) throws InvalidInputException {
		var TypeSyms = currentProgram.getSymbolTable().getSymbols(addr);
		Symbol SymOut = null;
		for (int i = 0; i < TypeSyms.length; i++) {
			if (TypeSyms[i].getName().equals(name)) {
				SymOut = TypeSyms[i];
				break;
			}
		}
		if (SymOut == null) {
			SymOut = currentProgram.getSymbolTable().createLabel(addr, name, SourceType.ANALYSIS);
		}
		return SymOut;
	}
	
	private Data MakeGetRttiData(Address addr, String typeName, int structSize) throws CodeUnitInsertionException {
		println(addr.toString() + " : " + typeName);
		Data dataOut = currentProgram.getListing().getDataAt(addr);
		if (dataOut == null) {
			// in the middle of some other data, clear stuff out
			currentProgram.getListing().clearCodeUnits(addr, addr.add(structSize), false);
			dataOut = currentProgram.getListing().getDataAt(addr);
		}
		if (!dataOut.getDataType().getName().equals(RttiTypes.get(typeName).getName())) {
			currentProgram.getListing().clearCodeUnits(addr, addr.add(structSize), false);
			dataOut = currentProgram.getListing().createData(addr, RttiTypes.get(typeName));
		}
		return dataOut;
	}
	
	private class RttiTypeDescriptorBuilder {
		public Address Address;
		public Boolean bDataAlreadyExists;
		public RttiTypeDescriptorBuilder(Address _Address, Boolean _bDataAlreadyExists) {
			Address = _Address;
			bDataAlreadyExists = _bDataAlreadyExists;
		}
	}
	private class GeneratedClass {
		// RTTI
		public Address TypeDescriptor;
		public Address CompleteObjectLocator;
		// Class structure
		public Address Vtable;
		//public String FullName;
		public String Name;
		public Namespace SymbolClass;
		public List<GeneratedClass> BaseClasses;
		public int ReportedSize;
		public int ReportedVtableCount;
		
		// If CompleteObjectLocator is null, fair to assume that it's a base class
		// https://blog.quarkslab.com/visual-c-rtti-inspection.html
		
		public Boolean CanCheckClassHierarchy() {
			return TypeDescriptor != null && CompleteObjectLocator != null; 
		}
		
		public GeneratedClass(String _Name, Namespace _SymbolClass) {
			Name = _Name;
			SymbolClass = _SymbolClass;
		}
		
		private boolean CheckClassIsBase() throws MemoryAccessException {
			/*
			Data ClassHierarchyPointer = currentProgram.getListing().getDataAt(CompleteObjectLocator).getComponent(4);
			Data ClassHierarchy = currentProgram.getListing().getDataAt(currentProgram.getMinAddress().add(currentProgram.getMemory().getInt(ClassHierarchyPointer.getAddress())));
			return currentProgram.getMemory().getInt(ClassHierarchy.getComponent(2).getAddress()) < 2;
			*/
			return false;
		}
	}
	
	private MemoryBlock GetMemoryBlockContainingTypeDescriptors() throws MemoryAccessException {
		MemoryBlock rtti0MemBlock = null;
		int rtti0NamesMaybeTotal = 0;
		MemoryBlock[] MemoryBlocks = currentProgram.getMemory().getBlocks();
		// Look for memory map block most likely to contain the type descriptors, since they're all stored
		// at the same part of the executable. We'll set the cutoff at 50.
		for (var MemoryBlock : MemoryBlocks) {
			Address[] rtti0Names = findBytes(new AddressSet(MemoryBlock.getAddressRange()), "\\x2e\\x3f\\x41\\x56", 25000, 8); // .?AV, always alignto(8)
			rtti0NamesMaybeTotal += rtti0Names.length;
			if (rtti0Names.length >= 50) {
				rtti0MemBlock = MemoryBlock;
				for (var rtti0Name : rtti0Names) {
					var rtti0AddrReal = rtti0Name.subtract(0x10);
					var rtti0AddrExistData = currentProgram.getListing().getDataAt(rtti0AddrReal);
					var bRttiTypeDescExists = rtti0AddrExistData.getDataType().toString().equals(RttiTypes.get("TypeDescriptor").getName());
					if (!bRttiTypeDescExists) {
						var rtti0EndOfName = rtti0Name;
						var currByte = 0;
						do {
							currByte = currentProgram.getMemory().getByte(rtti0EndOfName);
							rtti0EndOfName = rtti0EndOfName.add(1);
						} while (currByte != 0);
						currentProgram.getListing().clearCodeUnits(rtti0AddrReal, rtti0EndOfName, false);
					}
					rtti0Addresses.add(new RttiTypeDescriptorBuilder(rtti0AddrReal, bRttiTypeDescExists));
				}
				break;
			}
		}
		return rtti0MemBlock;
	}
	
	private void GetRttiTypes() {
		var builtinDTM = getDataTypeManagerByName("BuiltInTypes");
		// https://www.lukaszlipski.dev/post/rtti-msvc/
		RttiTypes.put("TypeDescriptor", builtinDTM.getDataType(RootPath, "RTTI_0"));
		/*
		 typedef struct TypeDescriptor
		{
		    const void* pVFTable;
		    void*       spare;          
		    char        name[];
		} TypeDescriptor;

		*/
		RttiTypes.put("BaseClassDescriptor", builtinDTM.getDataType(RootPath, "RTTI_1"));
		/*
		typedef const struct _s_RTTIBaseClassDescriptor {
		    int           pTypeDescriptor;
		    unsigned long numContainedBases;
		    PMD           where;
		    unsigned long attributes;
			    BCD_NOTVISIBLE - 0x1 -> set when the current base class is not inherited publicly.
			    BCD_AMBIGUOUS - 0x2 -> current base class is ambiguous in the class hierarchy.
			    BCD_PRIVORPROTBASE - 0x4 -> current base class is inherited privately.
			    BCD_PRIVORPROTINCOMPOBJ - 0x8 -> part of a privately inherited base class hierarchy.
			    BCD_VBOFCONTOBJ - 0x10 -> current base class is virtually inherited.
			    BCD_NONPOLYMORPHIC - 0x20 -> the name suggests that it should be set for a non-polymorphic base class
			    BCD_HASPCHD - 0x40 -> indicates that RTTIClassHierarchyDescriptor is present for current type and pClassDescriptor contains valid offset.
		    int           pClassDescriptor;
		} _RTTIBaseClassDescriptor;

		 */
		RttiTypes.put("BaseClassArray", builtinDTM.getDataType(RootPath, "RTTI_2"));
		/*
		typedef const struct _s_RTTIBaseClassArray {
		    int arrayOfBaseClassDescriptors[];
		} _RTTIBaseClassArray;
		 */
		RttiTypes.put("ClassHierachy", builtinDTM.getDataType(RootPath, "RTTI_3"));
		/*
		 typedef const struct _s_RTTIClassHierarchyDescriptor {
		    unsigned long signature; // always 0
		    unsigned long attributes;
		    	CHD_MULTINH - 0x1 -> set when hierarchy contains multiple inheritance
		    	CHD_VIRTINH - 0x2 -> set when hierarchy contains at least one virtual base
	    		CHD_AMBIGUOUS  - 0x4 -> set when the current type contains an ambiguous base class
		    unsigned long numBaseClasses;
		    int           pBaseClassArray;
		} _RTTIClassHierarchyDescriptor;

		 */
		RttiTypes.put("CompleteObjectLocator", builtinDTM.getDataType(RootPath, "RTTI_4"));
		/*
		 typedef const struct _s_RTTICompleteObjectLocator    
		{
		    unsigned long signature; // COL_SIG_REV1, always 1
		    unsigned long offset;
		    unsigned long cdOffset;
		    int           pTypeDescriptor;
		    int           pClassDescriptor;
		    int           pSelf;
		} _RTTICompleteObjectLocator;
		 */
	}
	
	private void GetTypeDescriptors() throws CodeUnitInsertionException, DemangledException, DuplicateNameException, InvalidInputException, CircularDependencyException {
		for (var rtti0Address : rtti0Addresses) {
			Data TypeDescriptorData;
			if (!rtti0Address.bDataAlreadyExists) {
				TypeDescriptorData = currentProgram.getListing().createData(rtti0Address.Address, RttiTypes.get("TypeDescriptor"));	
			} else {
				TypeDescriptorData = currentProgram.getListing().getDataAt(rtti0Address.Address);
			}
			Data TypeDescriptorName = TypeDescriptorData.getComponent(2);
			String RttiTypeDescMangledName = "??_R0" + TypeDescriptorName.getValue().toString().substring(1) + "@8";
			// Get class name
			String RttiTypeDescDemangledName = MSVCDemangler.demangle(RttiTypeDescMangledName).getDemangledName();
			String TypeName = RttiTypeDescDemangledName.split("class ", 2)[1].split(" `RTTI Type Descriptor'")[0];
			var nameParts = GetNamespaceParts(TypeName);
			Namespace nspace = GetOrMakeNamespace(TypeName);
			if (nspace != null) {
				GeneratedClass NewClass = new GeneratedClass(nameParts.get(nameParts.size() - 1), nspace);
				NewClass.TypeDescriptor = rtti0Address.Address;
				Symbol rttiTypeDescSym = MakeSymbol(rtti0Address.Address, "RTTI_Type_Descriptor");
				rttiTypeDescSym.setNamespace(NewClass.SymbolClass);
				Classes.add(NewClass);
				ClassesByTypeDescriptor.put(NewClass.TypeDescriptor, NewClass);
			}
		}
	}
	
	private void CreateCompleteObjectData(Address addr, GeneratedClass targetClass) {
		try {
			var signature = currentProgram.getMemory().getInt(addr.subtract(0xc));
			var offset = currentProgram.getMemory().getInt(addr.subtract(0x8));
			var classHierarchyPtr = currentProgram.getMemory().getInt(addr.add(4));
			if (signature == 1 && classHierarchyPtr != 0) {
				//println("Found pattern: " + addr.toString());
				targetClass.CompleteObjectLocator = addr.subtract(0xc);
				if (!
						currentProgram.getListing().getDataAt(targetClass.CompleteObjectLocator)
						.getDataType().getName().equals(RttiTypes.get("CompleteObjectLocator").getName())
					) {
					currentProgram.getListing().clearCodeUnits(targetClass.CompleteObjectLocator, targetClass.CompleteObjectLocator.add(0x14), false);
					currentProgram.getListing().createData(targetClass.CompleteObjectLocator, RttiTypes.get("CompleteObjectLocator"));
				}
				try {
					Symbol rrtiCompleteObjSym = MakeSymbol(targetClass.CompleteObjectLocator, "RTTI_Complete_Object_Locator");
					rrtiCompleteObjSym.setNamespace(targetClass.SymbolClass);
				} catch (CircularDependencyException | InvalidInputException | DuplicateNameException e) {
					println("Couldn't add symbol to namespace");
					e.printStackTrace();
				}
				if (offset > 0) {
					println("NOTE: Offset for " + targetClass.Name + " is more than 0 @ " + addr.subtract(0xc));
				}
			}
		} catch (MemoryAccessException | CodeUnitInsertionException e) {
			e.printStackTrace();
		}
	}
	
	private void AddEntriesToCompleteObjectSearcher(MemoryBytePatternSearcher Searcher, int start, int count, java.util.function.BiConsumer<Address, GeneratedClass> onFoundCb) {
		for (int i = start; i < start + count; i++) {
			var index = i;
			GenericMatchAction<Integer> actionOnFindPtr = new GenericMatchAction<>(index) {
				@Override
				public void apply(Program prog, Address addr, Match match) {
					onFoundCb.accept(addr, Classes.get(index));
				}
			};
			var typeDescAsInt = (int)Classes.get(index).TypeDescriptor.subtract(currentProgram.getMinAddress());
			byte[] typeDescAsBytes = DataConverter.getInstance(false).getBytes(typeDescAsInt);
			GenericByteSequencePattern<Integer> findTypeDescPtr = new GenericByteSequencePattern<>(typeDescAsBytes, actionOnFindPtr);
			Searcher.addPattern(findTypeDescPtr);
		}
	}
	
	private void FindCompleteObjectLocatorsPre(List<Integer> TargetBlockIndex) throws CancelledException {
		MemoryBlock[] MemoryBlocks = currentProgram.getMemory().getBlocks();
		AddressSet searchSet = new AddressSet();
		for (MemoryBlock block : MemoryBlocks) {
			searchSet.add(block.getStart(), block.getEnd());
		}
		MemoryBytePatternSearcher CompleteObjSearcherPre = new MemoryBytePatternSearcher("RTTI Complete Obj Searcher Pre");
		AddEntriesToCompleteObjectSearcher(CompleteObjSearcherPre, 0, 1, (Address addr, GeneratedClass gen) -> {
			CreateCompleteObjectData(addr, gen);
			for (int i = 0; i < MemoryBlocks.length; i++) {
				if (MemoryBlocks[i].contains(addr)) {
					TargetBlockIndex.add(i);
					break;
				}
			}
		});
		CompleteObjSearcherPre.search(currentProgram, searchSet, monitor);
	}
	
	private void FindCompleteObjectLocators() throws CancelledException {
		// Sacrifice the first type descriptor to search across the entire program before we can find
		// the memory block where it's referenced. Denuvo likes to rename memory blocks to screw up
		// reverse engineering programs, so we gotta do this.
		List<Integer> TargetBlocks = new ArrayList<>();
		FindCompleteObjectLocatorsPre(TargetBlocks);
		if (TargetBlocks.size() == 0) {
			throw new IllegalArgumentException("Could not find target block");
		}
		MemoryBlock TargetBlock = currentProgram.getMemory().getBlocks()[TargetBlocks.get(0)];
		println("Using target block " + TargetBlock.getName() + ", range " + TargetBlock.getAddressRange().toString());
		if (Classes.size() < 2) {
			return;
		}
		// Now the rest of the type descriptors can be searched quicker
		MemoryBytePatternSearcher CompleteObjSearcher = new MemoryBytePatternSearcher("RTTI Complete Obj Searcher");
		AddEntriesToCompleteObjectSearcher(CompleteObjSearcher, 1, Classes.size() - 1, (Address addr, GeneratedClass gen) -> CreateCompleteObjectData(addr, gen));
		
		AddressSet searchSet = new AddressSet();
		searchSet.add(TargetBlock.getAddressRange());
		CompleteObjSearcher.search(currentProgram, searchSet, monitor);
		
		for (var gClass : Classes) {
			if (gClass.CompleteObjectLocator == null) {
				//println("WARNING: CompleteObjectLocator for class " + gClass.Name + " is null!");
			}
		}
	}
	
	private void BuildClassHierarchy() throws MemoryAccessException, CodeUnitInsertionException, InvalidInputException, CircularDependencyException, DuplicateNameException {
		for (var gClass : Classes) {
			// Make and register class hierarchy objects
			if (gClass.CanCheckClassHierarchy()) {
				int Offset = currentProgram.getMemory().getInt(gClass.CompleteObjectLocator.add(4));
				if (Offset > 0) {
					continue;
				} // Only do this if offset > 0, it'll point to the same class hierarchy anyway
				Data rttiCompleteObj = currentProgram.getListing().getDataAt(gClass.CompleteObjectLocator);
				int ClassHierarchyPtr = currentProgram.getMemory().getInt(gClass.CompleteObjectLocator.add(0x10));
				Data ClassHierarchy = MakeGetRttiData(currentProgram.getMinAddress().add(ClassHierarchyPtr), "ClassHierachy", 0x10);
				Symbol ClassHierarchySym = MakeSymbol(ClassHierarchy.getAddress(), "RTTI_Class_Hierarchy_Descriptor");
				ClassHierarchySym.setNamespace(gClass.SymbolClass);
				int BaseClassCount = currentProgram.getMemory().getInt(ClassHierarchy.getAddress().add(0x8));
				int BaseClassArrayPtr = currentProgram.getMemory().getInt(ClassHierarchy.getAddress().add(0xc));
				Data BaseClassArray = MakeGetRttiData(currentProgram.getMinAddress().add(BaseClassArrayPtr), "BaseClassArray", 0x4 * BaseClassCount);
				Symbol BaseClassArraySym = MakeSymbol(BaseClassArray.getAddress(), "RTTI_Base_Class_Array");
				BaseClassArraySym.setNamespace(gClass.SymbolClass);
				for (int i = 0; i < BaseClassCount; i++) {
					Data BaseDescriptor = MakeGetRttiData(currentProgram.getMinAddress().add(currentProgram.getMemory().getInt(BaseClassArray.getAddress().add(0x4 * i))), "BaseClassDescriptor", 0x1c);
					GeneratedClass TargetClassForDescriptor = ClassesByTypeDescriptor.get(currentProgram.getMinAddress().add(currentProgram.getMemory().getInt(BaseDescriptor.getAddress())));
					String BaseDescriptorName;
					if (TargetClassForDescriptor != null) {
						BaseDescriptorName = "RTTI_Base_Class_Descriptor_(" + TargetClassForDescriptor.Name;
					} else {
						BaseDescriptorName = "RTTI_Base_Class_Descriptor_For_" + gClass.Name + i;
					}
					Symbol BaseDescriptorSym = MakeSymbol(BaseDescriptor.getAddress(), BaseDescriptorName);
					if (TargetClassForDescriptor != null) {
						BaseDescriptorSym.setNamespace(TargetClassForDescriptor.SymbolClass);
					} else {
						BaseDescriptorSym.setNamespace(gClass.SymbolClass);
					}
					/*
					String BaseDescriptorName = "RTTI_Base_Class_Descriptor_(" 
							+ currentProgram.getMemory().getInt(BaseDescriptor.getAddress().add(4)) + "," 
							+ currentProgram.getMemory().getInt(BaseDescriptor.getAddress().add(8)) + ","
							+ currentProgram.getMemory().getInt(BaseDescriptor.getAddress().add(0xc)) + ","
							+ currentProgram.getMemory().getInt(BaseDescriptor.getAddress().add(0x10)) + ")";
					*/
					/*
					for (var existingSymbol : currentProgram.getSymbolTable().getSymbols(BaseDescriptor.getAddress())) {
						currentProgram.getSymbolTable().removeSymbolSpecial(existingSymbol);
					}
					*/
					/*
					Symbol BaseDescriptorSym = currentProgram.getSymbolTable().getPrimarySymbol(BaseDescriptor.getAddress());
					if (BaseDescriptorSym == null || !BaseDescriptorSym.getName().equals(BaseDescriptorName)) {
						BaseDescriptorSym = MakeSymbol(BaseDescriptor.getAddress(), BaseDescriptorName);
						if (TargetClassForDescriptor != null) {
							BaseDescriptorSym.setNamespace(TargetClassForDescriptor.SymbolClass);
						} else {
							BaseDescriptorSym.setNamespace(gClass.SymbolClass);
						}
					}
					*/
				}
			}
		}
		// Find the class hierarchy and base class objects and build up an inheritance tree for each class
		for (var gClass : Classes) {
			if (gClass.CanCheckClassHierarchy() && gClass.BaseClasses == null && !gClass.CheckClassIsBase()) {
				// Generate base class list - we assume that classes that can't find hierarchy are base
			}
		}
	}
	
	private Data GetOrMakeFunctionPointer(Address ptrAddress) throws CodeUnitInsertionException {
		var dataPtr = currentProgram.getListing().getDataAt(ptrAddress);
		if (!dataPtr.getDataType().getName().equals("pointer") ||
			!dataPtr.getDataType().getName().equals("undefined *")) {
			currentProgram.getListing().clearCodeUnits(ptrAddress, ptrAddress.add(8), false);
			dataPtr = currentProgram.getListing().createData(ptrAddress, new Pointer64DataType());
		}
		return dataPtr;
	}
	
	private boolean IsInProgramRange(Address addr) {
		return currentProgram.getMinAddress().compareTo(addr) == -1 && currentProgram.getMaxAddress().compareTo(addr) == 1;
	}
	private Address Deref(Data pData) {
		return currentProgram.getAddressFactory().getAddress(pData.getValue().toString());
	}
	
	private Function GetOrMakeFunction(Address addr, String name, Namespace ns) 
			throws InvalidInputException, DuplicateNameException, CircularDependencyException, MemoryAccessException {
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
			func.setName(name, SourceType.ANALYSIS);
		}
		// Add to namespace if provided
		if (ns != null) {
			func.setParentNamespace(ns);
		}
		// check if it's a thunk function, in which case we'll have to rename the inner function too
		if (instr.getMnemonicString().equals("JMP")) {
			var instrLength = instr.getBytes().length;
			var jmpFirstByte = currentProgram.getMemory().getByte(addr);
			if (jmpFirstByte == -23) { // near jump, 32 bit branch pointer
				var jmpRel = currentProgram.getMemory().getInt(addr.add(1));
				Address thunkAddr = addr.add(jmpRel + instrLength);
				println(thunkAddr.toString());
				GetOrMakeFunction(thunkAddr, name, ns);
			} else {
				println("Unknown first byte " + jmpFirstByte + " at " + addr);
			}
		}
		return func;
	}
	
	private DecompInterface setUpDecompiler() {
		DecompInterface decomplib = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, currentProgram);
		}
		decomplib.setOptions(options);

		decomplib.toggleCCode(true);
		decomplib.toggleSyntaxTree(true);
		decomplib.setSimplificationStyle("decompile");

		return decomplib;
	}
	
	private void FindVtable() throws CancelledException {
		// Find vtable using ptr64 to RTTI Complete Object Locator
		MemoryBytePatternSearcher VtableMetaPointer = new MemoryBytePatternSearcher("RTTI Vtable Meta Pointer");
		for (var gClass : Classes) {
			if (gClass.CanCheckClassHierarchy()) {
				byte[] objLocPtr = DataConverter.getInstance(false).getBytes(gClass.CompleteObjectLocator.getOffset());
				GenericMatchAction<GeneratedClass> actionOnFindMetaPtr = new GenericMatchAction<>(gClass) {
					@Override
					public void apply(Program prog, Address addr, Match match) {
						try {
							//println("Found vtable for class " + gClass.Name + " at " + addr.add(8).toString());
							// Label pointer to Complete Object Locator
							Symbol typeMetaPtr = MakeSymbol(addr, "vtable_meta_ptr");
							typeMetaPtr.setNamespace(gClass.SymbolClass);
							gClass.Vtable = addr.add(8);
							// Label Vtable
							Symbol typeVtable = MakeSymbol(gClass.Vtable, "vtable");
							typeVtable.setNamespace(gClass.SymbolClass);
							// Label first function as destructor (this isn't true for all functions, check for assertSize)
							/*
							Data dtorPtr = GetOrMakeFunctionPointer(gClass.Vtable);
							if (IsInProgramRange(dtorPtr.getAddress())) {
								Function dtor = GetOrMakeFunction(Deref(dtorPtr), "`scalar_deleting_destructor'", gClass.SymbolClass);
							} else {
								println("WARNING: Scalar deleting destructor is null for class " + gClass.Name);
							}
							*/
							// Look for subsequent functions in the vtable
							//currentProgram.getAddressFactory().getAddress();
							//Symbol scalarDeletingDestructorSym = MakeSymbol()
						} catch (CircularDependencyException | InvalidInputException | DuplicateNameException  e) {
							e.printStackTrace();
						}
					}
				};
				GenericByteSequencePattern<GeneratedClass> findMetaPtr = new GenericByteSequencePattern<>(objLocPtr, actionOnFindMetaPtr);
				VtableMetaPointer.addPattern(findMetaPtr);
			}
		}
		AddressSet VtableMetaSearchSet = new AddressSet();
		VtableMetaSearchSet.add(currentProgram.getMinAddress(), currentProgram.getMaxAddress());
		VtableMetaPointer.search(currentProgram, VtableMetaSearchSet, monitor);
	}
	
	private void LookForStructSize() {
		// Check first function `scalar_deleting_destructor' and find the struct size
	}
	
	private void CreateDTMTypes() {
		
	}
	
	// https://github.com/angryzor/rangers-api
	private void FillInDataForKnownTypes() {
		
	}
	
	private void GiveDummyNamesForVtable() {
		
	}

	@Override
	protected void run() throws Exception {
		GetRttiTypes();
		Decompiler = setUpDecompiler();
		if (!Decompiler.openProgram(currentProgram)) {
			println("ERROR: Couldn't open the program in the decompiler");
			return;
		}
		MemoryBlock rtti0MemBlock = GetMemoryBlockContainingTypeDescriptors();
		if (rtti0MemBlock == null) {
			return;
		}
		println("Found block containing RTTI Type Descriptor info: " + rtti0MemBlock.getName() + ", " + rtti0Addresses.size() + " entries");
		GetTypeDescriptors();
		if (Classes.size() == 0) {
			return;
		}
		FindCompleteObjectLocators();
		BuildClassHierarchy();
		FindVtable();
		CreateDTMTypes();
		FillInDataForKnownTypes();
	}
}