//Checks the signatures stored in a RyoTune.Reloaded Scan INI file: See https://github.com/RyoTune/RyoTune.Reloaded/
//@author Rirurin
//@category Game Modding
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class LabelStaticClassFunctions extends GhidraScript {
	
	private static Listing GListing;
	private static Memory GMemory;
	private static SymbolTable GSymbolTable;
	public static DecompileOptions GDecompileOptions;
	public static DecompInterface GDecompInterface;
	
	public Function getOrCreateFunction(Address addr) {
		var func = GListing.getFunctionAt(addr);
		if (func == null) func = createFunction(addr, null);
		return func;
	}
	
	public class Signature {
		public byte[] search;
		public byte[] mask;
		
		public Signature(String string) {
			String[] bytes = string.split(" ");
			search = new byte[bytes.length];
			mask = new byte[bytes.length];
			for (int i = 0; i < bytes.length; i++) {
				if (bytes[i].equals("??")) {
					search[i] = 0;
					mask[i] = 0;
				} else {
					var AsInt = Integer.parseInt(bytes[i], 16);
					search[i] = (byte)AsInt;
					mask[i] = -1;
				}
			}
		}
		
		@Override
		public String toString() {
			String output = "";
			for (int i = 0; i < search.length; i++) {
				output += mask[i] != 0 ? String.format("%02X", Byte.toUnsignedInt(search[i])) : "??";
				if (i < search.length - 1) {
					output += " ";
				}
			}
			return output;
		}
	}
	
	public class SignatureSearch {
		public Signature[] candidates;
		private Address targetAddress = null;
		
		public SignatureSearch(Signature candidate) {
			this.candidates = new Signature[] { candidate };
		}
		
		public SignatureSearch(Signature[] candidates) {
			this.candidates = candidates;
		}
		
		public Address search() {
			for (Signature candidate : candidates) {
				targetAddress = GMemory.findBytes(
						GMemory.getMinAddress(),
						GMemory.getMaxAddress(),
						candidate.search,
						candidate.mask,
						true,
						monitor
				);
				if (targetAddress != null) {
					break;
				}
			}
			return targetAddress;
		}
	}
	
	private static UnrealVersion GVersion;
	private static Map<String, UnrealVersion> UnrealNames = Map.ofEntries(
			Map.entry("UE 4.27", UnrealVersion.UE_4_27),
			Map.entry("UE 5.0", UnrealVersion.UE_5_0),
			Map.entry("UE 5.1", UnrealVersion.UE_5_1),
			Map.entry("UE 5.2", UnrealVersion.UE_5_2),
			Map.entry("UE 5.3", UnrealVersion.UE_5_3),
			Map.entry("UE 5.4", UnrealVersion.UE_5_4),
			Map.entry("UE 5.5", UnrealVersion.UE_5_5),
			Map.entry("UE 5.6", UnrealVersion.UE_5_6),
			Map.entry("UE 5.7", UnrealVersion.UE_5_7)
	);
	
	private static Map<UnrealVersion, String> GetPrivateStaticClassBodySignatures = Map.ofEntries(
			Map.entry(UnrealVersion.UE_4_27, "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC 60 45 33 ED"),
			Map.entry(UnrealVersion.UE_5_0, "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC 30 4D 8B E1"),
			Map.entry(UnrealVersion.UE_5_1, "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 54 41 56 41 57 48 83 EC 30 4D 8B F1"),
			Map.entry(UnrealVersion.UE_5_2, "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC 30 4D 8B F1"),
			Map.entry(UnrealVersion.UE_5_3, "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC 30 4D 8B F1 49 8B F8"),
			Map.entry(UnrealVersion.UE_5_4, "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC 30 4D 8B F1 49 8B F8"),
			Map.entry(UnrealVersion.UE_5_5, "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC 30 4D 8B F1 49 8B F8"),
			Map.entry(UnrealVersion.UE_5_6, "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC 30 49 8B E9 49 8B D8"),
			Map.entry(UnrealVersion.UE_5_7, "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC 30 49 8B E9 49 8B D8")
	);
	
	private enum UnrealVersion {
		UE_4_27,
		UE_5_0,
		UE_5_1,
		UE_5_2,
		UE_5_3,
		UE_5_4,
		UE_5_5,
		UE_5_6,
		UE_5_7,
	}
	
	private int GetVersionValue(UnrealVersion value) {
		switch (value) {
			case UnrealVersion.UE_4_27:
				return 0;
			case UnrealVersion.UE_5_0:
				return 1;
			case UnrealVersion.UE_5_1:
				return 2;
			case UnrealVersion.UE_5_2:
				return 3;
			case UnrealVersion.UE_5_3:
				return 4;
			case UnrealVersion.UE_5_4:
				return 5;
			case UnrealVersion.UE_5_5:
				return 6;
			case UnrealVersion.UE_5_6:
				return 7;
			case UnrealVersion.UE_5_7:
				return 8;
			default:
				throw new IllegalArgumentException("Unknown version identifier " + value);
		}
	}
	
	private Varnode GetVarnodeFromFunctionParameter(HighFunction hf, int paramIndex) {
		var f = hf.getFunction();
		var reg = f.getParameter(paramIndex).getRegister();
		var vnodes = hf.getVarnodes(reg.getAddress());
		if (!vnodes.hasNext()) return null;
		return vnodes.next();
	}
	
	// From ShowConstantUse.java
	// These contains fields that are part of the back-tracking process if a
	// variable is traced
	// to the parameter of function, this is an entry for that location
	public class FunctionParamUse {
		String name;
		Address addr;
		Integer paramIndex;
		Varnode representative;
		ArrayList<PcodeOp> defUseList;

		public FunctionParamUse(String name, Address addr, int i, Varnode varnode,
				ArrayList<PcodeOp> defUseList) {
			this.name = name;
			this.addr = addr;
			this.paramIndex = i;
			this.defUseList = defUseList;
			this.representative = varnode;
		}

		public String getName() {
			return name;
		}

		public Address getAddress() {
			return addr;
		}

		public int getParamIndex() {
			return paramIndex;
		}

		public Varnode getRepresentative() {
			return representative;
		}

		public ArrayList<PcodeOp> getDefUseList() {
			return defUseList;
		}
	}
	
	// From ShowConstantUse.java
	/**
	 * Backtrack to a constant given a varnode within a decompiled function This
	 * isn't useful for functions that can't be decompiled
	 * 
	 * @param var
	 *            varnode that represents a variable in a decompilation
	 * @param tableChooserDialog
	 *            - accumulate entries. Don't like passing it, but this way the
	 *            user gets immediate feedback as locations are found
	 * @return a map of Addresses->constants (constants could be NULL)
	 * @throws CancelledException if cancelled
	 */
	private HashMap<Address, Long> backtrackToConstant(Varnode var, HighFunction hf) 
			throws CancelledException, InvalidInputException, DuplicateNameException, CircularDependencyException {
		// follow varnode back to any constants, accumulating back to function
		// param
		HashMap<Address, Long> constUse = new HashMap<Address, Long>();
		ArrayList<FunctionParamUse> funcList = new ArrayList<FunctionParamUse>();
		ArrayList<PcodeOp> defUseList = new ArrayList<PcodeOp>();
		followToParam(constUse, defUseList, hf, var, funcList, null);
		return followFunctionParamToConstant(funcList, constUse);
	}
	
	// From ShowConstantUse.java
	private void followToParam(HashMap<Address, Long> constUse, ArrayList<PcodeOp> defUseList,
			HighFunction highFunction, Varnode vnode, ArrayList<FunctionParamUse> funcList,
			HashSet<SequenceNumber> doneSet) {
		// follow back up through
		PcodeOp def = vnode.getDef();
		Function function = highFunction.getFunction();
		if (def == null) {
			HighVariable hvar = vnode.getHigh();
			if (hvar instanceof HighParam) {
				funcList.add(new FunctionParamUse(function.getName(), function.getEntryPoint(),
					((HighParam) hvar).getSlot(), hvar.getRepresentative(), defUseList));
				return;
			}
			if (hvar instanceof HighGlobal) {
				followThroughGlobal(constUse, defUseList, hvar, funcList, doneSet);
			}
			return;
		}
		
		// have we done this vnode source already?
		Address funcEntry = function.getEntryPoint();
		SequenceNumber seqNum = def.getSeqnum();
		remapAddress(funcEntry, def.getOutput().getPCAddress());

		if (doneSet == null) {
			doneSet = new HashSet<SequenceNumber>();
		}
		if (seqNum != null && doneSet.contains(seqNum)) {
			return;
		}
		doneSet.add(seqNum);
		
		int opcode = def.getOpcode();
		switch (opcode) {
			case PcodeOp.COPY:
				if (def.getInput(0).isConstant()) {
					long value = def.getInput(0).getOffset();
					try {
						value = applyDefUseList(value, defUseList);
						constUse.put(remapAddress(funcEntry, def.getOutput().getPCAddress()),
							value);
						/*
						println("   " + function.getName() + "    " +
							def.getOutput().getPCAddress() + " : 0x" + Long.toHexString(value));
						*/
					}
					catch (InvalidInputException exc) {
						// Do nothing
					}
					return;
				}
				followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
					doneSet);
				return;
			case PcodeOp.LOAD:
				if (def.getInput(0).isConstant() && def.getInput(1).isConstant()) {
					long space = def.getInput(0).getOffset();
					long offset = def.getInput(1).getOffset();
					if (space != funcEntry.getAddressSpace().getSpaceID()) {
						break;
					}
					try {
						offset = applyDefUseList(offset, defUseList);
						constUse.put(remapAddress(funcEntry, def.getOutput().getPCAddress()),
							offset);
						/*
						println("   " + function.getName() + "    " +
							def.getOutput().getPCAddress() + " : 0x" + Long.toHexString(offset));
						*/
					}
					catch (InvalidInputException exc) {
						// Do nothing
					}
					return;
				}
				followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
					doneSet);
				return;
			case PcodeOp.INT_ZEXT:
				followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
					doneSet);
				return;
			case PcodeOp.MULTIEQUAL:
				for (int i = 0; i < def.getNumInputs(); i++) {
					ArrayList<PcodeOp> splitUseList = new ArrayList<>(defUseList);
					followToParam(constUse, splitUseList, highFunction, def.getInput(i), funcList,
						doneSet);
				}
				return;
			case PcodeOp.CAST:
				followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
					doneSet);
				return;
			case PcodeOp.INDIRECT:
				Varnode output = def.getOutput();
				if (output.getAddress().equals(def.getInput(0).getAddress())) {
					followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
						doneSet);
					return;
				}
				if (def.getInput(0).isUnique()) {
					followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
						doneSet);
					return;
				}
				break;
			case PcodeOp.INT_AND:
				if (def.getInput(1).isConstant()) {
					defUseList.add(0, def);
					followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
						doneSet);
					return;
				}
				break;
			case PcodeOp.INT_ADD:
				if (def.getInput(1).isConstant()) {
					defUseList.add(0, def);
					followToParam(constUse, defUseList, highFunction, def.getInput(0), funcList,
						doneSet);
					return;
				}
				if (vnode.getHigh() instanceof HighParam) {
					// Do nothing
				}
				break;
			case PcodeOp.PTRADD: // Pointer + some offset (usually an array access)
				break;

			case PcodeOp.PTRSUB: // Pointer + some sub element access (usually a
								// structure ref)
				Varnode offsetVal = def.getInput(1);
				if (!offsetVal.isConstant()) {
					break;
				}
				Varnode baseVal = def.getInput(0);
				if (baseVal.isConstant()) {
					// both constant, just use it and return the address
					long value = baseVal.getOffset() + offsetVal.getOffset();
					try {
						value = applyDefUseList(value, defUseList);
						constUse.put(remapAddress(funcEntry, def.getOutput().getPCAddress()),
							value);
						println("   " + function.getName() + "    " +
							def.getOutput().getPCAddress() + " : 0x" + Long.toHexString(value));
					}
					catch (InvalidInputException exc) {
						// Do nothing
					}
					return;
				}
				break;
		}

		constUse.put(remapAddress(funcEntry, vnode.getPCAddress()), null);
		//println("   " + function.getName() + "    " + vnode.getPCAddress() + " : Lost");
		// println("     Lost IT! " + vnode.getPCAddress());
	}
	
	// From ShowConstantUse.java
	private void followThroughGlobal(HashMap<Address, Long> constUse, ArrayList<PcodeOp> defUseList,
			HighVariable hvar, ArrayList<FunctionParamUse> funcList,
			HashSet<SequenceNumber> doneSet) {
		Address loc = hvar.getRepresentative().getAddress();
		PcodeOp def = hvar.getRepresentative().getDef();
		SequenceNumber seqnum = null;
		if (def != null) {
			seqnum = def.getSeqnum();
			if (doneSet.contains(seqnum)) {
				return;
			}
		}
		else {
			seqnum = new SequenceNumber(loc, 0);
		}

		ReferenceIterator referencesTo = currentProgram.getReferenceManager().getReferencesTo(loc);
		while (referencesTo.hasNext()) {
			Reference reference = referencesTo.next();
			if (!reference.getReferenceType().isWrite()) {
				continue;
			}
			currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
			//Address refAddr = reference.getFromAddress();
		}

		doneSet.add(seqnum);
	}
	
	// From ShowConstantUse.java
	private long applyDefUseList(long value, ArrayList<PcodeOp> defUseList)
			throws InvalidInputException {
		if (defUseList == null || defUseList.size() <= 0) {
			return value;
		}
		for (PcodeOp pcodeOp : defUseList) {
			int opcode = pcodeOp.getOpcode();
			switch (opcode) {
				case PcodeOp.INT_AND:
					if (pcodeOp.getInput(0).isConstant()) {
						value = value & pcodeOp.getInput(0).getOffset();
					}
					else if (pcodeOp.getInput(1).isConstant()) {
						value = value & pcodeOp.getInput(1).getOffset();
					}
					else {
						throw new InvalidInputException(
							" Unhandled Pcode OP " + pcodeOp.toString());
					}
					break;
				default:
					throw new InvalidInputException(" Unhandled Pcode OP " + pcodeOp.toString());
			}
		}
		return value;
	}
	
	// From ShowConstantUse.java
	private Address remapAddress(Address funcEntry, Address address) {
		if (funcEntry.getAddressSpace().isOverlaySpace()) {
			address = funcEntry.getAddressSpace().getOverlayAddress(address);
		}
		return address;
	}
	
	private int getStringLength(Address addr, int charSize) throws MemoryAccessException {
		// string has no defined length, so go forward through the listing until we hit a 00 byte
		Data a = currentProgram.getListing().getDataAt(addr);
		int i = 0;
		short av;
		do {
			switch (charSize) {
				case 2:
					av = a.getShort(i);
					break;
				default:
					av = a.getByte(i);
					break;
			}
			i += charSize;
		} while (av != 0);
		return i - 1;
	}
	
	private void clearListingForDataType(Address addr, DataType typeToFit) throws CancelledException, MemoryAccessException {
		if (typeToFit.equals(new StringDataType())) {
			clearListing(addr, addr.add(getStringLength(addr, 1)));
		} else if (typeToFit.equals(new UnicodeDataType())) {
			clearListing(addr, addr.add(getStringLength(addr, 2)));
		} else {
			clearListing(addr, addr.add(typeToFit.getLength() - 1)); // type with defined length
		}
	}
	
	private Data addDataTypeToListing(Address listingLocation, DataType dt) throws CancelledException {
		Data out = null;
		try {
			out = currentProgram.getListing().getDataAt(listingLocation);
			if (!out.getDataType().equals(dt)) {
				clearListingForDataType(listingLocation, dt);
				out = currentProgram.getListing().createData(listingLocation, dt);
			} // else Type already exists at this location
		} catch (MemoryAccessException | CodeUnitInsertionException | NullPointerException e) {
			println("[LabelStaticClassFunctions::addDataTypeToListing] " + e.getMessage());
		}
		return out;
	}
	
	private void addConstants(HashMap<Address, Long> constLocs) throws CancelledException, InvalidInputException, DuplicateNameException, CircularDependencyException {
		Set<Address> keys;
		keys = constLocs.keySet();
		Address[] keyArray = keys.toArray(new Address[0]);
		//Arrays.sort(keyArray);
		for (Address loc : keyArray) {
			Long constant = constLocs.get(loc);
			Address classNameAddr = toAddr(Long.toHexString(constant - 2));
			var classNameData = addDataTypeToListing(classNameAddr, new UnicodeDataType());
			var className = classNameData.getValue().toString(); // remove U prefix
			var namespace = GSymbolTable.getNamespace(className, null);
			if (namespace == null) {
				continue;
			}
			var parentFunc = GListing.getFunctionContaining(loc);
			println(parentFunc.getName() + " @ " + parentFunc.getEntryPoint().toString() + " => " + className + "::StaticClass");
			//var namespace = GSymbolTable.getOrCreateNameSpace(null, className, SourceType.ANALYSIS);
			parentFunc.setName("StaticClass", SourceType.ANALYSIS);
			parentFunc.setParentNamespace(namespace);
		}
	} 
	
	// From ShowConstantUse.java
	private HashMap<Address, Long> followFunctionParamToConstant(
			ArrayList<FunctionParamUse> funcList, HashMap<Address, Long> constUse) throws CancelledException, InvalidInputException, DuplicateNameException, CircularDependencyException {

		// any routines we bumped into, process back up the chain
		HashSet<Address> doneRoutines = new HashSet<Address>();
		while (funcList.size() > 0) {
			// get the next function the variable has been traced back to
			FunctionParamUse funcVarUse = funcList.remove(0);
			Address addr = funcVarUse.getAddress();
			int paramIndex = funcVarUse.getParamIndex();
			ArrayList<PcodeOp> defUseList = funcVarUse.getDefUseList();

			// will do this at another time.
			if (doneRoutines.contains(addr)) {
				continue;
			}
			doneRoutines.add(addr);

			// find all functions referring to that place
			ReferenceIterator referencesTo =
				currentProgram.getReferenceManager().getReferencesTo(addr);
			for (Reference reference : referencesTo) {
				monitor.checkCancelled();

				// get function containing.
				Address refAddr = reference.getFromAddress();
				if (refAddr.getAddressSpace().getType() == AddressSpace.TYPE_NONE ||
					refAddr.isExternalAddress()) {
					continue;
				}

				Function refFunc =
					currentProgram.getFunctionManager().getFunctionContaining(refAddr);

				HashMap<Address, Long> localConstUse = new HashMap<Address, Long>();

				if (refFunc == null) {
					localConstUse.put(refAddr, null);
					/*
					String problem = "*** No function at " + refAddr +
						".\nCould not analyze constant use past this undefined function!";
					refFunc = UndefinedFunction.findFunction(currentProgram, refAddr, monitor);
					*/
				}

				if (refFunc != null) {
					// decompile function
					// look for call to this function
					// display call
					ArrayList<PcodeOp> localDefUseList = new ArrayList<PcodeOp>(defUseList);

					this.monitor.setMessage("Analyzing : " + refFunc.getName() + " for refs to " +
						addr + ":" + paramIndex);

					analyzeFunction(localConstUse, refFunc, refAddr, funcVarUse, paramIndex, localDefUseList, funcList);
					addConstants(localConstUse);
				}

				constUse.putAll(localConstUse);
			}
		}

		return constUse;
	}
	
	// From ShowConstantUse.java
	private void analyzeFunction(HashMap<Address, Long> constUse, Function f, Address refAddr, FunctionParamUse funcVarUse, int paramIndex,
			ArrayList<PcodeOp> defUseList, ArrayList<FunctionParamUse> funcList) {
		if (f == null) {
			return;
		}
		var hfunction = GDecompInterface.decompileFunction(f, 10, monitor).getHighFunction();
		Instruction instr = GListing.getInstructionAt(refAddr);
		if (hfunction == null) {
			return;
		}
		Iterator<PcodeOpAST> ops = hfunction.getPcodeOps(refAddr.getPhysicalAddress());
		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();
			if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {
				// get the second parameter
				Varnode parm = pcodeOpAST.getInput(paramIndex + 1); // 1st param is the call dest
				if (parm == null) {
					constUse.put(instr.getAddress(), null);
					/*
					String problem = "  *** Warning, it appears that function '" +
						funcVarUse.getName() + "' at " + funcVarUse.getAddress() +
						" does not have it's parameters recovered!\n" +
						"        Use Commit Params/Return in the decompiler on this function.";
					addErrorNote(instr.getAddress(), problem);
					*/
					break;
				}
				// see if it is a constant
				if (parm.isConstant() || parm.isAddress()) {
					// then this is a resource id
					// lookup the resource and create a reference
					long value = parm.getOffset();
					// TODO: not so fast, if there is a defUseList, must apply
					// it to get the real constant USED!
					try {
						value = applyDefUseList(value, defUseList);
						constUse.put(instr.getAddress(), value);
						/*
						println("   " + f.getName() + "    " + instr.getAddress() + " : 0x" +
							Long.toHexString(value));
						*/
					}
					catch (InvalidInputException exc) {
						// do nothing
					}
				}
				else {
					followToParam(constUse, defUseList, hfunction, parm, funcList, null);
				}
				break;
				// if this is anything else, get the high variable to see if it
				// can be traced back to a param
				// then repeat with any calls to this function at whatever the
				// param is
			}
			else if (pcodeOpAST.getOpcode() == PcodeOp.BRANCH) {
				Address faddr = pcodeOpAST.getInput(0).getAddress();
				if (funcVarUse == null || faddr == null) {
					continue;
				}
				if (!faddr.equals(funcVarUse.getAddress())) {
					continue;
				}
				Varnode rep = funcVarUse.getRepresentative();
				if (rep == null) {
					continue;
				}
				followToParam(constUse, defUseList, hfunction, rep, funcList, null);
			}
		}
	}

	@Override
	protected void run() throws Exception {
		GListing = currentProgram.getListing();
		GMemory = currentProgram.getMemory();
		GSymbolTable = currentProgram.getSymbolTable();
		
		GVersion = UnrealNames.get(askChoice(
				"Version Selector", "Unreal Version", 
				new ArrayList<>(UnrealNames.keySet()), 
				UnrealNames.keySet().toArray()[0])
		);
		var GetPrivateStaticClassBody_Search = new SignatureSearch(new Signature[] { new Signature(GetPrivateStaticClassBodySignatures.get(GVersion)) });
		var GetPrivateStaticClassBody = GetPrivateStaticClassBody_Search.search();
		if (GetPrivateStaticClassBody == null) {
			throw new IllegalArgumentException("Could not find GetPrivateStaticClassBody using the signature candidate for " + GVersion.toString());
		}
		GDecompileOptions = new DecompileOptions();
		GDecompInterface = new DecompInterface();
		GDecompInterface.setOptions(GDecompileOptions);
		GDecompInterface.openProgram(currentProgram);
		println(GetPrivateStaticClassBody.toString());
		var staticClassHF = GDecompInterface.decompileFunction(getOrCreateFunction(GetPrivateStaticClassBody), 10, monitor).getHighFunction();
		if (staticClassHF == null) {
			throw new IllegalArgumentException("Failed to decompile function GetPrivateStaticClassBody");
		}
		var varNode = GetVarnodeFromFunctionParameter(staticClassHF, 1);
		println(varNode.toString());
		backtrackToConstant(varNode, staticClassHF);
		GDecompInterface.closeProgram();
	}
}
