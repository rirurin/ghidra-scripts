//Checks the signatures stored in a UnrealEssentials formatted Scan YAML file: See https://github.com/AnimatedSwine37/UnrealEssentials/
//@author Rirurin
//@category Game Modding
//@keybinding
//@menupath
//@toolbar

import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.esotericsoftware.yamlbeans.YamlReader;
import com.ezylang.evalex.EvaluationException;
import com.ezylang.evalex.Expression;
import com.ezylang.evalex.config.ExpressionConfiguration;
import com.ezylang.evalex.data.EvaluationValue;
import com.ezylang.evalex.functions.AbstractFunction;
import com.ezylang.evalex.functions.FunctionParameter;
import com.ezylang.evalex.parser.ParseException;
import com.ezylang.evalex.parser.Token;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class CheckUnrealEssentialsScans extends GhidraScript {
	
	private static Listing GListing;
	private static Memory GMemory;
	private static Address CodeStart;
	private static Address CodeEnd;
	
	private static ConcurrentLinkedQueue<ScanFail> Failed;
	
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
		public String name;
		public Signature candidate;
		public Expression transform;
		private Address targetAddress = null;
		
		public SignatureSearch(String name, Signature candidate, Expression transform) {
			this.name = name;
			this.candidate = candidate;
			this.transform = transform;
		}
		
		public Address search() throws ParseException, EvaluationException {
			var start = GMemory.findBytes(
					CodeStart,
					CodeEnd,
					candidate.search,
					candidate.mask,
					true,
					monitor
			);
			if (this.transform != null) {
				EvaluationValue result = this.transform
						.with("result", start.getOffset())
						.evaluate();
				targetAddress = toAddr(Long.toHexString(result.getNumberValue().longValue()));	
			} else {
				targetAddress = start;
			}
			return targetAddress;
		}
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
	
	public class ScanIniEntry {
		public String Bytes;
		public Expression Transform;
		
		public ScanIniEntry(String Bytes) {
			this.Bytes = Bytes;
			this.Transform = null;
		}
		
		public ScanIniEntry(String Bytes, Expression Transform) {
			this.Bytes = Bytes;
			this.Transform = Transform;
		}
		
		@Override
		public String toString() {
			return this.Bytes + (this.Transform != null ? (" -> " + this.Transform) : "" );
		}
	}
	
	public class ScanFail {
		public String Name;
		public String Bytes;
		
		public ScanFail(String Name, String Bytes) {
			this.Name = Name;
			this.Bytes = Bytes;
		}
	}
	
	@FunctionParameter(name = "address")
	public class GetGlobalAddressFunction extends AbstractFunction {

		@Override
		public EvaluationValue evaluate(Expression expression, Token functionToken, EvaluationValue... parameterValues)
				throws EvaluationException {
			try {
				EvaluationValue value = parameterValues[0];
				var address = toAddr(Long.toHexString(Long.parseLong(value.getStringValue())));
				var offset = getInt(address);
				var outAddress = address.add(offset + 4);
				return expression.convertDoubleValue(outAddress.getOffset());
			} catch (MemoryAccessException e) {
				throw new IllegalArgumentException(e.getMessage());
			}
		}
	}
	
	public static Expression fromUnrealEssentialsTransform(String transform, ExpressionConfiguration config) throws Exception {
		switch (transform) {
			case "GetIndirectAddressShort":
				return new Expression("GetGlobalAddress(result + 1)", config);
			case "GetIndirectAddressShort2":
				return new Expression("GetGlobalAddress(result + 2)", config);
			case "GetIndirectAddressLong":
				return new Expression("GetGlobalAddress(result + 3)", config);
			case "GetIndirectAddressLong4":
				return new Expression("GetGlobalAddress(result + 4)", config);
			default:
				return new Expression(transform, config);
			//default:
			//	throw new Exception("Unknown transform name " + transform);
		}
	}
	
	private static String ResultKey = "_RESULT";
	private static String DisabledValue = "DISABLED";

	@Override
	protected void run() throws Exception {
		GListing = currentProgram.getListing();
		GMemory = currentProgram.getMemory();
		
		// Get actual code range
		var dosHeader = new FieldedData(GListing.getDataAt(GMemory.getMinAddress()));
		var ntHeader = new FieldedData(GListing.getDataAt(
				GMemory.getMinAddress().add(Long.parseLong(dosHeader.Get("e_lfanew").getValue().toString().substring(2), 16))));
		var optionalHeader = new FieldedData(ntHeader.Get("OptionalHeader"));
		
		CodeStart = toAddr(optionalHeader.Get("BaseOfCode").getValue().toString());
		CodeEnd = CodeStart.add(Long.parseLong(optionalHeader.Get("SizeOfCode").getValue().toString().substring(2), 16));
		
		var scanYaml = askFile("Select the Scan YAML file (UnrealEssentials)", "OK");
		HashMap<String, ScanIniEntry> Signatures = new HashMap<>();
		
		var expressionConfig = ExpressionConfiguration.defaultConfiguration()
				.withAdditionalFunctions(
						Map.entry("GetGlobalAddress", new GetGlobalAddressFunction())
						);
		
		Failed = new ConcurrentLinkedQueue<>();
		try (var reader = new YamlReader(new FileReader(scanYaml))) {
			@SuppressWarnings("unchecked")
			var object = (HashMap<String, Object>)reader.read();
			@SuppressWarnings("unchecked")
			var sigList = (HashMap<String, Object>)object.get("Signatures");
			if (sigList != null) {
				for (var sigEntry : sigList.entrySet()) {
					var className = sigEntry.getValue().getClass().getName();
					if (className.equals("java.lang.String")) {
						Signatures.put(sigEntry.getKey(), new ScanIniEntry((String)sigEntry.getValue()));
					} else if (className.equals("java.util.LinkedHashMap")) {
						@SuppressWarnings("unchecked")
						var entryMap = (HashMap<String, Object>)sigEntry.getValue();
						Signatures.put(sigEntry.getKey(), new ScanIniEntry(
								(String)entryMap.get("signatures"), 
								fromUnrealEssentialsTransform((String)entryMap.get("transforms"), expressionConfig)
								));
					}
				}
			}
		}
		
		try (ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors())) {
			Signatures.forEach((name, value) -> {
				executor.submit(() -> {
					var searcher = new SignatureSearch(name, new Signature(value.Bytes), value.Transform);
					try {
						var address = searcher.search();
						if (address != null) {
							println("Found " + name + " at " + address.toString());
						} else {
							Failed.add(new ScanFail(name, value.Bytes));
						}
					} catch (ParseException | EvaluationException e) {
						throw new IllegalArgumentException("Error while evaluating expression for " + name + " : " + e.getMessage());
					}
				});
			});
		}
		println("==================================");
		if (Failed.isEmpty()) {
			println("All signatures were found!");
		} else {
			println("Found " + Failed.size() + " broken signatures:");
			for (var fail : Failed) {
				println(fail.Name + " : " + fail.Bytes);
			}	
		}
	}
}
