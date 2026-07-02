//Checks the signatures stored in a RyoTune.Reloaded Scan INI file: See https://github.com/RyoTune/RyoTune.Reloaded/
//@author Rirurin
//@category Game Modding
//@keybinding
//@menupath
//@toolbar

import java.io.FileReader;
import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.commons.configuration2.INIConfiguration;

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

public class CheckScanINI extends GhidraScript {
	
	private static Listing GListing;
	private static Memory GMemory;
	private static Address CodeStart;
	private static Address CodeEnd;
	
	//private static ConcurrentLinkedQueue<ScanFail> Failed;
	private static ConcurrentMap<String, String> NotFound;
	
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
		
		var iniConfig = new INIConfiguration();
		var scanIni = askFile("Select the Scan INI file (scans.ini)", "OK");
		HashMap<String, ScanIniEntry> Signatures = new HashMap<>();
		//Failed = new ConcurrentLinkedQueue<>();
		NotFound = new ConcurrentHashMap<>();
		
		var expressionConfig = ExpressionConfiguration.defaultConfiguration()
				.withAdditionalFunctions(
						Map.entry("GetGlobalAddress", new GetGlobalAddressFunction())
						);
		
		try (var reader = new FileReader(scanIni)) {
			iniConfig.read(reader);
			var keyList = iniConfig.getKeys();
			while (keyList.hasNext()) {
				var currentKey = keyList.next();
				if (currentKey.endsWith(ResultKey)) {
					var keySlice = currentKey.substring(0, currentKey.length() - ResultKey.length());
					Signatures.get(keySlice).Transform = new Expression(iniConfig.getString(currentKey), expressionConfig);
				} else {
					var valueStr = iniConfig.getString(currentKey);
					if (!valueStr.equals(DisabledValue)) {
						Signatures.put(currentKey, new ScanIniEntry(valueStr));	
					}
				}
			}
		}
		
		try (ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors())) {
			Signatures.forEach((name, value) -> {
				executor.submit(() -> {
					var searcher = new SignatureSearch(name, new Signature(value.Bytes), value.Transform);
					NotFound.put(name, value.Bytes);
					try {
						var address = searcher.search();
						if (address != null) {
							println("Found " + name + " at " + address.toString());
							NotFound.remove(name);
						} else {
							//Failed.add(new ScanFail(name, value.Bytes));
						}
					} catch (ParseException | EvaluationException e) {
						throw new IllegalArgumentException("Error while evaluating expression for " + name + " : " + e.getMessage());
					}
				});
			});
		}
		println("==================================");
		if (NotFound.isEmpty()) {
			println("All signatures were found!");
		} else {
			println("Found " + NotFound.size() + " broken signatures:");
			for (var fail : NotFound.entrySet()) {
				//println(fail.Name + " : " + fail.Bytes);
				println(fail.getKey() + " : " + fail.getValue());
			}	
		}
	}
}
