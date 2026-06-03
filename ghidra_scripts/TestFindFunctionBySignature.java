//
//@author Rirurin
//@category Rirurin/Test
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public class TestFindFunctionBySignature extends GhidraScript {
	
	public static String P3R_GMALLOC_SIGNATURE = "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 50 ?? 33 F6";
	
	public static Memory GMemory;
	
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

	@Override
	protected void run() throws Exception {
		GMemory = currentProgram.getMemory();
		var searcher = new SignatureSearch(new Signature[] { new Signature(P3R_GMALLOC_SIGNATURE) });
		var foundAddress = searcher.search();
		if (foundAddress != null) {
			println("Found signature at " + foundAddress.toString());
		} else {
			println("Could not find signature in executable!");
		}
	}
}