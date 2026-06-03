import ghidra.app.script.GhidraScript;

public class FloatArrayToCSharpDecl extends GhidraScript {

	@Override
	public void run() throws Exception {
		var floats = getDataAt(currentAddress);
		for (int i = 0; i < floats.getNumComponents(); i++) {
			var curr_float = floats.getComponent(i);
			print("{ ");
			for (int j = 0; j < curr_float.getNumComponents(); j++) {
				var curr_curr_float = curr_float.getComponent(j);
				print(curr_curr_float.getValue().toString() + "f");
				if (j < curr_float.getNumComponents() - 1) print(", ");
			}
			print("}");
			if (i < floats.getNumComponents() - 1) print(",");
			println("");
		}
	}
}