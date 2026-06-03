//
//@author Rirurin
//@category Metaphor: Refantazio
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import docking.options.OptionsService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class PrintFunctionSignatures extends GhidraScript {
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
	
	//private Namespace GetOrMakeNamespace(String fullName) throws InvalidInputException, DuplicateNameException {
	private Namespace GetNamespace(String fullName) {
		Namespace ParentNamespace = currentProgram.getGlobalNamespace();
		for (var part : GetNamespaceParts(fullName)) {
			Namespace CurrNamespace = currentProgram.getSymbolTable().getNamespace(part, ParentNamespace);
			//Namespace CurrNamespace = currentProgram.getSymbolTable().getOrCreateNameSpace(ParentNamespace, part, SourceType.ANALYSIS);
			ParentNamespace = CurrNamespace;
		}
		return ParentNamespace;
	}
	
	private String TransformDataTypeName(String name) {
		Boolean containsPointer = false;
		if (name.endsWith("*")) {
			containsPointer = true;
			//name = "*const " + name.substring(0, name.length() - 2);
		} else if (name.equals("UUIC_Parts_Base")) {
			return "PartsBase";
		} else if (
				name.equals("undefined") ||
				name.equals("byte") || 
				name.equals("char")
		) {
			return "u8";
		} else if (name.equals("pointer")) {
			return "usize";
		} else if (name.equals("ulonglong") || name.equals("undefined8")) {
			return "u64";
		} else if (name.equals("longlong")) {
			return "i64";
		} else if (name.equals("uint") || name.equals("undefined4")) {
			return "u32";
		} else if (name.equals("int")) {
			return "i32";
		} else if (name.equals("ushort") || name.equals("undefined2")) {
			return "u16";
		} else if (name.equals("short")) {
			return "i16";
		}
		if (containsPointer) {
			name = "*const " + name.substring(0, name.length() - 2);
		}
		return name;
	}
	
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decomplib = new DecompInterface();
        
		DecompileOptions options;
		options = new DecompileOptions(); 
		OptionsService service = state.getTool().getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null,opt,program);
			options.setNameTransformer(null);
		}
        decomplib.setOptions(options);
        
		decomplib.toggleCCode(true);
		decomplib.toggleSyntaxTree(true);
		decomplib.setSimplificationStyle("decompile");
		
		return decomplib;
	}
	
    public DecompileResults decompileFunction(Function f, DecompInterface decomplib) {
        return decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), monitor);
    }
    
    public class VtableFunction {
    	public LinkedList<String> ParamTypes;
    	public LinkedList<String> ParamNames;
    	public String ReturnType;
    	public int Index;
    	
    	public VtableFunction(Address address, DecompInterface decomplib, int index) {
    		var function = currentProgram.getListing().getFunctionAt(address);
    		var result = decompileFunction(function, decomplib);
    		var proto = result.getHighFunction().getFunctionPrototype();
    		ParamTypes = new LinkedList<String>();
    		ParamNames = new LinkedList<String>();
    		ReturnType = TransformDataTypeName(proto.getReturnType().toString().trim());
    		Index = index;
    		if (proto.getNumParams() > 1) {
    			for (int i = 1; i < proto.getNumParams(); i++) {
    				var param = proto.getParam(i);
    				var dataTypeName = TransformDataTypeName(param.getDataType().toString().trim());
    				ParamTypes.add(dataTypeName);
    				var paramName = param.getName();
    				ParamNames.add(paramName);
    			}
    		}
    	}
    	
    	@Override
    	public String toString() {
    		var funcDef = "fn vtable_" + this.Index + "(&self";
    		for (int i = 0; i < ParamTypes.size(); i++) {
    			var paramName = ParamNames.get(i);
    			var paramType = ParamTypes.get(i);
				funcDef += ", " + paramName + ": " + paramType;
			}
    		funcDef += ")";
    		if (!ReturnType.equals("void")) {
    			funcDef += " -> " + ReturnType;
    		}
    		funcDef += " {\n\tunsafe {\n";
    		funcDef += "\t\tlet vtable_func = self.get_cpp_vtable().add(" + Index + " * size_of::<usize>());\n";
    		funcDef += "\t\tlet vtable_func = *std::mem::transmute::<_, *const fn(&Self";
    		for (String param : ParamTypes) {
    			funcDef += ", " + param;
    		}
    		funcDef += ")";
    		if (!ReturnType.equals("void")) {
    			funcDef += " -> " + ReturnType;
    		}
    		funcDef += ">(vtable_func);\n";
    		funcDef += "\t\t(vtable_func)(self";
    		for (String param : ParamNames) {
    			funcDef += ", " + param;
    		}
    		funcDef += ")\n";
    		funcDef += "\t}\n";
    		funcDef += "}\n";
    		return funcDef;
    	}
    	
    	public Boolean IsSelfOnly() {
    		return ParamTypes.isEmpty() && ParamNames.isEmpty();
    	}
    	
    	public void SetParamTypes(LinkedList<String> _ParamTypes ) {
    		ParamTypes = _ParamTypes;
    	}
    	public void SetParamNames(LinkedList<String> _ParamNames ) {
    		ParamNames = _ParamNames;
    	}
    	public void SetReturnType(String _ReturnType ) {
    		ReturnType = _ReturnType;
    	}
    }
    
    /*
    public void PrintVtableEntry(Address address, DecompInterface decomplib, int index) {
		var function = currentProgram.getListing().getFunctionAt(address);
		var result = decompileFunction(function, decomplib);
		var proto = result.getHighFunction().getFunctionPrototype();
		var funcDef = "fn vtable_" + index + "(&self";
		var paramTypes = new LinkedList<String>();
		var paramNames = new LinkedList<String>();
		var returnType = TransformDataTypeName(proto.getReturnType().toString().trim());
		if (proto.getNumParams() > 1) {
			funcDef += ", ";
			for (int i = 1; i < proto.getNumParams(); i++) {
				var param = proto.getParam(i);
				var dataTypeName = TransformDataTypeName(param.getDataType().toString().trim());
				paramTypes.add(dataTypeName);
				var paramName = param.getName();
				paramNames.add(paramName);
				funcDef += paramName + ": " + dataTypeName;
				if (i < proto.getNumParams() - 1) {
					funcDef += ", ";
				}
			}
		}
		funcDef += ")";
		if (!proto.getReturnType().getName().equals("void")) {
			funcDef += " -> " + returnType + " {\n";
		}
		funcDef += "\tunsafe {\n";
		funcDef += "\t\tlet vtable_func = self.get_cpp_vtable().add(" + index + " * size_of::<usize>());\n";
		funcDef += "\t\tlet vtable_func = *std::mem::transmute::<_, *const fn(&Self";
		for (String param : paramTypes) {
			funcDef += ", " + param;
		}
		funcDef += ")";
		if (!proto.getReturnType().getName().equals("void")) {
			funcDef += " -> " + returnType;
		}
		funcDef += ">(vtable_func);\n";
		funcDef += "\t\t(vtable_func)(self";
		for (String param : paramNames) {
			funcDef += ", " + param;
		}
		funcDef += ")\n";
		funcDef += "\t}\n";
		funcDef += "}\n";
		println(funcDef);
    }
    */

	@Override
	protected void run() throws Exception {
		File OutFile = askDirectory("Get Output File", "Ok");
		DecompInterface decomplib = setUpDecompiler(currentProgram);
		if (!decomplib.openProgram(currentProgram)) {
    		println("Decompile Error: " + decomplib.getLastMessage());
    		return;
    	}
		HashMap<Integer, VtableFunction> functions = new HashMap<>();
		//ArrayList<VtableFunction> functions = new ArrayList<>();

		// Look for the base Boss class and any classes inside of btl::boss.
		// Run with base boss first, then go through each specialized boss to
		// determine the signature for some overriden methods.
		//var boss_vtable = currentProgram.getSymbolTable().getSymbols("vtable", GetNamespace("btl::Boss"));
		var boss_vtable = currentProgram.getSymbolTable().getSymbols("vtable", GetNamespace("app::fld::fldChara"));
		var vtable_data = currentProgram.getListing().getDataAt(boss_vtable.get(0).getAddress());
		for (int i = 0; i < vtable_data.getNumComponents(); i++) {
			var comp = vtable_data.getComponent(i);
			functions.put(i, new VtableFunction(toAddr(comp.getValue().toString()), decomplib, i));
			//functions.add(new VtableFunction(toAddr(comp.getValue().toString()), decomplib, i));
			println(boss_vtable.get(0).getParentNamespace().getName() + " : Func " + i);
		}
		if (false) {
		//var child_bosses = currentProgram.getSymbolTable().getSymbols(GetNamespace("btl::boss"));
		var child_bosses = currentProgram.getSymbolTable().getSymbols(GetNamespace("btl::support"));
		for (Symbol child : child_bosses) {
			//var child_vtable = currentProgram.getSymbolTable().getSymbols("vtable", GetNamespace("btl::boss::" + child.getName()));
			var child_vtable = currentProgram.getSymbolTable().getSymbols("vtable", GetNamespace("btl::support::" + child.getName()));
			var child_data = currentProgram.getListing().getDataAt(child_vtable.get(0).getAddress());
			for (int i = 0; i < functions.size(); i++) {
				var comp = child_data.getComponent(i);
				if (functions.get(i).IsSelfOnly()) {
					var ReplacementMaybe = new VtableFunction(toAddr(comp.getValue().toString()), decomplib, i);
					if (!ReplacementMaybe.IsSelfOnly() ) {
						/*
						functions.get(i).SetParamTypes(ReplacementMaybe.ParamTypes);
						functions.get(i).SetParamNames(ReplacementMaybe.ParamNames);
						functions.get(i).SetReturnType(ReplacementMaybe.ReturnType);
						*/
						functions.replace(i, ReplacementMaybe);
						println("Replaced function " + i + " with implementation from " + child_vtable.get(0).getParentNamespace().getName());
						println(ReplacementMaybe.toString());
					}
					//println(child_vtable.get(0).getParentNamespace().getName() + " : Check Func " + i);
				}
			}
		}
		}
		//try (BufferedWriter fileWriter = new BufferedWriter(new FileWriter(new File(OutDirectory, "out_boss_vtable.txt")))) {
		try (BufferedWriter fileWriter = new BufferedWriter(new FileWriter(OutFile))) {
			for (int i = 0; i < vtable_data.getNumComponents(); i++) {
				fileWriter.write(functions.get(i).toString());
			}
		}
	}
}
 