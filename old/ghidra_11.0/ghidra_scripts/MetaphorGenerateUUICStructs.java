//
//@author Rirurin
//@category Metaphor: Refantazio
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.LinkedList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class MetaphorGenerateUUICStructs extends GhidraScript {
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
	
	private String TransformDataTypeName(String name) {
		if (name.startsWith("SingletonBase")) {
			return "*const u8";
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
		}
		return name;
	}
	
	private String GetSimpleFileName(String name) {
		var parts = name.split("_", 2);
		var shortName = parts[parts.length - 1];
		return shortName.toLowerCase() + ".rs";
	}

	@Override
	protected void run() throws Exception {
		
		File OutDirectory = askDirectory("Get Output Directory", "Ok");
		
		for (Symbol syn: currentProgram.getSymbolTable().getSymbols(GetOrMakeNamespace("app::ui"))) {
			if (syn.getSymbolType().isNamespace() && syn.getName().startsWith("UUIC")) {
				var UUICNamespace = (Namespace)syn.getObject();
				// look for this class's RTTI_Type_Descriptor, so we can get it's mangled name
				var typeInfoSyn = currentProgram.getSymbolTable().getSymbols("RTTI_Type_Descriptor", UUICNamespace);
				if (typeInfoSyn.size() < 1) { throw new IllegalArgumentException("TypeInfo missing for " + UUICNamespace.getName()); }
				var typeInfo = currentProgram.getListing().getDataAt(typeInfoSyn.get(0).getAddress());
				var mangledName = typeInfo.getComponent(2).getValue().toString();
				// Find the corresponding data type, so we can start building the struct output
				var uuicType = (Structure)currentProgram.getDataTypeManager().getDataType(new DataTypePath("/xrd759/ui", UUICNamespace.getName()));
				var structureFields = new LinkedList<String>();
				var structParts = UUICNamespace.getName().split("_", 3); 
				var structName = structParts[structParts.length - 1];
				structureFields.addLast("use allocator_api2::alloc::{ Allocator, Layout };");
				structureFields.addLast("use crate::app::ui::uuic::parts_base::PartsBase;");
				structureFields.addLast("use opengfd::device::ngr::allocator::AllocatorHook;");
				structureFields.addLast("use pm_proc_macro::impl_uuic;");
				structureFields.addLast("");
				structureFields.addLast("#[repr(C)]");
				structureFields.addLast("#[impl_uuic( name = \"" + mangledName + "\", custom_register = false )]");
				structureFields.addLast("pub struct " + structName + "<A = AllocatorHook>");
				structureFields.addLast("where A: Allocator + Clone");
				structureFields.addLast("{");
				var currentOffset = 0;
				var unkSections = 0;
				for (int i = 0; i < uuicType.getNumDefinedComponents(); i++) {
					var comp = uuicType.getComponent(i);
					if (comp.getOffset() - currentOffset > 0) {
						
					}
					var fieldName = comp.getFieldName();
					
					if (fieldName == null) { fieldName = "field" + Integer.toHexString(comp.getOffset()); }
					var fieldFmt = "\t" + fieldName + ": " + TransformDataTypeName(comp.getDataType().getName()) + ",";
					structureFields.addLast(fieldFmt);
				}
				structureFields.addLast("\t_allocator: A");
				structureFields.addLast("}");
				
				try (BufferedWriter fileWriter = new BufferedWriter(new FileWriter(new File(OutDirectory, GetSimpleFileName(uuicType.getName()))))) {					
					for (var field : structureFields) {
						fileWriter.write(field + "\n");
						
						//println(field);	
					}
				}
			}
		}
	}
}
