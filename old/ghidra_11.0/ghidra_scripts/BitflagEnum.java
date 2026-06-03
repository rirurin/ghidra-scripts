import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Type;
import java.util.LinkedList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.stream.JsonReader;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;

public class BitflagEnum extends GhidraScript {
	
	private Gson gson;
	
	public class BitflagEntry {
		public String Name;
		public int Value;
		public String Description;
		
		public BitflagEntry(String Name, int Value, String Description) {
			this.Name = Name;
			this.Value = Value;
			this.Description = Description;
		}
	}
	
	public class BitflagEntryDeserializer implements JsonDeserializer<BitflagEntry> {
		@Override
		public BitflagEntry deserialize(JsonElement json, Type typeOf, JsonDeserializationContext ctx)
				throws JsonParseException {
			JsonObject obj = json.getAsJsonObject();
			return new BitflagEntry(
					obj.get("Name").getAsString(), 
					obj.get("Value").getAsInt(),
					obj.get("Description").getAsString()
			);
		}
	}
	
	public class BitflagSection {
		public String Name;
		public String Description;
		public List<BitflagEntry> Entries;
		
		public BitflagSection(String Name, String Description, List<BitflagEntry> Entries) {
			this.Name = Name;
			this.Description = Description;
			this.Entries = Entries;
		}
	}
	
	public class BitflagSectionDeserializer implements JsonDeserializer<BitflagSection> {
		@Override
		public BitflagSection deserialize(JsonElement json, Type typeOf, JsonDeserializationContext ctx)
				throws JsonParseException {
			JsonObject obj = json.getAsJsonObject();
			String name = obj.get("Name").getAsString();
			JsonArray members = obj.get("Members").getAsJsonArray();
			List<BitflagEntry> memberList = new LinkedList<>();
			for (int i = 0; i < members.size(); i++) {
				memberList.add(gson.fromJson(members.get(i), BitflagEntry.class));
			}
			String description = obj.get("Description").getAsString();
			return new BitflagSection(name, description, memberList);
		}
	}
	
	public class LibraryJson {
		public BitflagSection Event;
		public BitflagSection Community;
		public BitflagSection Field;
		public BitflagSection Battle;
		public BitflagSection System;
		public BitflagSection DLC;
		public BitflagSection Counts;
		
		public LibraryJson(
				BitflagSection Event, BitflagSection Community,
				BitflagSection Field, BitflagSection Battle,
				BitflagSection System, BitflagSection DLC,
				BitflagSection Counts
			) {
			this.Event = Event;
			this.Community = Community;
			this.Field = Field;
			this.Battle = Battle;
			this.System = System;
			this.DLC = DLC;
		}
	}
	
	public class LibraryJsonDeserializer implements JsonDeserializer<LibraryJson> {
		@Override
		public LibraryJson deserialize(JsonElement json, Type typeOf, JsonDeserializationContext ctx)
				throws JsonParseException {
			JsonArray obj = json.getAsJsonArray();
			return new LibraryJson(
					gson.fromJson(obj.get(0), BitflagSection.class),
					gson.fromJson(obj.get(1), BitflagSection.class),
					gson.fromJson(obj.get(2), BitflagSection.class),
					gson.fromJson(obj.get(3), BitflagSection.class),
					gson.fromJson(obj.get(4), BitflagSection.class),
					gson.fromJson(obj.get(5), BitflagSection.class),
					gson.fromJson(obj.get(6), BitflagSection.class)
				);
		}
	}

	@Override
	public void run() throws Exception {
		
		gson = new GsonBuilder()
				.registerTypeAdapter(BitflagEntry.class, new BitflagEntryDeserializer())
				.registerTypeAdapter(BitflagSection.class, new BitflagSectionDeserializer())
				.registerTypeAdapter(LibraryJson.class, new LibraryJsonDeserializer())
				.create();
		
		File enumJson = askFile("Get enum.json file", "OK");
		String typePath = askString("Set file path for new enum", "OK");
		var flags = new EnumDataType(new CategoryPath(typePath), "Bitflags", 4); // sizeof(uint)
		var counts = new EnumDataType(new CategoryPath(typePath), "Counts", 4); // sizeof(uint)
		BufferedReader fileReader = new BufferedReader(new FileReader(enumJson));
		JsonReader json_read = gson.newJsonReader(fileReader);
		LibraryJson imported = gson.fromJson(json_read, LibraryJson.class);
		
		for (var Flag : imported.Event.Entries ) {
			flags.add(Flag.Name, Flag.Value);
		}
		for (var Flag : imported.Community.Entries ) {
			flags.add(Flag.Name, Flag.Value);
		}
		for (var Flag : imported.Field.Entries ) {
			flags.add(Flag.Name, Flag.Value);
		}
		for (var Flag : imported.Battle.Entries ) {
			flags.add(Flag.Name, Flag.Value);
		}
		for (var Flag : imported.System.Entries ) {
			flags.add(Flag.Name, Flag.Value);
		}
		for (var Flag : imported.DLC.Entries ) {
			flags.add(Flag.Name, Flag.Value);
		}
		
		/*
		for (var Count : imported.Counts.Entries ) {
			counts.add(Count.Name, Count.Value);
		}
		*/
		
		currentProgram.getDataTypeManager().addDataType(flags, null);
		//currentProgram.getDataTypeManager().addDataType(counts, null);
	}
}
