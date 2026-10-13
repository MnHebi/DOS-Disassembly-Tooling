// Read-only export of one analyzed Ghidra function to a compact JSON record.
//
// Invoked by DDT through analyzeHeadless in process mode:
//   analyzeHeadless <project_dir> <project_name> \
//     -process <program> -readOnly -noanalysis \
//     -postScript ExportFunction.java <function_address> <out.json>
//
// The script never writes to the program database; it only reads the loaded
// program and writes the requested JSON file. Ghidra memory bytes and original
// executable file offsets are reported as separate fields.
//
// @category DDT

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class ExportFunction extends GhidraScript {

    private static final String SCHEMA = "ddt.ghidra-function.v1";
    private static final int MAX_INSTRUCTIONS = 20000;
    private static final int MAX_REFERENCES = 20000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            writeError("usage: ExportFunction <function_address> <out.json>");
            return;
        }
        String addressArg = args[0];
        File outFile = new File(args[1]);
        try {
            Map<String, Object> root = buildRecord(addressArg);
            writeJson(outFile, root);
            println("DDT export written to " + outFile.getAbsolutePath());
        }
        catch (Exception e) {
            writeError(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private Map<String, Object> buildRecord(String addressArg) throws Exception {
        Function function = findFunction(addressArg);
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schema", SCHEMA);
        root.put("ghidra", ghidraInfo());
        root.put("program", programInfo());
        root.put("function", functionInfo(function));
        root.put("provenance", provenance());
        List<Object> limits = new ArrayList<>();
        limits.add("Instruction bytes are Ghidra memory bytes, not guaranteed original file bytes");
        limits.add("Incoming references are reported for the entry point only");
        limits.add("File offsets are present only where Ghidra recorded an import source mapping");
        root.put("limits", limits);
        return root;
    }

    private Function findFunction(String addressArg) throws Exception {
        Address address = currentProgram.getAddressFactory().getAddress(addressArg);
        if (address == null) {
            throw new IllegalArgumentException("unparseable Ghidra address: " + addressArg);
        }
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            throw new IllegalArgumentException("no function with entry point at " + addressArg);
        }
        return function;
    }

    private Map<String, Object> ghidraInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("version", safe(() -> Application.getApplicationVersion()));
        info.put("release", safe(() -> Application.getApplicationReleaseName()));
        return info;
    }

    private Map<String, Object> programInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", currentProgram.getName());
        info.put("executable_path", currentProgram.getExecutablePath());
        info.put("executable_format", currentProgram.getExecutableFormat());
        info.put("executable_md5", currentProgram.getExecutableMD5());
        info.put("executable_sha256", currentProgram.getExecutableSHA256());
        info.put("language_id", currentProgram.getLanguageID().toString());
        info.put("compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        info.put("image_base", addressString(currentProgram.getImageBase()));
        info.put("default_address_space", currentProgram.getAddressFactory().getDefaultAddressSpace().getName());
        List<Object> spaces = new ArrayList<>();
        for (AddressSpace space : currentProgram.getAddressFactory().getAddressSpaces()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", space.getName());
            entry.put("size_bits", space.getSize());
            entry.put("is_loaded_memory", space.isLoadedMemorySpace());
            entry.put("is_memory", space.isMemorySpace());
            spaces.add(entry);
        }
        info.put("address_spaces", spaces);
        List<Object> blocks = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            blocks.add(blockInfo(block));
        }
        info.put("memory_blocks", blocks);
        return info;
    }

    private Map<String, Object> blockInfo(MemoryBlock block) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", block.getName());
        info.put("start", addressString(block.getStart()));
        info.put("end", addressString(block.getEnd()));
        info.put("size", block.getSize());
        info.put("initialized", block.isInitialized());
        info.put("read", block.isRead());
        info.put("write", block.isWrite());
        info.put("execute", block.isExecute());
        List<Object> sources = new ArrayList<>();
        for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("length", source.getLength());
            entry.put("description", source.getDescription());
            Optional<FileBytes> fileBytes = source.getFileBytes();
            entry.put("file", fileBytes.isPresent() ? fileBytes.get().getFilename() : null);
            entry.put("file_offset", fileBytes.isPresent()
                    ? fileBytes.get().getFileOffset() + source.getFileBytesOffset(source.getMinAddress()) : null);
            sources.add(entry);
        }
        info.put("sources", sources);
        return info;
    }

    private Map<String, Object> functionInfo(Function function) throws Exception {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("entry", addressString(function.getEntryPoint()));
        info.put("name", function.getName());
        AddressSetView body = function.getBody();
        List<Object> ranges = new ArrayList<>();
        AddressRangeIterator rangeIterator = body.getAddressRanges();
        while (rangeIterator.hasNext()) {
            AddressRange range = rangeIterator.next();
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("min", addressString(range.getMinAddress()));
            entry.put("max", addressString(range.getMaxAddress()));
            entry.put("length", range.getLength());
            ranges.add(entry);
        }
        info.put("body_ranges", ranges);
        info.put("non_contiguous", ranges.size() > 1);

        List<Object> instructions = new ArrayList<>();
        List<Object> outgoing = new ArrayList<>();
        List<Object> unresolved = new ArrayList<>();
        int totalInstructions = 0;
        int totalOutgoing = 0;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(body, true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            totalInstructions++;
            Reference[] references = currentProgram.getReferenceManager()
                    .getReferencesFrom(instruction.getAddress());
            boolean resolvedFlow = false;
            for (Reference reference : references) {
                RefType type = reference.getReferenceType();
                boolean isFlow = type.isFlow();
                boolean computed = type.isComputed();
                if (isFlow && !computed) {
                    resolvedFlow = true;
                }
                totalOutgoing++;
                if (outgoing.size() < MAX_REFERENCES) {
                    outgoing.add(referenceInfo(reference));
                }
            }
            FlowType flow = instruction.getFlowType();
            if ((flow.isCall() || flow.isJump()) && !resolvedFlow && unresolved.size() < MAX_REFERENCES) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("address", addressString(instruction.getAddress()));
                entry.put("text", instruction.toString());
                entry.put("flow_type", flow.toString());
                unresolved.add(entry);
            }
            if (instructions.size() < MAX_INSTRUCTIONS) {
                instructions.add(instructionInfo(instruction, resolvedFlow));
            }
        }
        info.put("instruction_count", totalInstructions);
        info.put("instructions_truncated", totalInstructions > instructions.size());
        info.put("instructions", instructions);
        info.put("outgoing_reference_count", totalOutgoing);
        info.put("outgoing_references_truncated", totalOutgoing > outgoing.size());
        info.put("outgoing_references", outgoing);
        info.put("unresolved_flow", unresolved);

        List<Object> incoming = new ArrayList<>();
        ReferenceIterator incomingIterator = currentProgram.getReferenceManager()
                .getReferencesTo(function.getEntryPoint());
        while (incomingIterator.hasNext() && incoming.size() < MAX_REFERENCES) {
            incoming.add(referenceInfo(incomingIterator.next()));
        }
        info.put("incoming_references", incoming);
        return info;
    }

    private Map<String, Object> instructionInfo(Instruction instruction, boolean resolvedFlow) throws Exception {
        Map<String, Object> info = new LinkedHashMap<>();
        Address address = instruction.getAddress();
        info.put("address", addressString(address));
        info.put("bytes", bytesToHex(instruction.getBytes()));
        info.put("length", instruction.getLength());
        info.put("mnemonic", instruction.getMnemonicString());
        info.put("text", instruction.toString());
        info.put("flow_type", instruction.getFlowType().toString());
        info.put("resolved_flow", resolvedFlow);
        Map<String, Object> source = sourceMapping(address);
        info.put("source_file", source.get("file"));
        info.put("source_file_offset", source.get("file_offset"));
        info.put("mapping_known", source.get("file") != null);
        return info;
    }

    private Map<String, Object> referenceInfo(Reference reference) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("from", addressString(reference.getFromAddress()));
        Address to = reference.getToAddress();
        info.put("to", to == null ? null : addressString(to));
        RefType type = reference.getReferenceType();
        info.put("type", type.toString());
        info.put("computed", type.isComputed());
        info.put("flow", type.isFlow());
        info.put("external", reference.isExternalReference());
        info.put("memory", reference.isMemoryReference());
        info.put("offset", reference.isOffsetReference());
        return info;
    }

    private Map<String, Object> sourceMapping(Address address) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("file", null);
        result.put("file_offset", null);
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        if (block == null) {
            return result;
        }
        for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
            if (!source.contains(address)) {
                continue;
            }
            Optional<FileBytes> fileBytes = source.getFileBytes();
            if (fileBytes.isPresent()) {
                result.put("file", fileBytes.get().getFilename());
                result.put("file_offset",
                        fileBytes.get().getFileOffset() + source.getFileBytesOffset(address));
            }
            return result;
        }
        return result;
    }

    private Map<String, Object> provenance() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("bytes_source", "ghidra_memory");
        info.put("note", "Instruction bytes are read from the loaded program image; "
                + "they may differ from original file bytes where a loader applied relocations or patches.");
        info.put("file_offset_basis", "Ghidra MemoryBlockSourceInfo import mapping; "
                + "absent when the address was not imported from a file byte.");
        return info;
    }

    private String addressString(Address address) {
        // Canonical Ghidra form: "seg:off" in the default segmented space,
        // "SPACE::off" in a non-default space. Preserves address-space identity.
        return address.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(Character.forDigit((value >> 4) & 0xF, 16));
            builder.append(Character.forDigit(value & 0xF, 16));
        }
        return builder.toString();
    }

    private interface Supplier {
        String get() throws Exception;
    }

    private static String safe(Supplier supplier) {
        try {
            return supplier.get();
        }
        catch (Exception e) {
            return null;
        }
    }

    private void writeError(String message) throws Exception {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schema", SCHEMA);
        root.put("error", message);
        if (getScriptArgs().length >= 2) {
            writeJson(new File(getScriptArgs()[1]), root);
        }
        println("DDT export error: " + message);
    }

    private static void writeJson(File file, Object value) throws Exception {
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(toJson(value));
            writer.write("\n");
        }
    }

    @SuppressWarnings("unchecked")
    private static String toJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String) {
            return quote((String) value);
        }
        if (value instanceof Boolean || value instanceof Number) {
            return value.toString();
        }
        if (value instanceof Map) {
            StringBuilder builder = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) value).entrySet()) {
                if (!first) {
                    builder.append(",");
                }
                first = false;
                builder.append("\n  ").append(quote(entry.getKey())).append(": ");
                builder.append(indent(toJson(entry.getValue())));
            }
            return builder.append(first ? "}" : "\n}").toString();
        }
        if (value instanceof List) {
            StringBuilder builder = new StringBuilder("[");
            boolean first = true;
            for (Object element : (List<Object>) value) {
                if (!first) {
                    builder.append(",");
                }
                first = false;
                builder.append("\n  ").append(indent(toJson(element)));
            }
            return builder.append(first ? "]" : "\n]").toString();
        }
        return quote(value.toString());
    }

    private static String indent(String text) {
        return text.replace("\n", "\n  ");
    }

    private static String quote(String text) {
        StringBuilder builder = new StringBuilder("\"");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"': builder.append("\\\""); break;
                case '\\': builder.append("\\\\"); break;
                case '\n': builder.append("\\n"); break;
                case '\r': builder.append("\\r"); break;
                case '\t': builder.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        builder.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        builder.append(c);
                    }
            }
        }
        return builder.append("\"").toString();
    }
}
