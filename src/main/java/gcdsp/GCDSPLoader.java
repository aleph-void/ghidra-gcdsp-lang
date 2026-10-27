/* Apache License 2.0 (see LICENSE.txt).  Ghidra-Rare addition to the GCDSP module. */
package gcdsp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.AddressLabelInfo;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for raw GameCube/Wii DSP microcode ("ucode") dumps, such as the ones Dolphin writes when
 * DumpUCode is enabled: big-endian 16-bit words that are loaded into instruction RAM at inst:0000.
 *
 * It replaces the 25-step manual import of the original module: the image becomes the {@code iram}
 * block, the data memory ({@code dram}, {@code coef}) and the memory-mapped hardware registers
 * ({@code ifx}, data:ff00-ffff) are created, and when the files {@code dsp_rom.bin} and
 * {@code dsp_coef.bin} (Dolphin's free replacement ROM and coefficients, or dumps of the real
 * ones) are in the same folder as the ucode they are loaded into {@code irom} (inst:8000) and
 * {@code coef} (data:1000), so that calls into the boot ROM resolve.
 */
public class GCDSPLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "GameCube/Wii DSP ucode (raw binary)";
	static final String LANG = "GCDSP:BE:16:default";
	static final int IRAM_BYTES = 0x2000;      // 4096 words
	static final int IROM_BYTES = 0x2000;      // 4096 words at inst:8000
	static final int COEF_BYTES = 0x1000;      // 2048 words at data:1000

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 60;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		long n = provider.length();
		// A raw image has no signature: offer the loader for files that fit the instruction RAM,
		// but never as the preferred choice.
		if (n >= 2 && n <= IRAM_BYTES && n % 2 == 0) {
			specs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANG, "default"), false));
		}
		return specs;
	}

	private static void removeBlock(Memory mem, String name, TaskMonitor monitor) throws Exception {
		MemoryBlock b = mem.getBlock(name);
		if (b != null) {
			mem.removeBlock(b, monitor);
		}
	}

	private static byte[] padded(byte[] b, int size) {
		return Arrays.copyOf(b, size);
	}

	@Override
	protected void load(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		Memory mem = program.getMemory();
		AddressSpace inst = program.getAddressFactory().getAddressSpace("inst");
		AddressSpace data = program.getAddressFactory().getAddressSpace("data");
		try {
			for (String n : new String[] { "iram", "irom", "dram", "coef", "ifx" }) {
				removeBlock(mem, n, monitor);
			}
			byte[] code = provider.getInputStream(0).readAllBytes();
			MemoryBlockUtils.createInitializedBlock(program, false, "iram",
				inst.getTruncatedAddress(0, true),
				new ByteArrayInputStream(padded(code, IRAM_BYTES)), IRAM_BYTES,
				"Instruction RAM: the ucode", NAME, true, true, true, log, monitor);

			File dir = provider.getFile() != null ? provider.getFile().getParentFile() : null;
			byte[] rom = sibling(dir, "dsp_rom.bin", IROM_BYTES);
			Address irom = inst.getTruncatedAddress(0x8000, true);
			if (rom != null) {
				MemoryBlockUtils.createInitializedBlock(program, false, "irom", irom,
					new ByteArrayInputStream(rom), IROM_BYTES, "Instruction ROM (dsp_rom.bin)", NAME,
					true, false, true, log, monitor);
			}
			else {
				MemoryBlockUtils.createUninitializedBlock(program, false, "irom", irom, IROM_BYTES,
					"Instruction ROM: add dsp_rom.bin here (Dolphin's free ROM works)", NAME, true,
					false, true, log);
			}
			MemoryBlockUtils.createUninitializedBlock(program, false, "dram",
				data.getTruncatedAddress(0, true), 0x2000, "Data RAM", NAME, true, true, false, log);
			Address coef = data.getTruncatedAddress(0x1000, true);
			byte[] cf = sibling(dir, "dsp_coef.bin", COEF_BYTES);
			if (cf != null) {
				MemoryBlockUtils.createInitializedBlock(program, false, "coef", coef,
					new ByteArrayInputStream(cf), COEF_BYTES, "ADPCM coefficients (dsp_coef.bin)", NAME,
					true, false, false, log, monitor);
			}
			else {
				MemoryBlockUtils.createUninitializedBlock(program, false, "coef", coef, COEF_BYTES,
					"Coefficient ROM: add dsp_coef.bin here (Dolphin's free one works)", NAME, true,
					false, false, log);
			}
			MemoryBlock ifx = MemoryBlockUtils.createUninitializedBlock(program, false, "ifx",
				data.getTruncatedAddress(0xff00, true), 0x200, "Memory-mapped hardware registers", NAME,
				true, true, false, log);
			ifx.setVolatile(true);

			SymbolTable st = program.getSymbolTable();
			for (AddressLabelInfo info : program.getLanguage().getDefaultSymbols()) {
				try {
					st.createLabel(info.getAddress(), info.getLabel(), SourceType.IMPORTED);
					if (info.isEntry()) {
						st.addExternalEntryPoint(info.getAddress());
					}
				}
				catch (Exception e) {
					log.appendMsg(NAME, "symbol " + info.getLabel() + ": " + e.getMessage());
				}
			}
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	/** The named file next to the ucode, if it exists and has exactly {@code size} bytes. */
	private static byte[] sibling(File dir, String name, int size) throws IOException {
		if (dir == null) {
			return null;
		}
		File f = new File(dir, name);
		if (!f.isFile() || f.length() != size) {
			return null;
		}
		return Files.readAllBytes(f.toPath());
	}
}
