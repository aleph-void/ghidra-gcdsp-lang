// P-code semantics check for the GCDSP module.  Reads test/emu/cases.txt (expectations worked out by
// hand from the GameCube DSP User's Manual), and for each case writes the code at inst:0x1000 of the
// program, disassembles it (so the loop context of LOOP/BLOOP is set, as in a real analysis), sets
// registers and memory, emulates with Ghidra's EmulatorHelper until the PC reaches the end of the code
// (or the address given by "until"), and compares registers, flags, memory and the PC.
//
// Case format (one directive per line, '#' comments):
//   case <name> [only default|exact] [broken]   "broken" cases carry a deliberately wrong expectation
//   code <hex words>                            words placed at inst:0x1000
//   until <hex-address>                         stop when PC reaches this address (default: end of code)
//   steps <n>                                   or: run exactly n instructions
//   set <reg> <value> | set d:<hex-addr> <value> | set i:<hex-addr> <value>
//   expect <reg> <value> | expect d:<hex-addr> <value> | expect PC <value>
//   end
// Registers are Ghidra register names; the status flags can be written C O Z S AS TB LZ OS AM SXM SU.
// Script args: <cases.txt> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;

public class EmuTest extends GhidraScript {

	private static final Map<String, String> FLAGS = Map.ofEntries(Map.entry("C", "SR_CARRY_"),
		Map.entry("O", "SR_OVERFLOW_"), Map.entry("Z", "SR_ARITH_ZERO_"), Map.entry("S", "SR_SIGN_"),
		Map.entry("AS", "SR_OVER_32_"), Map.entry("TB", "SR_TOP2BITS_"), Map.entry("LZ", "SR_LOGIC_ZERO_"),
		Map.entry("OS", "SR_OVERFLOW_STICKY_"), Map.entry("AM", "SR_MUL_MODIFY_"),
		Map.entry("SXM", "SR_40_MODE_"), Map.entry("SU", "SR_MUL_UNSIGNED_"));

	private static class Case {
		String name;
		String only = "";
		boolean broken;
		int[] code;
		long until = -1;
		int steps = -1;
		Map<String, Long> set = new LinkedHashMap<>();
		Map<String, Long> expect = new LinkedHashMap<>();
	}

	private AddressSpace inst, data;

	private Address wa(AddressSpace sp, long w) {
		return sp.getTruncatedAddress(w, true);
	}

	private List<Case> load(String path) throws Exception {
		List<Case> cases = new ArrayList<>();
		Case c = null;
		try (BufferedReader r = new BufferedReader(new FileReader(path))) {
			String line;
			while ((line = r.readLine()) != null) {
				int h = line.indexOf('#');
				if (h >= 0) {
					line = line.substring(0, h);
				}
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				String[] f = line.split("\\s+");
				switch (f[0]) {
					case "case":
						c = new Case();
						c.name = f[1];
						for (int i = 2; i < f.length; i++) {
							if (f[i].equals("only")) {
								c.only = f[++i];
							}
							else if (f[i].equals("broken")) {
								c.broken = true;
							}
						}
						break;
					case "code":
						c.code = new int[f.length - 1];
						for (int i = 1; i < f.length; i++) {
							c.code[i - 1] = Integer.parseInt(f[i], 16);
						}
						break;
					case "only":
						c.only = f[1];
						break;
					case "until":
						c.until = Long.parseLong(f[1], 16);
						break;
					case "steps":
						c.steps = Integer.parseInt(f[1]);
						break;
					case "set":
						c.set.put(f[1], Long.decode(f[2]));
						break;
					case "expect":
						c.expect.put(f[1], Long.decode(f[2]));
						break;
					case "end":
						cases.add(c);
						break;
					default:
						throw new IllegalArgumentException("bad line: " + line);
				}
			}
		}
		return cases;
	}

	private long readReg(EmulatorHelper emu, String name) {
		String n = FLAGS.getOrDefault(name, name);
		return emu.readRegister(n).longValue();
	}

	private String runCase(Case c) throws Exception {
		Address start = wa(inst, 0x1000);
		int tx = currentProgram.startTransaction("case");
		try {
			byte[] bytes = new byte[c.code.length * 2];
			for (int i = 0; i < c.code.length; i++) {
				bytes[2 * i] = (byte) (c.code[i] >> 8);
				bytes[2 * i + 1] = (byte) c.code[i];
			}
			clearListing(start, wa(inst, 0x1100));
			currentProgram.getMemory().setBytes(start, bytes);
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		disassemble(start);
		long endWord = c.until >= 0 ? c.until : 0x1000 + c.code.length;
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			for (Map.Entry<String, Long> e : c.set.entrySet()) {
				String k = e.getKey();
				if (k.startsWith("d:") || k.startsWith("i:")) {
					long a = Long.parseLong(k.substring(2).replaceFirst("^0x", ""), 16);
					long v = e.getValue();
					emu.writeMemory(wa(k.charAt(0) == 'd' ? data : inst, a),
						new byte[] { (byte) (v >> 8), (byte) v });
				}
				else {
					emu.writeRegister(FLAGS.getOrDefault(k, k), BigInteger.valueOf(e.getValue()));
				}
			}
			emu.writeRegister(emu.getPCRegister(), 0x1000);
			int steps = 0;
			while (true) {
				long pc = emu.getExecutionAddress().getAddressableWordOffset();
				if (c.steps >= 0 ? steps >= c.steps : pc == endWord) {
					break;
				}
				if (++steps > 2000) {
					return "did not reach the end (pc " + Long.toHexString(pc) + ")";
				}
				if (!emu.step(monitor)) {
					return "emulation error at " + Long.toHexString(pc) + ": " + emu.getLastError();
				}
			}
			StringBuilder bad = new StringBuilder();
			for (Map.Entry<String, Long> e : c.expect.entrySet()) {
				String k = e.getKey();
				long got;
				if (k.startsWith("d:") || k.startsWith("i:")) {
					byte[] b = emu.readMemory(wa(k.charAt(0) == 'd' ? data : inst,
						Long.parseLong(k.substring(2).replaceFirst("^0x", ""), 16)), 2);
					got = ((b[0] & 0xff) << 8) | (b[1] & 0xff);
				}
				else if (k.equals("PC")) {
					got = emu.getExecutionAddress().getAddressableWordOffset();
				}
				else {
					got = readReg(emu, k);
				}
				if (got != e.getValue()) {
					bad.append(String.format(" %s=0x%x (expected 0x%x)", k, got, e.getValue()));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		inst = currentProgram.getAddressFactory().getAddressSpace("inst");
		data = currentProgram.getAddressFactory().getAddressSpace("data");
		int tx = currentProgram.startTransaction("blocks");
		try {
			currentProgram.getMemory().createInitializedBlock("code", wa(inst, 0x1000), 0x200, (byte) 0,
				monitor, false);
			currentProgram.getMemory().createInitializedBlock("target", wa(inst, 0x2000), 0x200,
				(byte) 0, monitor, false);
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		List<Case> cases = load(args[0]);
		PrintStream out = new PrintStream(args[1]);
		String lang = currentProgram.getLanguageID().getIdAsString();
		String variant = lang.endsWith("exact") ? "exact" : "default";
		int pass = 0, fail = 0, brokenSeen = 0, brokenMissed = 0;
		for (Case c : cases) {
			if (!c.only.isEmpty() && !c.only.equals(variant)) {
				continue;
			}
			String err = runCase(c);
			if (c.broken) {
				if (err != null) {
					brokenSeen++;
					out.println("PASS (broken expectation detected) " + c.name + ": " + err);
				}
				else {
					brokenMissed++;
					out.println("FAIL " + c.name + ": the deliberately wrong expectation passed");
				}
			}
			else if (err == null) {
				pass++;
				out.println("PASS " + c.name);
			}
			else {
				fail++;
				out.println("FAIL " + c.name + ": " + err);
			}
		}
		out.printf("emulation (%s): %d passed, %d failed, broken expectation %s%n", lang, pass,
			fail + brokenMissed, brokenSeen > 0 && brokenMissed == 0 ? "detected" : "NOT detected");
		out.close();
	}
}
