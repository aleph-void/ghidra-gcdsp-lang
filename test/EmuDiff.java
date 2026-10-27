// Runs single instructions (or short sequences) in Ghidra's emulator for the GCDSP test harness.
// Input lines:   id|code hex words|reg=hex,reg=hex,...|space:addr=hexval,...   ('d' data, 'i' inst memory words)
// Output lines:  id|status|pc|reg=hex,...|d:addr=hex,... (data words changed by the run, inst words changed)
// All registers named in REGS are always written (missing ones to 0) so runs are independent.
// Script args: <vectors.txt> <outfile> [steps]
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;

public class EmuDiff extends GhidraScript {
	static final String[] REGS = { "ar0", "ar1", "ar2", "ar3", "ix0", "ix1", "ix2", "ix3", "wr0", "wr1",
		"wr2", "wr3", "st0", "st1", "st2", "st3", "cr", "prod.l", "prod.m1", "prod.h", "prod.m2",
		"ax0.l", "ax0.h", "ax1.l", "ax1.h", "acc0", "acc1" };
	static final String[] SRBITS = { "SR_CARRY_", "SR_OVERFLOW_", "SR_ARITH_ZERO_", "SR_SIGN_",
		"SR_OVER_32_", "SR_TOP2BITS_", "SR_LOGIC_ZERO_", "SR_OVERFLOW_STICKY_", "SR_100_",
		"SR_INT_ENABLE_", "SR_400_", "SR_EXT_INT_ENABLE_", "SR_1000_", "SR_MUL_MODIFY_",
		"SR_40_MODE_", "SR_MUL_UNSIGNED_" };
	static final int[][] WINDOWS = { { 0x100, 0x200 }, { 0xff00, 0xff40 } };
	static final int CODE = 0x8000;

	AddressSpace data, inst;

	Address wa(AddressSpace sp, long w) {
		return sp.getTruncatedAddress(w, true);
	}


	long getReg(EmulatorHelper emu, String n) {
		Register r = currentProgram.getLanguage().getRegister(n);
		BigInteger v = emu.readRegister(r);
		return v.longValue();
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		int steps = args.length > 2 ? Integer.parseInt(args[2]) : 1;
		data = currentProgram.getAddressFactory().getAddressSpace("data");
		inst = currentProgram.getAddressFactory().getAddressSpace("inst");
		PrintStream out = new PrintStream(args[1]);
		EmulatorHelper emu = null;
		List<String> lines = new ArrayList<>();
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String l;
			while ((l = r.readLine()) != null) {
				if (!l.isBlank()) {
					lines.add(l);
				}
			}
		}
		boolean srFake = currentProgram.getLanguage().getRegister("SR_CARRY_") != null;
		int idx = 0;
		for (String line : lines) {
			String[] f = line.split("\\|", -1);
			String id = f[0];
			// the emulator caches decoded instructions by address: every vector gets its own code
			// address, and the emulator is recreated when the code area wraps
			if (emu == null || idx % 3000 == 0) {
				if (emu != null) {
					emu.dispose();
				}
				emu = new EmulatorHelper(currentProgram);
			}
			long codeAddr = CODE + (idx % 3000) * 8L;
			idx++;
			// clear the windows
			for (int[] w : WINDOWS) {
				byte[] z = new byte[(w[1] - w[0]) * 2];
				emu.writeMemory(wa(data, w[0]), z);
				emu.writeMemory(wa(inst, w[0]), z);
			}
			for (String n : REGS) {
				emu.writeRegister(n, BigInteger.ZERO);
			}
			if (srFake) {
				for (String n : SRBITS) {
					emu.writeRegister(n, BigInteger.ZERO);
				}
			}
			byte[] code = new byte[f[1].length() / 2];
			for (int i = 0; i < code.length; i++) {
				code[i] = (byte) Integer.parseInt(f[1].substring(2 * i, 2 * i + 2), 16);
			}
			emu.writeMemory(wa(inst, codeAddr), code);
			if (!f[2].isEmpty()) {
				for (String kv : f[2].split(",")) {
					String[] p = kv.split("=");
					emu.writeRegister(p[0], new BigInteger(p[1], 16));
				}
			}
			if (!f[3].isEmpty()) {
				for (String kv : f[3].split(",")) {
					String[] p = kv.split("=");
					int a = Integer.parseInt(p[0].substring(1), 16);
					int v = Integer.parseInt(p[1], 16);
					AddressSpace sp = p[0].charAt(0) == 'd' ? data : inst;
					emu.writeMemory(wa(sp, a), new byte[] { (byte) (v >> 8), (byte) v });
				}
			}
			emu.writeRegister(emu.getPCRegister(), codeAddr);
			String status = "ok";
			for (int s = 0; s < steps; s++) {
				if (!emu.step(monitor)) {
					status = "err:" + emu.getLastError();
					break;
				}
			}
			StringBuilder sb = new StringBuilder();
			sb.append(id).append('|').append(status).append('|');
			long rel = emu.getExecutionAddress().getAddressableWordOffset() - codeAddr;
			sb.append(rel >= 0 && rel < 16 ? Long.toHexString(rel) : "A" + Long.toHexString(emu.getExecutionAddress().getAddressableWordOffset())).append('|');
			sb.append("ca=").append(Long.toHexString(codeAddr)).append(',');
			boolean first = true;
			List<String> names = new ArrayList<>(List.of(REGS));
			if (srFake) {
				names.addAll(List.of(SRBITS));
			}
			for (String n : names) {
				if (!first) {
					sb.append(',');
				}
				first = false;
				sb.append(n).append('=').append(Long.toHexString(getReg(emu, n)));
			}
			sb.append('|');
			first = true;
			for (int[] w : WINDOWS) {
				for (int a = w[0]; a < w[1]; a++) {
					for (int sp = 0; sp < 2; sp++) {
						byte[] b = emu.readMemory(wa(sp == 0 ? data : inst, a), 2);
						int v = ((b[0] & 0xff) << 8) | (b[1] & 0xff);
						if (v != 0) {
							if (!first) {
								sb.append(',');
							}
							first = false;
							sb.append(sp == 0 ? 'd' : 'i').append(String.format("%04x=%04x", a, v));
						}
					}
				}
			}
			out.println(sb);
		}
		out.close();
		if (emu != null) {
			emu.dispose();
		}
	}
}
