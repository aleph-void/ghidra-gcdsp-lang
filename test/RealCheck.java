// Real-code check: after import and auto-analysis, writes
//   <out>.insns   one "<word-address-hex> <text>" line per instruction in the listing
//   <out>.txt     counts: instructions, functions, bad-instruction / error bookmarks, decompile failures
// Script args: <out-prefix> [decompile=1|0]
//@category Testing

import java.io.PrintStream;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Bookmark;
import java.util.Iterator;

public class RealCheck extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		boolean decomp = args.length < 2 || !args[1].equals("0");
		PrintStream ins = new PrintStream(args[0] + ".insns");
		int n = 0;
		for (Instruction i : currentProgram.getListing().getInstructions(true)) {
			StringBuilder hex = new StringBuilder();
			for (byte b : i.getBytes()) {
				hex.append(String.format("%02x", b));
			}
			ins.printf("%04x\t%s\t%s%n", i.getAddress().getAddressableWordOffset(), hex, i);
			n++;
		}
		ins.close();
		int funcs = 0, fails = 0, timeouts = 0;
		StringBuilder failed = new StringBuilder();
		DecompInterface di = new DecompInterface();
		if (decomp) {
			di.openProgram(currentProgram);
		}
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			funcs++;
			if (!decomp) {
				continue;
			}
			DecompileResults r = di.decompileFunction(f, 60, monitor);
			if (!r.decompileCompleted()) {
				if (r.isTimedOut()) {
					timeouts++;
				}
				else {
					fails++;
				}
				failed.append(f.getName()).append(": ").append(r.getErrorMessage()).append('\n');
			}
		}
		int bad = 0, err = 0, warn = 0;
		StringBuilder badList = new StringBuilder();
		Iterator<Bookmark> bi = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (bi.hasNext()) {
			Bookmark b = bi.next();
			if (b.getType().getTypeString().equals("Error")) {
				if (b.getCategory().contains("Bad Instruction")) {
					bad++;
					badList.append("bad ").append(Long.toHexString(b.getAddress().getAddressableWordOffset())).append(' ').append(b.getComment()).append('\n');
				}
				else {
					err++;
				}
			}
			else if (b.getType().getTypeString().equals("Warning")) {
				warn++;
			}
		}
		PrintStream out = new PrintStream(args[0] + ".txt");
		out.printf("instructions %d%nfunctions %d%nbad-instruction-bookmarks %d%nother-error-bookmarks %d%nwarning-bookmarks %d%ndecompile-failures %d%ndecompile-timeouts %d%n",
			n, funcs, bad, err, warn, fails, timeouts);
		out.print(badList);
		out.print(failed);
		out.close();
	}
}
