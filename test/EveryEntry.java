// Every-entry decode test: decodes every case in the input file (hex strings, one per line) and
// records which SLEIGH constructors (in every subtable) were used. Prints the constructors never
// reached and a total. Script args: <cases.txt> <outfile> [seen-in.txt] [ctxfield=value ...]
// (the optional seen-in.txt, "-" for none, holds constructor keys already reached by earlier runs)
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.plugin.processors.sleigh.ConstructState;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class EveryEntry extends GhidraScript {

	private final Set<String> seen = new TreeSet<>();

	private static String key(Constructor c) {
		return String.format("%s:%d %s", c.getSourceFile(), c.getLineno(), c.getParent().getName());
	}

	private void walk(ConstructState s) {
		if (s == null || s.getConstructor() == null) {
			return;
		}
		seen.add(key(s.getConstructor()));
		for (int i = 0; i < s.getNumSubStates(); i++) {
			walk(s.getSubState(i));
		}
	}

	@Override
	protected void run() throws Exception {
		// Script args: <outfile> <cases.txt> [ctxfield=value ...] [-- <cases.txt> [ctxfield=value ...]] ...
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[0]);
		SleighLanguage lang = (SleighLanguage) currentProgram.getLanguage();
		Address a = currentProgram.getAddressFactory().getAddressSpace("inst").getTruncatedAddress(0x1000, true);
		long n = 0;
		int pos = 1;
		while (pos < args.length) {
			String cases = args[pos++];
			List<String> ctxs = new ArrayList<>();
			while (pos < args.length && !args[pos].equals("--")) {
				ctxs.add(args[pos++]);
			}
			pos++;
			try (BufferedReader r = new BufferedReader(new FileReader(cases))) {
				String line;
				while ((line = r.readLine()) != null) {
					line = line.trim();
					if (line.isEmpty()) {
						continue;
					}
					byte[] b = new byte[line.length() / 2 + 8];
					for (int i = 0; i < line.length() / 2; i++) {
						b[i] = (byte) Integer.parseInt(line.substring(2 * i, 2 * i + 2), 16);
					}
					ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
					Register cr = lang.getContextBaseRegister();
					if (cr != null && cr != Register.NO_CONTEXT) {
						ctx.setRegisterValue(
							currentProgram.getProgramContext().getDefaultDisassemblyContext());
					}
					for (String c : ctxs) {
						String[] kv = c.split("=");
						ctx.setValue(lang.getRegister(kv[0]), new java.math.BigInteger(kv[1]));
					}
					try {
						MemBuffer buf = new ByteMemBufferImpl(a, b, true);
						InstructionPrototype proto = lang.parse(buf, ctx, false);
						PseudoInstruction ins = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
						walk(((SleighInstructionPrototype) ins.getPrototype()).getRootState());
						n++;
					}
					catch (Exception e) {
						// undecodable
					}
				}
			}
		}
		int total = 0, missed = 0;
		for (Symbol sym : lang.getSymbolTable().getSymbolList()) {
			if (!(sym instanceof SubtableSymbol st)) {
				continue;
			}
			for (int i = 0; i < st.getNumConstructors(); i++) {
				total++;
				String k = key(st.getConstructor(i));
				if (!seen.contains(k)) {
					missed++;
					out.println("NOT REACHED " + k);
				}
			}
		}
		out.printf("every-entry: %d decodes, %d/%d constructors reached, %d not reached%n", n,
			total - missed, total, missed);
		out.close();
	}
}
