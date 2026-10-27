// Prints the p-code of each instruction given as a hex string (4 hex digits per word) in the script args.
//@category Testing
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Language lang = currentProgram.getLanguage();
		Address a = currentProgram.getAddressFactory().getAddressSpace("inst").getTruncatedAddress(0x1000, true);
		for (String line : getScriptArgs()) {
			byte[] b = new byte[line.length() / 2 + 16];
			for (int i = 0; i < line.length() / 2; i++) {
				b[i] = (byte) Integer.parseInt(line.substring(2 * i, 2 * i + 2), 16);
			}
			ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
			ctx.setRegisterValue(currentProgram.getProgramContext().getDefaultDisassemblyContext());
			MemBuffer buf = new ByteMemBufferImpl(a, b, true);
			InstructionPrototype proto = lang.parse(buf, ctx, false);
			PseudoInstruction pi = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
			println(line + ": " + pi + "  (length " + pi.getLength() + ")");
			for (PcodeOp op : pi.getPcode()) {
				println("    " + op);
			}
		}
	}
}
