//@category Testing
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
public class Probe extends GhidraScript {
	@Override protected void run() throws Exception {
		println("pc=" + currentProgram.getLanguage().getProgramCounter());
		println("default=" + currentProgram.getLanguage().getDefaultSpace());
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		println("pcreg=" + emu.getPCRegister());
		AddressSpace inst = currentProgram.getAddressFactory().getAddressSpace("inst");
		println("spaces=" + java.util.Arrays.toString(currentProgram.getAddressFactory().getAllAddressSpaces()));
		for (var r : currentProgram.getLanguage().getRegisters()) if (r.getName().startsWith("SR_C")) println(r + " " + r.getAddress() + " " + r.getAddressSpace());
	}
}
