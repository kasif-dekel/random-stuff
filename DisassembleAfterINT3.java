import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class DisassembleAfterINT3 extends GhidraScript {

	@Override
	public void run() throws Exception {
		Listing listing = currentProgram.getListing();
		InstructionIterator initer = listing.getInstructions(currentProgram.getMemory(), true);
		while (initer.hasNext() && !monitor.isCancelled()) {
			Instruction instruct = initer.next();
			if(instruct.getMnemonicString().contentEquals("INT") && instruct.getDefaultOperandRepresentation(0).equals("3")) { 
				disassemble(instruct.getAddress().add(1));
			}
		}
	}
}
