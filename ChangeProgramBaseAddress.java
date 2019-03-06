import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import javax.swing.JOptionPane;

// didn't find a way to do this throught the ghidra GUI :O

public class ChangeProgramBaseAddress extends GhidraScript {

    @Override
    public void run() throws Exception {
    	
    	Program program = currentProgram;
    	
    	Address ba = askAddress("Base Address", "Enter new base address (hex, don't use 0x)");
    	program.setImageBase(ba, true);
    	JOptionPane.showMessageDialog(null,"updated base address to " +  ba.toString(),"Sucess", JOptionPane.INFORMATION_MESSAGE);

	

    }

}
