// PLEASE READ:

// not complete and might be buggy - work in progress (when i get time)
// still need to support x86 and ARM 
// please excuse my java programming :)




import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Timer;
import java.util.TimerTask;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.DataDirectory;
import ghidra.app.util.bin.format.pe.ExceptionDataDirectory;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.util.Issue;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.IssueListener;
import ghidra.util.task.TaskMonitor;


class TimedTaskMonitor implements TaskMonitor {

	private Timer timer = new Timer();
	private volatile boolean isCancelled;

	TimedTaskMonitor(int timeoutSecs) {
		isCancelled = false;
		timer.schedule(new TimeOutTask(), timeoutSecs * 1000);
	}

	private class TimeOutTask extends TimerTask {
		@Override
		public void run() {
			TimedTaskMonitor.this.cancel();
		}
	}

	@Override
	public boolean isCancelled() {
		return isCancelled;
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// stub
	}

	@Override
	public void setMessage(String message) {
		// stub
	}

	@Override
	public void setProgress(long value) {
		// stub
	}

	@Override
	public void initialize(long max) {
		// stub
	}

	@Override
	public void setMaximum(long max) {
		// stub
	}

	@Override
	public long getMaximum() {
		return 0;
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		// stub
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (isCancelled()) {
			throw new CancelledException();
		}
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		// stub
	}

	@Override
	public long getProgress() {
		return 0;
	}

	@Override
	public void reportIssue(Issue issue) {
		// stub
	}

	@Override
	public void cancel() {
		timer.cancel(); // Terminate the timer thread
		isCancelled = true;
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		// stub
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		// stub
	}

	@Override
	public void addIssueListener(IssueListener listener) {
		// stub
	}

	@Override
	public void removeIssueListener(IssueListener listener) {
		// stub
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		// stub
	}

	@Override
	public boolean isCancelEnabled() {
		return true;
	}

	@Override
	public void clearCanceled() {
		isCancelled = false;
	}
}

public class ParseX64SEHDirectory extends GhidraScript {

	@Override
	public void run() throws Exception {
		
		//add support for ARM and x86.
		
		/*StructureDataType sRuntimeFunction = new StructureDataType("RUNTIME_FUNCTION", 0);
		PointerDataType dwordPtr = new PointerDataType(new DWordDataType());
		sRuntimeFunction.add(dwordPtr,"begin","");
		sRuntimeFunction.add(dwordPtr,"end","");
		sRuntimeFunction.add(dwordPtr,"unwind_info","");
		
		
		CreateStructureCmd csc = null;*/ //for later versions
		
		TimedTaskMonitor ttm = new TimedTaskMonitor(10);
		Memory memory = currentProgram.getMemory();
		Address baseAddr = memory.getMinAddress();

		ByteProvider provider = new MemoryByteProvider(memory, baseAddr);
		
		PortableExecutable pe = null;

		try {
			pe = PortableExecutable.createPortableExecutable(RethrowContinuesFactory.INSTANCE, provider, SectionLayout.MEMORY, false, false);
		}
		catch (Exception e) {
			printerr("Unable to create PE from current program");
			provider.close();
			return;
		}
		

		NTHeader nth = pe.getNTHeader();
		if (nth == null) {
			print("NT Header not found");
			provider.close();
			return;
		}

		
		OptionalHeader oph = nth.getOptionalHeader();
		if (oph == null) {
			print("OP Header not found");
			provider.close();
			return;
		}
		
		
		
		try { 
			oph.processDataDirectories(ttm);
		} catch(Exception e) { 
			System.out.println("only partial results!"); //TODO: handle this correctly.
		}
		
		DataDirectory[] datadirs = oph.getDataDirectories();
		
		
		
		if (datadirs == null) {
			print("Could not find any data directories");
			provider.close();
			return;
		}
		
		ExceptionDataDirectory edd = null;
		
	
		for (DataDirectory datadir : datadirs) {
			if(datadir == null || datadir.getDirectoryName().equals("IMAGE_DIRECTORY_ENTRY_EXCEPTION")) { 
				edd = (ExceptionDataDirectory) datadir;
				break;
			}
		}

		
		if (edd == null) {
			print("Could not find the exception dir");
			provider.close();
			return;
		}
		//System.out.println("size: " + edd.getSize() + " vaddr: " + edd.getVirtualAddress() + " ptr: " + edd.getPointer());
		//printf("%s", edd.getDirectoryName());
		byte[] rfentry = new byte[RUNTIME_FUNCTION.RUNTIME_FUNCTION_SIZE];
		byte[] uientry = new byte[UNWIND_INFO_HEADER.UNWIND_INFO_HEADER_SIZE];
		byte[] sehentry = new byte[SCOPE_ENTRY_HEADER.SCOPE_ENTRY_HEADER_SIZE];
		byte[] seentry = new byte[SCOPE_ENTRY.SCOPE_ENTRY_SIZE];
		RUNTIME_FUNCTION rf = null;
		UNWIND_INFO_HEADER ui = null;
		SCOPE_ENTRY_HEADER seh = null;
		SCOPE_ENTRY se = null;
		Address current_entry = null;
		Address unwind_header = null;
		Address scopeaddr = null;
		try {
			for(int i = 0; i < edd.getSize() / RUNTIME_FUNCTION.RUNTIME_FUNCTION_SIZE; i++) { 
				
				
				current_entry = baseAddr.add(edd.getPointer()+(i*RUNTIME_FUNCTION.RUNTIME_FUNCTION_SIZE));
				
				//csc = new CreateStructureCmd(sRuntimeFunction, current_entry);
				//csc.applyTo(currentProgram);
				
				
				
				memory.getBytes(current_entry, rfentry);
				rf = new RUNTIME_FUNCTION(rfentry);
				
				
				if(!baseAddr.add(rf.begin).isLoadedMemoryAddress() || !baseAddr.add(rf.end).isLoadedMemoryAddress() || !baseAddr.add(rf.data).isLoadedMemoryAddress()) { 
					continue;
				}
				
				
				
				
				
				unwind_header = baseAddr.add(rf.data);
				memory.getBytes(unwind_header, uientry);
				
				ui = new UNWIND_INFO_HEADER(uientry);
				
				int flags = (byte) (ui.version_flags >> 3);
				
				if((flags & 4) != 0 || !((flags & 1) == 0 || (flags & 2) == 0)) { 
					continue;
				}
				
				
				int code_count = ui.count_of_codes;
				
				scopeaddr = unwind_header.add(4 + (code_count * 2));
				scopeaddr = scopeaddr.add(scopeaddr.getUnsignedOffset() % 4); 
				
				if(memory.getBytes(scopeaddr, sehentry) != SCOPE_ENTRY_HEADER.SCOPE_ENTRY_HEADER_SIZE) { 
					System.out.println("awful shit just happened");
					continue;
				}
				
				seh = new SCOPE_ENTRY_HEADER(sehentry);
				
				if(!baseAddr.add(seh.exception_handler).isLoadedMemoryAddress()) { 
					continue;
				}
				
				
				
				if(!disassemble(baseAddr.add(seh.exception_handler))) { 
					//System.out.println("#2");
					continue;
				};
				
				Function fnc = createFunction(baseAddr.add(seh.exception_handler), null);
				fnc = getFunctionAt(baseAddr.add(seh.exception_handler));
				
				if(fnc == null) { 
					//System.out.println("#3");
					continue;
				}
				
				if(!fnc.getName().contains("C_specific_handler") && !fnc.getName().contains("GSHandlerCheck")) { 
					continue;
				}
				
				System.out.println("Begin: " + Integer.toHexString(rf.begin) + " End: " + Integer.toHexString(rf.end) + " Unwind: " + Integer.toHexString(rf.data));
				
				System.out.println("\t Func: " + Integer.toHexString(seh.exception_handler) + " Name: " + fnc.getName());
				
				
				
				for(int sei = 0; sei < seh.number_of_entries; sei++) { 
					memory.getBytes(scopeaddr.add(SCOPE_ENTRY.SCOPE_ENTRY_SIZE * sei + SCOPE_ENTRY_HEADER.SCOPE_ENTRY_HEADER_SIZE), seentry);
					se = new SCOPE_ENTRY(seentry);
					System.out.println("\t\t SCOPEENTRY(" + sei + ") Begin: " + Integer.toHexString(se.begin) + " End: " + Integer.toHexString(se.end) + " Handler: " + Integer.toHexString(se.handler) + " Target: " + Integer.toHexString(se.target));
					disassemble(baseAddr.add(se.target));
					setPostComment(baseAddr.add(se.target), "SEH Handler");
					setPreComment(baseAddr.add(se.begin), "try { //handler: " + baseAddr.add(se.target).toString());
					setPreComment(baseAddr.add(se.end), "} //handler: " + baseAddr.add(se.target).toString());
				}
				

			}
			

		}
		finally {
			provider.close();
		}

	}

}


class RUNTIME_FUNCTION {

	public static int RUNTIME_FUNCTION_SIZE = 12;
    public final int begin;
    public final int end;
    public final int data;

    public RUNTIME_FUNCTION(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        bb.order(ByteOrder.LITTLE_ENDIAN); 

        begin = bb.getInt();
        end = bb.getInt();
        data = bb.getInt();
    }
}


class UNWIND_INFO_HEADER {
	
	public static int UNWIND_INFO_HEADER_SIZE = 4;
    public final byte version_flags;
    public final byte size_of_prolog;
    public final byte count_of_codes;
    public final byte frames;
    
    public UNWIND_INFO_HEADER(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        bb.order(ByteOrder.LITTLE_ENDIAN); 

        version_flags = bb.get();
        size_of_prolog = bb.get();
        count_of_codes = bb.get();
        frames = bb.get();
        
    }
    
    
}


class SCOPE_ENTRY_HEADER {
	
	public static int SCOPE_ENTRY_HEADER_SIZE = 8; 
    public final int exception_handler;
    public final int number_of_entries;

    
    public SCOPE_ENTRY_HEADER(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        bb.order(ByteOrder.LITTLE_ENDIAN); 

        exception_handler = bb.getInt();
        number_of_entries = bb.getInt();

    }
}


class SCOPE_ENTRY {
	
	public static int SCOPE_ENTRY_SIZE = 16;
    public final int begin;
    public final int end;
    public final int handler;
    public final int target;

    
    public SCOPE_ENTRY(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        bb.order(ByteOrder.LITTLE_ENDIAN); 

        begin = bb.getInt();
        end = bb.getInt();
        
        handler = bb.getInt();
        target = bb.getInt();

    }
}
