import java.awt.BorderLayout;
import java.awt.Desktop;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Observable;
import javax.swing.*;

import org.apache.commons.io.IOUtils;

import docking.widgets.EmptyBorderButton;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.InstructionTableDataObject;
import ghidra.app.plugin.core.instructionsearch.model.InstructionTableModel;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData.UpdateType;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTable;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTablePanel;
import ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.OperandType;
import ghidra.util.Msg;
import resources.ResourceManager;


// Author: Kasif Dekel (@kasifdekel)
// Based on GHIDRA's yara plugin
// Current known bugs: near branches gets masked out because OperandType.RELATIVE isn't correctly set by GHIDRA, as a workaround you can use the GUI panel to mask/unmask specific bytes.


public class VTgrepGHIDRA extends GhidraScript {

	public static final int MIN_QUERY_LEN = 10; 
	public static final int MAX_QUERY_LEN = 4096;
	
	private InstructionSearchPlugin plugin;

	private InstructionSearchDialog dialog;
	
	private String currentSTR;


	@Override
	protected void run() throws Exception {

		plugin = InstructionSearchUtils.getInstructionSearchPlugin(state.getTool());

		if (plugin == null) {
			popup("Instruction Pattern Search plugin not installed! Please install and re-run script.");
			return;
		}

		if (currentProgram == null) {
			popup("Please open a program before running this script.");
			return;
		}

		if (currentSelection == null) {
			popup("Please make a valid selection in the program and select 'reload'. Or select the 'manual entry' option from the toolbar.");
		}

		dialog = new YaraDialog();
		state.getTool().showDialog(dialog);

		dialog.loadInstructions(plugin);
	}


	private String generateYaraString(String ruleName) {

		StringBuilder yaraString = new StringBuilder("\n\nrule " + ruleName + "\n");
		yaraString.append("{\n\tstrings:\n");

		String fullStr = "";
		String currStr = "";
		String lc = "";
		boolean isWildcards;

		if (dialog == null || dialog.getSearchData() == null) {
			return null;
		}
		String instrStr = dialog.getSearchData().getCombinedString();

		for (int i = 0; i < instrStr.length(); i += 8) {
			isWildcards = false;
			String curByte = instrStr.length() >= 8 ? instrStr.substring(i, i + 8) : instrStr.substring(i);
			String nibble1 = curByte.length() >= 4 ? curByte.substring(0, 4) : curByte.substring(0);
			String nibble2 = curByte.length() >= 8 ? curByte.substring(4, 8)
					: curByte.length() >= 4 ? curByte.substring(4) : "";

			if (nibble1.contains(".") || nibble2.contains(".")) {
				currStr = "??";
				isWildcards = true;
			}
			else {
				currStr = InstructionSearchUtils.toHex(nibble1, false).trim();
				currStr += InstructionSearchUtils.toHex(nibble2, false).trim();
			}

			if(fullStr.isEmpty()) { 
				fullStr += currStr;
				continue;
			}
			lc = fullStr.substring(fullStr.length() - 1);
			fullStr += (lc.equals("?") ? (isWildcards ? currStr : " " + currStr) : (isWildcards ? " " + currStr : currStr));
			
		}

		currentSTR = fullStr;
		println(currentSTR);
		yaraString.append("\t\t$STR" + 1 + " = { " + fullStr + " }\n");
		yaraString.append("\n\tcondition:\n");
		yaraString.append("\t\t$STR1");
		yaraString.append(" or $STR" + (1));
		yaraString.append("\n}\n");

		return yaraString.toString();
	}


	private class YaraDialog extends InstructionSearchDialog {

		private JTextArea yaraTA;
		JScrollPane scrollPane;

		private JSplitPane verticalSplitter;
 
		private int splitterSave = 200;

		private YaraDialog() {
			super(plugin, "Yara Rule Generator + VTgrepGHIDRA", null);
			revalidate();
			setPreferredSize(500, 400);
		}
		
		private class SearchVTAction extends AbstractAction {
			InstructionTable instructionTable;
			public SearchVTAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
				super(text, icon);
				putValue(SHORT_DESCRIPTION, desc);
				this.instructionTable = instructionTable;
			}

			@Override
			public void actionPerformed(ActionEvent e) {
				
				String toURL = sanitize(reduce_query(currentSTR));
				
				println("DEBUG: toURL: " + toURL); //TODO: remove
				
				if(toURL.length() < MIN_QUERY_LEN || toURL.length() > MAX_QUERY_LEN) { 
					popup("Error! minimum bytes query length should be at least 5 and below 2048!");
					return;
				}
				
				dialog = new InstructionSearchDialog(plugin,"VT Search",null);
				try {
					toURL = URLEncoder.encode(":{ " + toURL + " }", StandardCharsets.UTF_8.toString());
				} catch (UnsupportedEncodingException e1) {
					popup("Error encounted while submitting data to VT.");
					e1.printStackTrace();
				}
				String url = "https://www.virustotal.com/gui/search/content"+ toURL + "/files" ;
				OpenBrowser(url);
				InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
				model.fireTableDataChanged();
			}
		}
		
		
		private class SimilarAction extends AbstractAction {
			InstructionTable instructionTable;
			public SimilarAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
				super(text, icon);
				putValue(SHORT_DESCRIPTION, desc);
				this.instructionTable = instructionTable;
			}

			@Override
			public void actionPerformed(ActionEvent e) {
				
				for (int i = 0; i < this.instructionTable.getRowCount(); i++) {
					for (int j = 0; j < this.instructionTable.getColumnCount(); j++) {
						InstructionTableDataObject obj = this.instructionTable.getCellData(i, j);
						if(obj == null || obj.getOperandCase() == null) { 
							continue;
						}
						if (OperandType.isDataReference(obj.getOperandCase().getOpType()) || OperandType.isScalar(obj.getOperandCase().getOpType()) || (OperandType.isCodeReference(obj.getOperandCase().getOpType()) && !OperandType.isRelative(obj.getOperandCase().getOpType()))) {
							obj.setState(OperandState.MASKED, false);
						}
						
				
					}
				}
				
				InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
				model.fireTableDataChanged();
			}

		}
		
		private class StrictAction extends AbstractAction {
			InstructionTable instructionTable;
			public StrictAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
				super(text, icon);
				putValue(SHORT_DESCRIPTION, desc);
				this.instructionTable = instructionTable;
			}

			@Override
			public void actionPerformed(ActionEvent e) {
				
				for (int i = 0; i < this.instructionTable.getRowCount(); i++) {
					for (int j = 0; j < this.instructionTable.getColumnCount(); j++) {
						InstructionTableDataObject obj = this.instructionTable.getCellData(i, j);
						if(obj == null || obj.getOperandCase() == null) { 
							continue;
						}
						if (OperandType.isAddress(obj.getOperandCase().getOpType()) || OperandType.isDataReference(obj.getOperandCase().getOpType()) || OperandType.isScalar(obj.getOperandCase().getOpType()) || OperandType.isImmediate(obj.getOperandCase().getOpType()) || (OperandType.isCodeReference(obj.getOperandCase().getOpType()) && !OperandType.isRelative(obj.getOperandCase().getOpType()))) {
							obj.setState(OperandState.MASKED, false);
						}
						
					
					}
				}
				
				InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
				model.fireTableDataChanged();
			}

		}
		
		private class CertAction extends AbstractAction {
			InstructionTable instructionTable;
			public CertAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
				super(text, icon);
				putValue(SHORT_DESCRIPTION, desc);
				this.instructionTable = instructionTable;
			}

			@Override
			public void actionPerformed(ActionEvent e) {
				
				check_cert();
				
				InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
				model.fireTableDataChanged();
			}

		}
		
		public void check_cert() { 
			String path = currentProgram.getExecutablePath();
			String stdout = "";
			String stderr = "";
			if(System.getProperty("os.name").toLowerCase().contains("win")) {
				File f = new File(path);
				if(!f.exists()) { //for whatever reason :)
				    popup("Something went wrong while processing this file");
				    return;
				}
				String command = "powershell.exe (Get-AuthenticodeSignature '"+f.getPath()+"').SignerCertificate.Thumbprint";
				Process powerShellProcess;
				try {
					powerShellProcess = Runtime.getRuntime().exec(command);
					powerShellProcess.getOutputStream().close();
					stdout = IOUtils.toString(powerShellProcess.getInputStream(), StandardCharsets.UTF_8).trim();
					stderr = IOUtils.toString(powerShellProcess.getErrorStream(), StandardCharsets.UTF_8).trim();
				} catch (IOException e) {
					popup("Something went wrong while processing this file");
				    return;
				}
				
				if(!stderr.isEmpty() || stdout.isEmpty() || !stdout.matches("^[0-9a-fA-F]+$")) { 
					popup("Something went wrong while processing this file");
				    return;
				}
				
				try {
					stdout = URLEncoder.encode(":\""+stdout+"\"", StandardCharsets.UTF_8.toString());
				} catch (UnsupportedEncodingException e1) {
					popup("Error encounted while submitting data to VT.");
					e1.printStackTrace();
				}
				
				String url = "https://www.virustotal.com/gui/search/signature"+stdout+"/files" ;
				OpenBrowser(url);
				
			} else { 
				popup("Sorry, this feature isn't supported on OSes other than windows!");
			}
			
		}
		
		private void OpenBrowser(String URL) {
	        if(Desktop.isDesktopSupported()){
	            Desktop desktop = Desktop.getDesktop();
	            try {
	                desktop.browse(new URI(URL));
	            } catch (IOException | URISyntaxException e) {
	            	popup("Error!");
	            }
	        }else{
	            Runtime runtime = Runtime.getRuntime();
	            try {
	                runtime.exec("xdg-open " + URL);
	            } catch (IOException e) {
	            	popup("Error encountered while searching VT");
	            }
	        }
		}

		@Override
		protected JPanel createWorkPanel() {

			// Create the main text area and give it a scroll bar. 
			yaraTA = new JTextArea(12, 0);
			scrollPane = new JScrollPane(yaraTA);
			yaraTA.setWrapStyleWord(true);
			yaraTA.setLineWrap(true);

			// Create the instruction table and set it as a listener of the table model, so 
			// this gui will be notified when changes have been made (when the user has adjusted
			// the mask settings).  This allows us to dynamically update the yara string as 
			// the user is changing things.
			InstructionTablePanel instructionTablePanel =
				new InstructionTablePanel(searchData.getMaxNumOperands(), plugin, this);
			instructionTablePanel.getTable().getModel().addTableModelListener(e -> {
				generateYara();
			});
			
			

			Icon VTscaledIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/magnifier.png"), 16, 16);
			Action actionVT = new SearchVTAction("VTgrep", VTscaledIcon, "Search using VTgrep", instructionTablePanel.getTable());
			
			
			EmptyBorderButton VTButton = new EmptyBorderButton();
			VTButton.setAction(actionVT);
			VTButton.setName("VTgrep");
			VTButton.setHideActionText(true);
			instructionTablePanel.getTable().getToolbar().add(VTButton);
			

			Icon SimilarIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/checkmark_green.gif"), 16, 16);
			Action actionSimilarCheck = new SimilarAction("SimilarCheck", SimilarIcon, "Generate Similar Query", instructionTablePanel.getTable());
			
			
			EmptyBorderButton SimilarButton = new EmptyBorderButton();
			SimilarButton.setAction(actionSimilarCheck);
			SimilarButton.setName("VTgrep");
			SimilarButton.setHideActionText(true);
			instructionTablePanel.getTable().getToolbar().add(SimilarButton);
			
			Icon StrictIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/notes.gif"), 16, 16);
			Action actionStrictCheck = new StrictAction("StrictCheck", StrictIcon, "Generate Similar Query (Strict)", instructionTablePanel.getTable());
			
			
			EmptyBorderButton StrictButton = new EmptyBorderButton();
			StrictButton.setAction(actionStrictCheck);
			StrictButton.setName("VTgrep");
			StrictButton.setHideActionText(true);
			instructionTablePanel.getTable().getToolbar().add(StrictButton);
			
			
			Icon CertIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/key.png"), 16, 16);
			Action actionCertCheck = new CertAction("CertCheck", CertIcon, "Find files signed by the same certificate", instructionTablePanel.getTable());
			
			
			EmptyBorderButton CertButton = new EmptyBorderButton();
			CertButton.setAction(actionCertCheck);
			CertButton.setName("VTgrep");
			CertButton.setHideActionText(true);
			instructionTablePanel.getTable().getToolbar().add(CertButton);
			
			
			JPanel mainPanel = new JPanel();
			mainPanel.setLayout(new BorderLayout());
			verticalSplitter = new JSplitPane(JSplitPane.VERTICAL_SPLIT, instructionTablePanel.getWorkPanel(), scrollPane);
			mainPanel.add(verticalSplitter);


			searchData.registerForGuiUpdates(instructionTablePanel.getTable());
			verticalSplitter.setDividerLocation(splitterSave);

			return mainPanel;
		}


		private void generateYara() {
			try {
				yaraTA.setText(generateYaraString("<insert name>"));
			}
			catch (Exception e1) {
				Msg.error(this, "Error generating yara string: " + e1);
			}
		}


		@Override
		public void update(Observable o, Object arg) {

			// Before rebuilding the UI, remember the splitter location so we can reset it
			// afterwards.
			if (verticalSplitter != null) {
				splitterSave = verticalSplitter.getDividerLocation();
			}

			if (arg instanceof UpdateType) {
				UpdateType type = (UpdateType) arg;
				switch (type) {
					case RELOAD:
						revalidate();
						break;
					case UPDATE:
						// do nothing
				}
			}
		}
		
		public ArrayList<Object> generate_slices(String[] sslices) { 
			ArrayList<Object> slices = new ArrayList<Object>();
			for(String sslice: sslices) { 
				if(sslice.contains("?")) { 
					slices.add(new Wildcards(sslice));
				} else { 
					slices.add(new Bytes(sslice));
				}
			}
			
			return slices;
			
		}
		
		public ArrayList<Object> reduce_query(String str) {

			ArrayList<Object> query_slices = generate_slices(str.split(" "));
			ArrayList<Object> reduced_list = new ArrayList<Object>();
			
			int prev = 0;
			for(Object current: query_slices) { 
				if(reduced_list.isEmpty()) { 
					reduced_list.add(current);
				} else { 
					prev = reduced_list.size() - 1;
					if(reduced_list.get(prev) instanceof Wildcards) { 
						if(((Wildcards)reduced_list.get(prev)).combinable(current)) { 
							reduced_list.set(prev, ((Wildcards)reduced_list.get(prev)).combine(current));
						} else { 
							reduced_list.add(current);
						}
						
					}
					
					if(reduced_list.get(prev) instanceof Bytes) { 
						if(((Bytes)reduced_list.get(prev)).combinable(current)) { 
							reduced_list.set(prev, ((Bytes)reduced_list.get(prev)).combine(current));
						} else { 
							reduced_list.add(current);
						}
					}
				}
				
				String toURL = "";
				for(Object curr: reduced_list) { 
					if(curr instanceof Wildcards) { 
						toURL += ((Wildcards) curr).get();
					} else { 
						toURL += ((Bytes) curr).get();
					}
				}
			}
			
			return reduced_list;
		}
		
		public String sanitize(ArrayList<Object> query) { 
			
			boolean Modified = true;
			String outputSTR = "";
			int query_len;
			int qslice_index;
			int next_qslice_index;
			Object next_qslice;
			Object qslice;
			
			while(Modified) { 
				Modified = false;
				query_len = query.size();
				qslice_index = 0;
				
				for(; qslice_index < query_len; qslice_index++) { 
					next_qslice_index = qslice_index + 1;
					if(next_qslice_index != query_len) { 
						next_qslice = query.get(next_qslice_index);
						if((boolean)(qslice = check_combinable_and_combine(query.get(qslice_index), next_qslice)) == true) { 
							query.set(qslice_index, qslice);
							query.remove(next_qslice_index);
							Modified = true;
							break;
						}
					} else { 
						if((boolean) check_combinable_and_combine(query.get(qslice_index), null)) { 
							query.remove(qslice_index);
							Modified = true;
							break;
						} 
					}
				}
			}
			
			
			for(Object curr: query) { 
				if(curr instanceof Wildcards) { 
					outputSTR += ((Wildcards) curr).get();
				} else { 
					outputSTR += ((Bytes) curr).get();
				}
			}
			
			return outputSTR;
		}

		public Object check_combinable_and_combine(Object slice, Object next_slice) { 
			if(slice instanceof Bytes) { 
				return check_combinable_and_combine(((Bytes)slice), next_slice);
			}
			return check_combinable_and_combine(((Wildcards)slice), next_slice);
		}
		
		public Object check_combinable_and_combine(Bytes slice, Object next_slice) { 
			if(slice.combinable(next_slice)) { 
				return slice.combine(next_slice);
			}
			
			return false;
		}
		
		public Object check_combinable_and_combine(Wildcards slice, Object next_slice) { 
			if(slice.combinable(next_slice)) { 
				slice.combine(next_slice);
				return true;
			}
			
			return false;
		}
		
		

		@Override
		protected void revalidate() {
			removeWorkPanel();
			addWorkPanel(createWorkPanel());
			generateYara();
		}
	}

	private class Bytes { 
		private String bytes_stream;
		
		public Bytes(String str) { 
			this.bytes_stream = str;
		}
		
		public void append(Object qslice) { 
			if(qslice instanceof Bytes) { 
				this.bytes_stream += ((Bytes) qslice).get();
			} else { 
				this.bytes_stream += qslice;
			}
			
		}

		public String get() { 
			return this.bytes_stream;
		}
		
		public int len() { 
			return this.bytes_stream.length();
		}
		

		
		public boolean combinable(Object next_qslice) { 
			if(next_qslice != null) { 
				if(next_qslice instanceof Bytes == false && this.len() >= 8) { 
					return false;
				}
			} else if(this.len() >= 8) { 
				return false;
			}
			return true;
		}
		
		public Object combine(Object next_qslice) { 
			String wcs_stream;
			if(next_qslice != null) { 
				if(next_qslice instanceof Bytes || next_qslice instanceof String) { 
					this.append(next_qslice);
					return this;
				}
				wcs_stream = "?".repeat(this.len());
				((Wildcards) next_qslice).append(wcs_stream);
				return next_qslice;
			}
			return this;
		}

	}

	private class Wildcards { 
		private String wcs_stream;
		private boolean packed = false;
		
		public Wildcards(String str) {
			this.wcs_stream = str;
			this.pack();
		}
		
		private void append(Object qslice) { 
			int wcs_len;
			int wcs_count;
			if(!this.packed && qslice instanceof Wildcards == false) { 
				this.wcs_stream += qslice;
				this.pack();
			} else {
				if(qslice instanceof Wildcards) { 
					wcs_len = this.len() + ((Wildcards) qslice).len();
				} else { 
					wcs_len = this.len() + ((String) qslice).length();
				}
				
				wcs_count = wcs_len / 2;
				this.wcs_stream = "["+wcs_count+"]" + "?".repeat(wcs_len % 2);
				this.packed = true;
			}
		}
		
		private String get() { 
			return this.wcs_stream;
		}
		
		private int len() { 
			int str_len = 0;
			String  wcs_len;
			int question_index;
			
			if(this.packed) { 
				wcs_len = this.wcs_stream.replaceAll("^\\[", "").replaceAll("\\]$", "");
				//TODO: check the index of "?"
				question_index = this.wcs_stream.indexOf("?");
				if(question_index != -1) { 
					str_len = Integer.parseInt(wcs_len.replaceAll("\\]?$", "")) * 2;
					str_len++;
				} else { 
					str_len = Integer.parseInt(wcs_len) * 2;
				}
				
				return str_len;
				
			}
			return this.wcs_stream.length();
		}
		
		private void pack() {
			int wcs_len;
			int wcs_count;
			if(!this.packed) { 
				wcs_len = this.wcs_stream.length();
				if(wcs_len > 3) { 
					wcs_count = (wcs_len / 2);
					this.wcs_stream = "["+wcs_count+"]" + "?".repeat(wcs_len % 2);
					this.packed = true;
				}
			}
		}
		
		private boolean combinable(Object next_slice) { 
			if(next_slice != null) { 
				if(next_slice instanceof Bytes && ((Bytes)next_slice).len() >= 8) { 
					return false;
				}
			}
			return true; //????
		}
		
		private Object combine(Object next_slice) { 
			String wcs_stream;
			if(next_slice != null) { 
				if(next_slice instanceof Bytes) { 
					wcs_stream = "?".repeat(((Bytes)next_slice).len());
					this.append(wcs_stream);
				} else { 
					this.append(next_slice);
				}
				
			}
			return this;
		}
		
	}
}
