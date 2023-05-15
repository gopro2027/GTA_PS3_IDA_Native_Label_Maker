package com.main;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class make_ida_label {

	static List<String[]> cross = new ArrayList<String[]>();

	public static String[] getNative(String u32) {
		for (String[] sa : cross) {
			if (sa[2].equalsIgnoreCase(u32)) {
				return sa;
			}
		}
		return null;
	}

	public static void main(String[] args) {
		String native_addressesFileLoc = "C:\\Users\\Ty\\Documents\\gta1.12\\native_addresses.csv";//output from the ida script ida_gta_ps3_output_natives.py
		String crossFileLoc = "C:\\Users\\Ty\\Documents\\gta1.12\\native_script_maker\\natives_cross_names.csv";//same for every version
		String outputFile = "C:\\Users\\Ty\\Documents\\gta1.12\\label_natives_1.12.idc";
		String line = "";
		String splitBy = ",";
		try {
			// parsing a CSV file into BufferedReader class constructor
			BufferedReader br = new BufferedReader(new FileReader(crossFileLoc));
			while ((line = br.readLine()) != null) // returns a Boolean value
			{
				cross.add(line.split(splitBy));
				//System.out.println("Employee [First Name=" + employee[0] + ", Last Name=" + employee[1]
				//		+ ", Designation=" + employee[2] + ", Contact=" + employee[3] + ", Salary= " + employee[4]
				//		+ ", City= " + employee[5] + "]");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		StringBuilder sb = new StringBuilder();
		sb.append("#include <idc.idc>\n" + 
				"static main() {\n" );
		
		try {
			// parsing a CSV file into BufferedReader class constructor
			BufferedReader br = new BufferedReader(new FileReader(native_addressesFileLoc));
			while ((line = br.readLine()) != null) // returns a Boolean value
			{
				//cross.add(line.split(splitBy));
				String[] split = line.split(splitBy);
				String s_u32 = split[0];
				String opd = split[1];
				String native_f = split[2];
				String func = split[3];
				
				String[] native_def = getNative(s_u32);
				
				if (native_def != null) {
				
					String nativeName = native_def[0];
					if (nativeName.equalsIgnoreCase("undefined")) {
						nativeName = "n_"+native_def[1]+"_"+native_def[2];
					}
					
					String opd_name = "struct_"+nativeName;
					String native_f_name = "native_"+nativeName;
					String func_name = nativeName;
				
				
					sb.append("    MakeName("+opd+", \""+opd_name+"\");\n");
					sb.append("    MakeName("+native_f+", \""+native_f_name+"\");\n");
					sb.append("    MakeCode("+func+");\n");
					sb.append("    MakeName("+func+", \""+func_name+"\");\n");
				}
			}
			sb.append("}\n");
			try (PrintWriter out = new PrintWriter(outputFile)) {
			    out.println(sb.toString());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}