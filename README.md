# GTA_PS3_IDA_Native_Label_Maker
Some code for creating a script to label all the natives in ida.

1. Run webpage which will generate the cross-map between the leaked native names (natives_leaked_names.json), 64 bit hashes, and 32 bit hashes (natives.json). This does not need to be ran again. Output is currently in 2 file formats: natives_cross_names.csv and native_cross_names.json

2. In IDA (ps3) run ida_gta_ps3_output_natives.py which will spit out a CSV in the console that you need to copy to a file native_addresses.csv, this contains the addresses of all the natives. You will have to update the native function addresses for your version of gta.

3. Run the java file. This will combine the native addresses file and the crossmap csv to output a .idc script file which can be ran in ida which will label all the natives
