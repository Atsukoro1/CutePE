#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <phnt_windows.h>
#include <phnt.h>

#define PE_FILE_SUCCESS 0x0
#define PE_FILE_READ_ERROR 0x1
#define PE_FILE_SIZE_GET_ERROR 0x2
#define PE_FILE_OPEN_ERROR 0x3
#define PE_FILE_INVALID_DOS_HEADER 0x4
#define PE_FILE_INVALID_NT_HEADER 0x5

struct ImportedFunction {
	std::string name;
	WORD hint;
	bool is_ordinal;
	ULONGLONG address;
};

struct ImportedLibrary {
	std::string dll_name;
	std::vector<ImportedFunction> functions;
};

class PEParser
{
public:	
	bool is_64bit;
	PIMAGE_DOS_HEADER pe_dos_header;
	PIMAGE_NT_HEADERS pe_nt_headers;
	PIMAGE_SECTION_HEADER pe_section_headers;
	std::vector<ImportedLibrary> pe_imports;

	PEParser();

	DWORD from_bytes(char* bytes);
	DWORD from_disk(char* path);

protected:
	char* raw_pe_data;

	DWORD parse();
	DWORD parse_import_entries();
	DWORD parse_resource_entries();
	DWORD get_thunk_data_addr(char* thunk_ptr, int index);
	ImportedFunction resolve_thunk_function(ULONGLONG func_ptr);
	PIMAGE_DATA_DIRECTORY get_data_directory(DWORD type);
	DWORD rva_to_offset(DWORD rva);
};