#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <phnt_windows.h>
#include <phnt.h>

///
/// File parsing status codes
/// 
#define PE_FILE_SUCCESS 0x0
#define PE_FILE_READ_ERROR 0x1
#define PE_FILE_SIZE_GET_ERROR 0x2
#define PE_FILE_OPEN_ERROR 0x3
#define PE_FILE_INVALID_DOS_HEADER 0x4
#define PE_FILE_INVALID_NT_HEADER 0x5

///
///	Section related structs 
///
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

struct ResourceEntry {
	WORD id;
	bool is_directory;
	std::string name;
	DWORD data_ptr;
	std::vector<ResourceEntry> entries;
};

struct RelocEntry {
	DWORD rva;
	WORD type;
};

struct RelocBlock {
	DWORD page_rva;
	std::vector<RelocEntry> entries;
};

class PEParser
{
public:	
	bool is_64bit;
	PIMAGE_DOS_HEADER pe_dos_header;
	PIMAGE_NT_HEADERS pe_nt_headers;
	PIMAGE_SECTION_HEADER pe_section_headers;
	std::vector<ImportedLibrary> pe_imports;
	PIMAGE_RESOURCE_DIRECTORY pe_resource;
	ResourceEntry pe_resource_entries;
	RelocBlock pe_relocation_blocks;

	PEParser();

	DWORD from_bytes(char* bytes);
	DWORD from_disk(char* path);

private:
	///
	/// Variables & functions related to data directories
	///
	PIMAGE_DATA_DIRECTORY export_directory;
	PIMAGE_DATA_DIRECTORY import_directory;
	PIMAGE_DATA_DIRECTORY resource_directory;
	PIMAGE_DATA_DIRECTORY exception_directory;
	PIMAGE_DATA_DIRECTORY security_directory;
	PIMAGE_DATA_DIRECTORY reloc_directory;
	PIMAGE_DATA_DIRECTORY debug_directory;

	DWORD resolve_directories();

protected:
	char* raw_pe_data;

	DWORD parse();

	///
	/// Functions specific to parsing section entries
	///
	DWORD parse_import_entries();
	DWORD get_thunk_data_addr(char* thunk_ptr, int index);
	ImportedFunction resolve_thunk_function(ULONGLONG func_ptr);
	PIMAGE_DATA_DIRECTORY get_data_directory(DWORD type);
	DWORD parse_resource_entries();
	DWORD parse_reloc_entries();

	///
	/// General purpose helper functions
	///
	DWORD rva_to_offset(DWORD rva);
	template <typename T> T* rva_to_ptr(DWORD rva);
};