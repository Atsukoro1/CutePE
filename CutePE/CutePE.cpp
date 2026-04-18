#include <iostream>
#include <phnt_windows.h>
#include <phnt.h>

#include "PEParser.h"

const char* EXE_PATH = "C:\\Users\\Jakub\\AppData\\Local\\exodus\\Exodus.exe";

int main()
{
    PEParser parser = PEParser();

    ResultCode parsing_res = parser.from_disk((char*)EXE_PATH);
    if (parsing_res != ResultCode::SUCCESS)
    {
        std::cerr << "[!] Failed to parse, error code: " << parsing_res << std::endl;
        return EXIT_FAILURE;
    }
  
    return EXIT_SUCCESS;
}