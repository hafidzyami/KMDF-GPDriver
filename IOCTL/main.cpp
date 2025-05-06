#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <ctime>

#include "IOCTLShared.h"
#include "Commands.h"

// Declare these functions externally since they are already defined in Commands.cpp
extern std::wstring FormatTime(const LARGE_INTEGER& time);
extern std::wstring StringToWString(const std::string& str);
extern std::string WStringToString(const std::wstring& wstr);

void DisplayHelp() {
    std::cout << "GPDriver Monitoring Tool - Command Line Interface\n";
    std::cout << "--------------------------------------------------\n";
    std::cout << "Available commands:\n\n";
    
    std::cout << "process-list                      - List all monitored processes\n";
    std::cout << "process-info <PID>                - Display detailed information about a specific process\n";
    std::cout << "registry-monitor [count]          - Display recent registry activity (optional: specify count)\n";
    std::cout << "add-registry-filter <path> <flags>- Add registry path to protection list (flags: r=read, w=write, d=delete)\n";
    std::cout << "dll-monitor [PID]                 - List loaded modules/DLLs (optional: for specific process)\n";
    std::cout << "thread-monitor [PID]              - List thread creation events (optional: for specific process)\n";
    std::cout << "alerts [clear]                    - Display security alerts (optional: clear alerts)\n";
    std::cout << "protect-process <PID> <0|1>       - Enable/disable tamper protection for a process\n";
    std::cout << "export-csv <filename> <command>   - Export data to CSV file (specify command to export)\n";
    std::cout << "stats                             - Display system statistics\n";
    std::cout << "help                              - Display this help information\n";
    std::cout << "exit                              - Exit the application\n";
}

bool ProcessCommand(const std::string& command, const std::vector<std::string>& args) {
    if (command == "help" || command == "h" || command == "?") {
        DisplayHelp();
        return true;
    }
    else if (command == "exit" || command == "quit" || command == "q") {
        return false;
    }
    else if (command == "process-list") {
        CommandProcessList();
        return true;
    }
    else if (command == "process-info") {
        if (args.size() < 1) {
            std::cout << "Error: Missing process ID parameter.\n";
            std::cout << "Usage: process-info <PID>\n";
            return true;
        }
        
        try {
            ULONG pid = std::stoul(args[0]);
            CommandProcessInfo(pid);
        }
        catch (const std::exception&) {
            std::cout << "Error: Invalid process ID format.\n";
        }
        return true;
    }
    else if (command == "registry-monitor") {
        ULONG count = 10; // Default to 10 entries
        if (args.size() >= 1) {
            try {
                count = std::stoul(args[0]);
            }
            catch (const std::exception&) {
                std::cout << "Warning: Invalid count parameter, using default (10).\n";
            }
        }
        CommandRegistryMonitor(count);
        return true;
    }
    else if (command == "add-registry-filter") {
        if (args.size() < 2) {
            std::cout << "Error: Missing parameters.\n";
            std::cout << "Usage: add-registry-filter <registry_path> <flags>\n";
            std::cout << "Flags: r=read, w=write, d=delete (e.g., wd = write and delete)\n";
            return true;
        }
        
        std::wstring regPath = StringToWString(args[0]);
        std::string flags = args[1];
        ULONG filterFlags = 0;
        
        if (flags.find('r') != std::string::npos) filterFlags |= 0x1;  // Read
        if (flags.find('w') != std::string::npos) filterFlags |= 0x2;  // Write
        if (flags.find('d') != std::string::npos) filterFlags |= 0x4;  // Delete
        
        CommandAddRegistryFilter(regPath, filterFlags);
        return true;
    }
    else if (command == "dll-monitor") {
        ULONG pid = 0; // 0 means all processes
        if (args.size() >= 1) {
            try {
                pid = std::stoul(args[0]);
            }
            catch (const std::exception&) {
                std::cout << "Warning: Invalid process ID, showing all processes.\n";
                pid = 0;
            }
        }
        CommandDllMonitor(pid);
        return true;
    }
    else if (command == "thread-monitor") {
        ULONG pid = 0; // 0 means all processes
        if (args.size() >= 1) {
            try {
                pid = std::stoul(args[0]);
            }
            catch (const std::exception&) {
                std::cout << "Warning: Invalid process ID, showing all processes.\n";
                pid = 0;
            }
        }
        CommandThreadMonitor(pid);
        return true;
    }
    else if (command == "alerts") {
        bool clear = false;
        if (args.size() >= 1 && args[0] == "clear") {
            clear = true;
        }
        CommandAlerts(clear);
        return true;
    }
    else if (command == "protect-process") {
        if (args.size() < 2) {
            std::cout << "Error: Missing parameters.\n";
            std::cout << "Usage: protect-process <PID> <0|1>\n";
            return true;
        }
        
        try {
            ULONG pid = std::stoul(args[0]);
            bool enable = (args[1] == "1" || args[1] == "true" || args[1] == "yes" || args[1] == "y");
            CommandProtectProcess(pid, enable);
        }
        catch (const std::exception&) {
            std::cout << "Error: Invalid parameters.\n";
        }
        return true;
    }
    else if (command == "export-csv") {
        if (args.size() < 2) {
            std::cout << "Error: Missing parameters.\n";
            std::cout << "Usage: export-csv <filename.csv> <command>\n";
            std::cout << "Commands: process-list, registry-monitor, dll-monitor, thread-monitor, alerts\n";
            return true;
        }
        
        std::string filename = args[0];
        std::string exportCommand = args[1];
        
        if (exportCommand == "process-list" || 
            exportCommand == "registry-monitor" || 
            exportCommand == "dll-monitor" || 
            exportCommand == "thread-monitor" || 
            exportCommand == "alerts") {
            CommandExportCsv(filename, exportCommand);
        }
        else {
            std::cout << "Error: Invalid export command. Supported commands are:\n";
            std::cout << "process-list, registry-monitor, dll-monitor, thread-monitor, alerts\n";
        }
        return true;
    }
    else if (command == "stats") {
        CommandSystemStats();
        return true;
    }
    else {
        std::cout << "Unknown command: " << command << "\n";
        std::cout << "Type 'help' for available commands.\n";
        return true;
    }
}

int main(int argc, char* argv[]) {
    // Check if running as interactive mode or with command line arguments
    if (argc > 1) {
        // Process command line arguments
        std::string command = argv[1];
        std::vector<std::string> args;
        
        for (int i = 2; i < argc; i++) {
            args.push_back(argv[i]);
        }
        
        ProcessCommand(command, args);
    }
    else {
        // Interactive mode
        std::cout << "GPDriver Monitoring Tool - Command Line Interface\n";
        std::cout << "Type 'help' for available commands, 'exit' to quit.\n";
        
        bool running = true;
        std::string input;
        
        while (running) {
            std::cout << "\n> ";
            std::getline(std::cin, input);
            
            // Parse command and arguments
            std::istringstream iss(input);
            std::string command;
            std::vector<std::string> args;
            
            iss >> command;
            std::string arg;
            while (iss >> arg) {
                args.push_back(arg);
            }
            
            running = ProcessCommand(command, args);
        }
    }
    
    return 0;
}
