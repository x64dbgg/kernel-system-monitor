#include <iostream>
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <Windows.h>
#include "ProcessMonitor.h"
#include "MemoryAnalyzer.h"
#include "KernelDriver.h"
#include "APIHook.h"
#include "SystemInfo.h"

std::atomic<bool> g_running(true);

void displayMenu() {
    system("cls");
    std::cout << "===== Windows Kernel Inspector =====" << std::endl;
    std::cout << "1. Start Process Monitoring" << std::endl;
    std::cout << "2. Analyze System Memory" << std::endl;
    std::cout << "3. Install API Hooks" << std::endl;
    std::cout << "4. Display System Information" << std::endl;
    std::cout << "5. Load Kernel Driver" << std::endl;
    std::cout << "6. Exit" << std::endl;
    std::cout << "===================================" << std::endl;
    std::cout << "Selection: ";
}

void processMonitoringThread(std::shared_ptr<ProcessMonitor> monitor) {
    std::cout << "Process monitoring started. Press any key to stop." << std::endl;
    monitor->startMonitoring();
    
    while(!GetAsyncKeyState(VK_ESCAPE) && g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    monitor->stopMonitoring();
    std::cout << "Process monitoring stopped." << std::endl;
}

int main() {
    try {
        // Initialize components
        auto processMonitor = std::make_shared<ProcessMonitor>();
        auto memoryAnalyzer = std::make_shared<MemoryAnalyzer>();
        auto kernelDriver = std::make_shared<KernelDriver>();
        auto apiHook = std::make_shared<APIHook>();
        auto systemInfo = std::make_shared<SystemInfo>();
        
        int choice = 0;
        std::thread monitorThread;
        bool monitorRunning = false;
        
        while(g_running) {
            displayMenu();
            std::cin >> choice;
            
            switch(choice) {
                case 1: {
                    if (!monitorRunning) {
                        monitorThread = std::thread(processMonitoringThread, processMonitor);
                        monitorRunning = true;
                    } else {
                        std::cout << "Process monitoring is already running." << std::endl;
                    }
                    break;
                }
                case 2: {
                    auto results = memoryAnalyzer->analyzeSystemMemory();
                    memoryAnalyzer->displayResults(results);
                    std::cout << "Press any key to continue..." << std::endl;
                    std::cin.ignore();
                    std::cin.get();
                    break;
                }
                case 3: {
                    apiHook->installHooks();
                    std::cout << "API hooks installed. Press any key to continue..." << std::endl;
                    std::cin.ignore();
                    std::cin.get();
                    break;
                }
                case 4: {
                    systemInfo->displaySystemInfo();
                    std::cout << "Press any key to continue..." << std::endl;
                    std::cin.ignore();
                    std::cin.get();
                    break;
                }
                case 5: {
                    if (kernelDriver->loadDriver()) {
                        std::cout << "Driver loaded successfully." << std::endl;
                    } else {
                        std::cout << "Failed to load driver." << std::endl;
                    }
                    std::cout << "Press any key to continue..." << std::endl;
                    std::cin.ignore();
                    std::cin.get();
                    break;
                }
                case 6: {
                    g_running = false;
                    break;
                }
                default: {
                    std::cout << "Invalid option. Please try again." << std::endl;
                    break;
                }
            }
        }
        
        if (monitorRunning && monitorThread.joinable()) {
            monitorThread.join();
        }
        
        // Cleanup
        apiHook->removeHooks();
        kernelDriver->unloadDriver();
        
        std::cout << "Application terminated." << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
