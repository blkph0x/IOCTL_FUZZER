#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <string>
#include <random>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <fstream>

std::wstring GetDriverPath(const std::wstring& driverName) {
    return L"\\\\.\\" + driverName;
}

DWORD GenerateRandomIOCTL() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<DWORD> dist(0x00000000, 0xCCCCCCCC);
    return dist(gen);
}

std::vector<BYTE> GenerateRandomBuffer(size_t bufferSize) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> byteDist(0x00, 0xFF);

    std::vector<BYTE> buffer(bufferSize);
    for (size_t i = 0; i < bufferSize; i++) {
        buffer[i] = static_cast<BYTE>(byteDist(gen));
    }

    return buffer;
}

LONG WINAPI FuzzHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    std::wofstream logfile("log.txt", std::ios::app);
    if (logfile.is_open()) {
        logfile << L"Access violation occurred with code: " << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl;
        logfile.close();
    }
    // Handle the exception gracefully, e.g., log the error, recover if possible
    return EXCEPTION_CONTINUE_SEARCH; // or EXCEPTION_EXECUTE_HANDLER if you want to suppress the exception
}

std::mutex printMutex;

bool IsIOCTLValid(HANDLE hDevice, DWORD ioctlCode, const std::vector<BYTE>& inputBuffer, std::vector<BYTE>& outputBuffer) {
    DWORD bytesReturned;
    if (DeviceIoControl(
        hDevice,
        ioctlCode,
        const_cast<BYTE*>(inputBuffer.data()),
        static_cast<DWORD>(inputBuffer.size()),
        outputBuffer.data(),
        static_cast<DWORD>(outputBuffer.size()),
        &bytesReturned,
        nullptr))
    {
        return true;
    }
    return false;
}

void FuzzDriver(const TCHAR* driverPath, size_t bufferSize) {
    const int maxAttempts = 10;  // Increase the number of attempts
    const int delayMs = 1000;  // Delay between attempts (1 second)

    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
        HANDLE hDevice = CreateFile(
            driverPath,
            GENERIC_READ | GENERIC_WRITE,
            0,  // Exclusive access
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (hDevice != INVALID_HANDLE_VALUE) {
            try {
                std::vector<BYTE> inputBuffer(bufferSize);  // Allocate input buffer
                std::vector<BYTE> outputBuffer(bufferSize);  // Allocate output buffer

                for (DWORD randomIOCTL = 0x00000000; randomIOCTL <= 0xCCCCCCCC; randomIOCTL++) {
                    std::vector<BYTE> tempInputBuffer = GenerateRandomBuffer(bufferSize);
                    memcpy(inputBuffer.data(), tempInputBuffer.data(), bufferSize);

                    if (IsIOCTLValid(hDevice, randomIOCTL, inputBuffer, outputBuffer)) {
                        std::lock_guard<std::mutex> lock(printMutex);
                        std::wofstream logfile("log.txt", std::ios::app);
                        if (logfile.is_open()) {
                            logfile << L"Valid IOCTL command for driver " << driverPath << L": " << randomIOCTL << std::endl;
                            logfile.close();
                        }
                    }
                }
            }
            catch (std::exception& e) {
                std::lock_guard<std::mutex> lock(printMutex);
                std::wofstream logfile("log.txt", std::ios::app);
                if (logfile.is_open()) {
                    logfile << L"Exception occurred while sending IOCTL commands for driver " << driverPath << L": " << e.what() << std::endl;
                    logfile.close();
                }
                // Handle the exception gracefully, e.g., log the error, recover if possible
            }

            CloseHandle(hDevice);
        }
        else {
            std::lock_guard<std::mutex> lock(printMutex);
            std::wofstream logfile("log.txt", std::ios::app);
            if (logfile.is_open()) {
                logfile << L"Failed to open device: " << driverPath << L". Error code: " << GetLastError() << std::endl;
                logfile.close();
            }

            if (attempt < maxAttempts) {
                std::wofstream logfile("log.txt", std::ios::app);
                if (logfile.is_open()) {
                    logfile << L"Retrying in " << delayMs << L" milliseconds..." << std::endl;
                    logfile.close();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            }
            else {
                std::wofstream logfile("log.txt", std::ios::app);
                if (logfile.is_open()) {
                    logfile << L"Maximum number of attempts reached. Skipping driver: " << driverPath << std::endl;
                    logfile.close();
                }
            }
        }
    }
}

int main() {
    const size_t maxBufferSize = 2048;
    LPVOID* drivers = new LPVOID[maxBufferSize];
    DWORD bytesNeeded;

    SetUnhandledExceptionFilter(FuzzHandler);

    if (EnumDeviceDrivers(drivers, maxBufferSize * sizeof(LPVOID), &bytesNeeded)) {
        int driverCount = bytesNeeded / sizeof(drivers[0]);

        std::vector<std::thread> threads;

        for (size_t bufferSize = 0; bufferSize <= maxBufferSize; bufferSize++) {
            for (int i = 0; i < driverCount; i++) {
                TCHAR driverPath[MAX_PATH];
                if (GetDeviceDriverFileName(drivers[i], driverPath, MAX_PATH)) {
                    threads.emplace_back([driverPath, bufferSize]() {
                        std::wofstream logfile("log.txt", std::ios::app);
                        if (logfile.is_open()) {
                            logfile << L"Testing driver: " << driverPath << L", Buffer Size: " << bufferSize << std::endl;
                            logfile.close();
                        }
                        FuzzDriver(driverPath, bufferSize);
                        });
                }
            }
        }

        for (auto& thread : threads) {
            thread.join();
        }
    }
    else {
        std::wofstream logfile("log.txt", std::ios::app);
        if (logfile.is_open()) {
            logfile << "Failed to enumerate device drivers. Error code: " << GetLastError() << std::endl;
            logfile.close();
        }
    }

    delete[] drivers;

    return 0;
}
