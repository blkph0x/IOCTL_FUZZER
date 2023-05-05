#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <Psapi.h>
#include <sstream>
#include <SetupAPI.h>
#include <locale>
#include <codecvt>
#include <random>
#include <cstdint>

#pragma comment(lib, "SetupAPI.lib")
#pragma comment(lib, "Psapi.lib")

std::string wstring_to_string(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

std::vector<std::string> SplitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::vector<std::string> EnumerateLoadedDeviceDriverIDs() {
    std::vector<std::string> driverIDs;
    HMODULE drivers[1024];
    DWORD cbNeeded;

    if (EnumDeviceDrivers(reinterpret_cast<LPVOID*>(drivers), sizeof(drivers), &cbNeeded)) {
        TCHAR driverPath[MAX_PATH];
        DWORD numDrivers = cbNeeded / sizeof(drivers[0]);

        for (DWORD i = 0; i < numDrivers; ++i) {
            MODULEINFO moduleInfo;
            if (GetModuleInformation(GetCurrentProcess(), drivers[i], &moduleInfo, sizeof(moduleInfo))) {
                TCHAR moduleName[MAX_PATH];
                if (GetModuleFileNameEx(GetCurrentProcess(), drivers[i], moduleName, sizeof(moduleName) / sizeof(moduleName[0]))) {
                    std::wstring moduleNameStr(moduleName);
                    std::string moduleNameUtf8 = wstring_to_string(moduleNameStr);
                    driverIDs.push_back(moduleNameUtf8);
                }
            }
        }
    }
    else {
        throw std::runtime_error("Failed to enumerate loaded device driver IDs.");
    }

    return driverIDs;
}

std::string GetDriverName(const std::string& hardwareID) {
    std::vector<std::string> parts = SplitString(hardwareID, '\\');
    if (!parts.empty()) {
        return parts[0];
    }
    return "";
}

bool IsDriverOwnedByNT(const std::string& driverName) {
    return driverName.find("nt") == 0;
}

bool IsDriverSkippable(const std::string& driverName) {
    if (driverName == "hwpolicy") {
        return true;
    }
    return false;
}

std::random_device rdGlobal;
std::mt19937 genGlobal(rdGlobal());
std::uniform_int_distribution<unsigned int> byteDistGlobal(0, 255);

void FuzzIOCTL(const std::string& driverID) {
    // Open the device with the driver ID
    std::string devicePath = "\\\\.\\";
    devicePath += driverID;
    HANDLE hDevice = CreateFileA(devicePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open the device for driver ID: " << driverID << ". Error code: " << GetLastError() << std::endl;
        return;
    }
    std::cout << "Successfully opened the device for driver ID: " << driverID << std::endl;

    DWORD_PTR minAddress = 0x00000000;
    DWORD_PTR maxAddress = 0xFFFFFFFFFFFFFFFF;
    DWORD bytesReturned = 0;
    BYTE inputBuffer[1024] = { 0 };
    BYTE outputBuffer[1024] = { 0 };

    std::cout << "Starting IOCTL fuzzing for driver ID: " << driverID << std::endl;

    for (DWORD_PTR address = minAddress; address <= maxAddress; ++address) {
        // Randomize the input buffer
        for (size_t i = 0; i < sizeof(inputBuffer); ++i) {
            inputBuffer[i] = byteDistGlobal(genGlobal);
        }

        if (DeviceIoControl(hDevice, address, inputBuffer, sizeof(inputBuffer), outputBuffer, sizeof(outputBuffer), &bytesReturned, NULL)) {
            std::cout << "Valid IOCTL command found for driver ID " << driverID << ": " << std::hex << address << std::endl;
        }
    }

    std::cout << "Finished IOCTL fuzzing for driver ID: " << driverID << std::endl;

    CloseHandle(hDevice);
}

std::vector<std::string> EnumerateDeviceDriverIDs() {
    std::vector<std::string> driverIDs;

    HDEVINFO hDevInfo = SetupDiGetClassDevs(NULL, L"DRIVER", NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Failed to get device information set.");
    }

    SP_DEVINFO_DATA devInfoData;
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    DWORD index = 0;
    while (SetupDiEnumDeviceInfo(hDevInfo, index, &devInfoData)) {
        DWORD bufferSize = 0;
        if (SetupDiGetDeviceRegistryProperty(hDevInfo, &devInfoData, SPDRP_HARDWAREID, NULL, NULL, 0, &bufferSize) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            ++index;
            continue;
        }

        std::vector<TCHAR> buffer(bufferSize / sizeof(TCHAR), 0);
        if (!SetupDiGetDeviceRegistryProperty(hDevInfo, &devInfoData, SPDRP_HARDWAREID, NULL, reinterpret_cast<PBYTE>(buffer.data()), bufferSize, NULL)) {
            ++index;
            continue;
        }

        std::wstring hardwareID(buffer.data());
        std::string driverName = GetDriverName(wstring_to_string(hardwareID));
        if (!IsDriverOwnedByNT(driverName) && !IsDriverSkippable(driverName)) {
            driverIDs.push_back(wstring_to_string(hardwareID));
        }

        ++index;
    }

    if (GetLastError() != ERROR_NO_MORE_ITEMS) {
        SetupDiDestroyDeviceInfoList(hDevInfo);
        throw std::runtime_error("Failed to enumerate device driver IDs.");
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);

    return driverIDs;
}

int main() {
    std::vector<std::string> driverIDs;
    try {
        std::cout << "Enumerating loaded device driver IDs..." << std::endl;
        driverIDs = EnumerateLoadedDeviceDriverIDs();
        std::cout << "Enumeration completed. Total drivers found: " << driverIDs.size() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error enumerating loaded device driver IDs: " << e.what() << std::endl;
        return 1;
    }

    for (const std::string& driverID : driverIDs) {
        try {
            FuzzIOCTL(driverID);
        }
        catch (const std::exception& e) {
            std::cerr << "Error fuzzing IOCTL commands for driver ID: " << driverID << ". " << e.what() << std::endl;
            // Handle the error as needed
        }
    }

    std::cout << "IOCTL fuzzing completed for all driver IDs." << std::endl;

    system("pause");
    return 0;
}
