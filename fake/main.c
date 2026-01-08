#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    const wchar_t* className = L"CabinetWClass";
    const wchar_t* title = L"控制面板";

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = 0;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = NULL;
    wc.hCursor = NULL;
    wc.hbrBackground = NULL;
    wc.lpszMenuName = NULL;
    wc.lpszClassName = className;
    wc.hIconSm = NULL;

    if (!RegisterClassExW(&wc)) {
        DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            MessageBoxW(NULL, L"RegisterClassExW failed.", L"Error", MB_ICONERROR);
            return (int)err;
        }
    }

    HWND hwnd = CreateWindowExW(
        WS_EX_TOOLWINDOW,   // exStyle
        className,          // lpClassName
        title,              // lpWindowName
        WS_POPUP,           // dwStyle
        0, 0, 0, 0,         // x, y, w, h
        NULL,               // hWndParent
        NULL,               // hMenu
        hInstance,          // hInstance
        NULL                // lpParam
    );

    if (!hwnd) {
        DWORD err = GetLastError();
        MessageBoxW(NULL, L"CreateWindowExW failed.", L"Error", MB_ICONERROR);
        return (int)err;
    }

    ShowWindow(hwnd, SW_HIDE);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
