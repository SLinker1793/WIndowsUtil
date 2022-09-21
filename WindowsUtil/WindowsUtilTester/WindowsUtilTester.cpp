// WindowsUtilTester.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

#pragma comment(lib, "WindowsUtil.lib")

#include "..\WindowsUtil\ProcessHelper.h"
#include "..\WindowsUtil\ServiceHelper.h"

int main()
{
    CProcessHelper process;
    CServiceHelper service(L"SaniTOX EP");

    DWORD parent = 0;
    process.GetParentId(27628, &parent);

    service.Start();

    service.SendControlCode(165);
    service.SendControlCode(170);

    std::cout << "Hello World!\n";
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
