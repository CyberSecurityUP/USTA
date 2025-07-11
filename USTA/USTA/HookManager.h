// HookManager.h
#pragma once

bool HookFunction(void* targetFunc, void* detourFunc, void** originalFunc);
bool InitializeHooks();
