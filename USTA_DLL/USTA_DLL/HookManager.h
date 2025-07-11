#pragma once

bool HookFunction(void* targetFunc, void* detourFunc, void** originalFunc);
void InitializeHooks();
