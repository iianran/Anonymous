#include "XModule.h"
#include <cstdio>
int main(int argc, char** argv) {
    if (argc < 2) return 1;
    XModule m;
    mp_sint32 r = m.loadModule((const SYSCHAR*)argv[1]);
    printf("loadModule result=%d\n", (int)r);
    return 0;
}
#include "AudioDriverManager.h"
AudioDriverManager::AudioDriverManager() {}
AudioDriverManager::~AudioDriverManager() {}
AudioDriverInterface* AudioDriverManager::getPreferredAudioDriver() { return nullptr; }
AudioDriverInterface* AudioDriverManager::getAudioDriverByName(const char*) { return nullptr; }
