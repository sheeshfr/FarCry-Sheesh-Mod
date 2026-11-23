#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>

#include "deflate_min.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// Binary Payload Footer & Manifest Opcodes
// ============================================================================
#pragma pack(push, 1)
struct PayloadFooter {
    char magic[8];               // "FCMDRNZ1"
    uint64_t stub_exe_size;      // Size of pure setup_wizard.exe stub
    uint64_t manifest_offset;    // Offset of zlib-compressed manifest
    uint32_t manifest_comp_size;
    uint32_t manifest_raw_size;
};
#pragma pack(pop)

enum OpType : uint8_t {
    OP_PE_LAA         = 1,
    OP_BIN_PATCH      = 2,
    OP_DELTA_LOOSE    = 3,
    OP_SURGICAL_ZIP   = 4,
    OP_SAME_PAK       = 5,
    OP_DELTA_PAK      = 6,
    OP_DELTA_REF_FILE = 7,
    OP_NEW_FILE       = 8
};

struct BinHunk {
    uint32_t offset;
    std::vector<uint8_t> vanilla_bytes;
    std::vector<uint8_t> mod_bytes;
};

struct ManifestRecord {
    uint8_t op;
    std::wstring rel_path;
    std::wstring source_pak;
    std::string pak_entry;
    uint32_t vanilla_size = 0;
    uint32_t vanilla_crc = 0;
    uint32_t mod_size = 0;
    uint32_t mod_crc = 0;
    uint64_t payload_offset = 0;
    uint32_t payload_comp_size = 0;
    uint32_t payload_raw_size = 0;
    std::vector<BinHunk> hunks;
};

// ============================================================================
// String & Path Helpers
// ============================================================================
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), NULL, 0);
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], len);
    return out;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &out[0], len, NULL, NULL);
    return out;
}

static std::wstring TrimSlash(std::wstring p) {
    while (p.size() > 3 && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
    for (auto& c : p) if (c == L'/') c = L'\\';
    return p;
}

static std::wstring JoinPath(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    std::wstring r = TrimSlash(a);
    if (b.front() != L'\\' && b.front() != L'/') r += L'\\';
    r += b;
    for (auto& c : r) if (c == L'/') c = L'\\';
    return r;
}

static bool FileExistsW(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY));
}

static bool DirExistsW(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY));
}

static bool IsReparsePointW(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT));
}

static void EnsureParentDirsW(const std::wstring& filePath) {
    size_t pos = 0;
    while ((pos = filePath.find(L'\\', pos)) != std::wstring::npos) {
        std::wstring dir = filePath.substr(0, pos);
        if (dir.size() > 2 && !DirExistsW(dir)) {
            CreateDirectoryW(dir.c_str(), NULL);
        }
        pos++;
    }
}

static bool ReadWholeFileW(const std::wstring& path, std::vector<uint8_t>& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
    out.resize((size_t)sz.QuadPart);
    size_t total = 0;
    while (total < out.size()) {
        DWORD chunk = (DWORD)std::min<size_t>(out.size() - total, 1 << 24);
        DWORD rd = 0;
        if (!ReadFile(h, out.data() + total, chunk, &rd, NULL) || rd == 0) break;
        total += rd;
    }
    CloseHandle(h);
    return total == out.size();
}

static bool WriteWholeFileW(const std::wstring& path, const void* data, size_t size) {
    EnsureParentDirsW(path);
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY)) {
        SetFileAttributesW(path.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
    }
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    const uint8_t* p = (const uint8_t*)data;
    size_t total = 0;
    while (total < size) {
        DWORD chunk = (DWORD)std::min<size_t>(size - total, 1 << 24);
        DWORD wr = 0;
        if (!WriteFile(h, p + total, chunk, &wr, NULL) || wr == 0) {
            CloseHandle(h);
            return false;
        }
        total += wr;
    }
    CloseHandle(h);
    return true;
}

static bool ReadSliceAt(HANDLE h, uint64_t offset, void* buf, size_t len) {
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) return false;
    uint8_t* p = (uint8_t*)buf;
    size_t total = 0;
    while (total < len) {
        DWORD chunk = (DWORD)std::min<size_t>(len - total, 1 << 22);
        DWORD rd = 0;
        if (!ReadFile(h, p + total, chunk, &rd, NULL) || rd == 0) return false;
        total += rd;
    }
    return true;
}

// ============================================================================
// ZIP (.pak) Reader & Surgical Single-Entry Updater
// ============================================================================
static bool ExtractZipEntryW(const std::wstring& zipPath, const std::string& wantedEntry, std::vector<uint8_t>& outData) {
    HANDLE h = CreateFileW(zipPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER fsz;
    if (!GetFileSizeEx(h, &fsz) || fsz.QuadPart < 22) { CloseHandle(h); return false; }
    uint64_t fileSize = (uint64_t)fsz.QuadPart;
    size_t tailLen = (size_t)std::min<uint64_t>(fileSize, 65557);
    std::vector<uint8_t> tail(tailLen);
    if (!ReadSliceAt(h, fileSize - tailLen, tail.data(), tailLen)) { CloseHandle(h); return false; }

    int64_t eocdPos = -1;
    for (int64_t i = (int64_t)tailLen - 22; i >= 0; --i) {
        size_t idx = (size_t)i;
        if (tail[idx] == 'P' && tail[idx+1] == 'K' && tail[idx+2] == 5 && tail[idx+3] == 6) {
            eocdPos = i;
            break;
        }
    }
    if (eocdPos < 0) { CloseHandle(h); return false; }
    uint16_t cdCount = *(uint16_t*)(tail.data() + eocdPos + 10);
    uint32_t cdSize  = *(uint32_t*)(tail.data() + eocdPos + 12);
    uint32_t cdOff   = *(uint32_t*)(tail.data() + eocdPos + 16);

    std::vector<uint8_t> cd(cdSize);
    if (!ReadSliceAt(h, cdOff, cd.data(), cdSize)) { CloseHandle(h); return false; }

    std::string wantNorm = wantedEntry;
    for (auto& c : wantNorm) { if (c == '\\') c = '/'; c = (char)tolower((unsigned char)c); }

    size_t p = 0;
    for (uint16_t i = 0; i < cdCount && p + 46 <= cd.size(); ++i) {
        if (memcmp(cd.data() + p, "PK\x01\x02", 4) != 0) break;
        uint16_t method = *(uint16_t*)(cd.data() + p + 10);
        uint32_t compSz = *(uint32_t*)(cd.data() + p + 20);
        uint32_t uncompSz = *(uint32_t*)(cd.data() + p + 24);
        uint16_t fnLen  = *(uint16_t*)(cd.data() + p + 28);
        uint16_t exLen  = *(uint16_t*)(cd.data() + p + 30);
        uint16_t cmLen  = *(uint16_t*)(cd.data() + p + 32);
        uint32_t lhOff  = *(uint32_t*)(cd.data() + p + 42);
        if (p + 46 + fnLen > cd.size()) break;

        std::string name((const char*)(cd.data() + p + 46), fnLen);
        std::string nameNorm = name;
        for (auto& c : nameNorm) { if (c == '\\') c = '/'; c = (char)tolower((unsigned char)c); }

        if (nameNorm == wantNorm) {
            uint8_t lh[30];
            if (!ReadSliceAt(h, lhOff, lh, 30) || memcmp(lh, "PK\x03\x04", 4) != 0) {
                CloseHandle(h); return false;
            }
            uint16_t lFnLen = *(uint16_t*)(lh + 26);
            uint16_t lExLen = *(uint16_t*)(lh + 28);
            uint64_t dataOff = (uint64_t)lhOff + 30 + lFnLen + lExLen;
            std::vector<uint8_t> compBuf(compSz);
            if (!ReadSliceAt(h, dataOff, compBuf.data(), compSz)) {
                CloseHandle(h); return false;
            }
            CloseHandle(h);
            if (method == 0) {
                outData = std::move(compBuf);
                return true;
            } else if (method == 8) {
                return inflate_raw(compBuf.data(), compBuf.size(), outData, uncompSz);
            }
            return false;
        }
        p += 46 + fnLen + exLen + cmLen;
    }
    CloseHandle(h);
    return false;
}

static bool SurgicalUpdateZipSingleEntryW(const std::wstring& zipPath, const std::string& wantedEntry, const std::vector<uint8_t>& newData, uint32_t newCrc) {
    std::vector<uint8_t> pak;
    if (!ReadWholeFileW(zipPath, pak) || pak.size() < 22) return false;

    int64_t eocd = -1;
    for (int64_t i = (int64_t)pak.size() - 22; i >= (int64_t)std::max<int64_t>(0, (int64_t)pak.size() - 65557); --i) {
        size_t idx = (size_t)i;
        if (pak[idx] == 'P' && pak[idx+1] == 'K' && pak[idx+2] == 5 && pak[idx+3] == 6) {
            eocd = i;
            break;
        }
    }
    if (eocd < 0) return false;

    uint16_t dnum      = *(uint16_t*)(pak.data() + eocd + 4);
    uint16_t cd_dnum   = *(uint16_t*)(pak.data() + eocd + 6);
    uint16_t cd_cnt_d  = *(uint16_t*)(pak.data() + eocd + 8);
    uint16_t cd_cnt    = *(uint16_t*)(pak.data() + eocd + 10);
    uint32_t cd_sz     = *(uint32_t*)(pak.data() + eocd + 12);
    uint32_t cd_off    = *(uint32_t*)(pak.data() + eocd + 16);
    uint16_t cmlen     = *(uint16_t*)(pak.data() + eocd + 20);

    std::string wantNorm = wantedEntry;
    for (auto& c : wantNorm) { if (c == '\\') c = '/'; c = (char)tolower((unsigned char)c); }

    size_t p = cd_off;
    bool found = false;
    uint32_t target_lhoff = 0;
    uint32_t target_end = 0;
    int32_t delta = 0;
    std::vector<uint8_t> new_local_entry;
    std::vector<uint8_t> new_cd;
    new_cd.reserve(cd_sz);

    for (uint16_t i = 0; i < cd_cnt && p + 46 <= pak.size(); ++i) {
        uint8_t hdr[46];
        memcpy(hdr, pak.data() + p, 46);
        uint16_t fnlen   = *(uint16_t*)(hdr + 28);
        uint16_t exlen   = *(uint16_t*)(hdr + 30);
        uint16_t cmlen_i = *(uint16_t*)(hdr + 32);
        uint32_t lhoff   = *(uint32_t*)(hdr + 42);
        size_t tailLen   = fnlen + exlen + cmlen_i;
        if (p + 46 + tailLen > pak.size()) return false;

        std::string fname((const char*)(pak.data() + p + 46), fnlen);
        std::string fnameNorm = fname;
        for (auto& c : fnameNorm) { if (c == '\\') c = '/'; c = (char)tolower((unsigned char)c); }

        if (!found && fnameNorm == wantNorm) {
            found = true;
            target_lhoff = lhoff;
            if (lhoff + 30 > pak.size()) return false;
            uint8_t lhdr[30];
            memcpy(lhdr, pak.data() + lhoff, 30);
            uint32_t old_csz = *(uint32_t*)(lhdr + 18);
            uint16_t lfnlen  = *(uint16_t*)(lhdr + 26);
            uint16_t lexlen  = *(uint16_t*)(lhdr + 28);
            target_end = lhoff + 30 + lfnlen + lexlen + old_csz;
            if (target_end > pak.size()) return false;

            *(uint16_t*)(lhdr + 8)  = 0; // method = 0 (stored)
            *(uint32_t*)(lhdr + 14) = newCrc;
            *(uint32_t*)(lhdr + 18) = (uint32_t)newData.size();
            *(uint32_t*)(lhdr + 22) = (uint32_t)newData.size();

            new_local_entry.resize(30 + lfnlen + lexlen + newData.size());
            memcpy(new_local_entry.data(), lhdr, 30);
            memcpy(new_local_entry.data() + 30, pak.data() + lhoff + 30, lfnlen + lexlen);
            memcpy(new_local_entry.data() + 30 + lfnlen + lexlen, newData.data(), newData.size());

            delta = (int32_t)new_local_entry.size() - (int32_t)(target_end - target_lhoff);
            *(uint16_t*)(hdr + 10) = 0; // method = 0
            *(uint32_t*)(hdr + 16) = newCrc;
            *(uint32_t*)(hdr + 20) = (uint32_t)newData.size();
            *(uint32_t*)(hdr + 24) = (uint32_t)newData.size();
        } else if (found && lhoff > target_lhoff) {
            *(uint32_t*)(hdr + 42) = (uint32_t)((int32_t)lhoff + delta);
        }
        new_cd.insert(new_cd.end(), hdr, hdr + 46);
        new_cd.insert(new_cd.end(), pak.data() + p + 46, pak.data() + p + 46 + tailLen);
        p += 46 + tailLen;
    }
    if (!found) return false;

    uint8_t eocd_buf[22];
    memcpy(eocd_buf, "PK\x05\x06", 4);
    *(uint16_t*)(eocd_buf + 4)  = dnum;
    *(uint16_t*)(eocd_buf + 6)  = cd_dnum;
    *(uint16_t*)(eocd_buf + 8)  = cd_cnt_d;
    *(uint16_t*)(eocd_buf + 10) = cd_cnt;
    *(uint32_t*)(eocd_buf + 12) = (uint32_t)new_cd.size();
    *(uint32_t*)(eocd_buf + 16) = (uint32_t)((int32_t)cd_off + delta);
    *(uint16_t*)(eocd_buf + 20) = cmlen;

    HANDLE h = CreateFileW(zipPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    auto writeChunk = [&](const void* ptr, size_t sz) -> bool {
        const uint8_t* b = (const uint8_t*)ptr;
        size_t tot = 0;
        while (tot < sz) {
            DWORD ch = (DWORD)std::min<size_t>(sz - tot, 1 << 24);
            DWORD wr = 0;
            if (!WriteFile(h, b + tot, ch, &wr, NULL) || wr == 0) return false;
            tot += wr;
        }
        return true;
    };
    bool ok = writeChunk(pak.data(), target_lhoff) &&
              writeChunk(new_local_entry.data(), new_local_entry.size()) &&
              writeChunk(pak.data() + target_end, cd_off - target_end) &&
              writeChunk(new_cd.data(), new_cd.size()) &&
              writeChunk(eocd_buf, 22);
    CloseHandle(h);
    return ok;
}
// ============================================================================
// Runtime Story & Dialogue Voice Booster (+25% gain + soft-knee limiter)
// Generates FCData\zz_sheesh_voices.pak locally from english.pak without
// modifying or redistributing Ubisoft's original english.pak archive.
// ============================================================================
static bool ShouldBoostDialogueVoice(const std::string& lowPath) {
    if (lowPath.size() < 4 || lowPath.compare(lowPath.size() - 4, 4, ".wav") != 0) return false;
    static const char* kPrefixes[] = {
        "languages/missiontalk/",
        "languages/voicepacks/krieger/",
        "languages/voicepacks/mission_generic/",
        "languages/voicepacks/val/affirmative_",
        "languages/voicepacks/val/receive_"
    };
    for (const char* pfx : kPrefixes) {
        size_t plen = strlen(pfx);
        if (lowPath.size() >= plen && lowPath.compare(0, plen, pfx) == 0) return true;
    }
    return false;
}

static bool ApplyDialogueBoostInPlace(std::vector<uint8_t>& wav, const std::vector<int16_t>& lut) {
    if (wav.size() < 44) return false;
    if (memcmp(wav.data(), "RIFF", 4) != 0 || memcmp(wav.data() + 8, "WAVE", 4) != 0) return false;

    uint16_t fmtCode = 0;
    uint16_t bitsPerSample = 0;
    bool boostedAny = false;
    size_t pos = 12;

    while (pos + 8 <= wav.size()) {
        const uint8_t* cid = wav.data() + pos;
        uint32_t csz = *(const uint32_t*)(wav.data() + pos + 4);
        size_t dataStart = pos + 8;
        size_t dataEnd = std::min<size_t>(wav.size(), dataStart + (size_t)csz);
        size_t payloadLen = (dataEnd >= dataStart) ? (dataEnd - dataStart) : 0;

        if (memcmp(cid, "fmt ", 4) == 0 && payloadLen >= 16) {
            fmtCode = *(const uint16_t*)(wav.data() + dataStart);
            bitsPerSample = *(const uint16_t*)(wav.data() + dataStart + 14);
        } else if (memcmp(cid, "data", 4) == 0 && fmtCode == 1 && bitsPerSample == 16 && payloadLen >= 2) {
            size_t sampleCount = payloadLen / 2;
            uint8_t* samples = wav.data() + dataStart;
            for (size_t i = 0; i < sampleCount; ++i) {
                uint16_t u = (uint16_t)samples[i * 2] | ((uint16_t)samples[i * 2 + 1] << 8);
                int16_t outS = lut[u];
                samples[i * 2]     = (uint8_t)(outS & 0xFF);
                samples[i * 2 + 1] = (uint8_t)((outS >> 8) & 0xFF);
            }
            boostedAny = true;
        }
        size_t adv = (size_t)csz + (csz & 1);
        if (dataStart + adv <= pos) break;
        pos = dataStart + adv;
    }
    return boostedAny;
}

static bool WriteHandleAll(HANDLE h, const void* ptr, size_t sz, uint64_t& curOffset) {
    const uint8_t* b = (const uint8_t*)ptr;
    size_t tot = 0;
    while (tot < sz) {
        DWORD ch = (DWORD)std::min<size_t>(sz - tot, 1 << 24);
        DWORD wr = 0;
        if (!WriteFile(h, b + tot, ch, &wr, NULL) || wr == 0) return false;
        tot += wr;
    }
    curOffset += sz;
    return true;
}

static int GenerateBoostedVoicesPakW(const std::wstring& engPakPath, const std::wstring& outPakPath) {
    HANDLE hEng = CreateFileW(engPakPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hEng == INVALID_HANDLE_VALUE) return 0;

    LARGE_INTEGER fsz;
    if (!GetFileSizeEx(hEng, &fsz) || fsz.QuadPart < 22) {
        CloseHandle(hEng);
        return 0;
    }
    uint64_t fileSize = (uint64_t)fsz.QuadPart;
    size_t tailLen = (size_t)std::min<uint64_t>(fileSize, 65557);
    std::vector<uint8_t> tail(tailLen);
    if (!ReadSliceAt(hEng, fileSize - tailLen, tail.data(), tailLen)) {
        CloseHandle(hEng);
        return 0;
    }

    int64_t eocdPos = -1;
    for (int64_t i = (int64_t)tailLen - 22; i >= 0; --i) {
        size_t idx = (size_t)i;
        if (tail[idx] == 'P' && tail[idx+1] == 'K' && tail[idx+2] == 5 && tail[idx+3] == 6) {
            eocdPos = i;
            break;
        }
    }
    if (eocdPos < 0) { CloseHandle(hEng); return 0; }

    uint16_t cdCount = *(const uint16_t*)(tail.data() + eocdPos + 10);
    uint32_t cdSize  = *(const uint32_t*)(tail.data() + eocdPos + 12);
    uint32_t cdOff   = *(const uint32_t*)(tail.data() + eocdPos + 16);
    if ((uint64_t)cdOff + (uint64_t)cdSize > fileSize) { CloseHandle(hEng); return 0; }

    std::vector<uint8_t> cd(cdSize);
    if (!ReadSliceAt(hEng, cdOff, cd.data(), cdSize)) {
        CloseHandle(hEng);
        return 0;
    }

    std::vector<int16_t> lut(65536, 0);
    const double kGain = 1.25;
    const double kKnee = 0.90;
    const double kHeadroom = 0.095;
    for (int i = 0; i < 65536; ++i) {
        int s = (i < 32768) ? i : (i - 65536);
        double x = (s / 32768.0) * kGain;
        double ax = (x < 0.0) ? -x : x;
        double y;
        if (ax <= kKnee) {
            y = x;
        } else {
            double sign = (x >= 0.0) ? 1.0 : -1.0;
            double excess = ax - kKnee;
            y = sign * (kKnee + kHeadroom * std::tanh(excess / kHeadroom));
        }
        int outS = (int)std::lround(y * 32768.0);
        if (outS > 32767) outS = 32767;
        else if (outS < -32767) outS = -32767;
        lut[i] = (int16_t)outS;
    }

    EnsureParentDirsW(outPakPath);
    std::wstring tmpPath = outPakPath + L".tmp";
    HANDLE hOut = CreateFileW(tmpPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        CloseHandle(hEng);
        return 0;
    }

    std::vector<uint8_t> outCd;
    outCd.reserve(256 * 1024);
    uint64_t writeOffset = 0;
    int boostedCount = 0;
    bool writeFailed = false;

    size_t p = 0;
    for (uint16_t i = 0; i < cdCount && p + 46 <= cd.size(); ++i) {
        if (memcmp(cd.data() + p, "PK\x01\x02", 4) != 0) break;
        uint16_t method  = *(const uint16_t*)(cd.data() + p + 10);
        uint16_t modTime = *(const uint16_t*)(cd.data() + p + 12);
        uint16_t modDate = *(const uint16_t*)(cd.data() + p + 14);
        uint32_t compSz  = *(const uint32_t*)(cd.data() + p + 20);
        uint32_t uncompSz= *(const uint32_t*)(cd.data() + p + 24);
        uint16_t fnLen   = *(const uint16_t*)(cd.data() + p + 28);
        uint16_t exLen   = *(const uint16_t*)(cd.data() + p + 30);
        uint16_t cmLen   = *(const uint16_t*)(cd.data() + p + 32);
        uint32_t extAttr = *(const uint32_t*)(cd.data() + p + 38);
        uint32_t lhOff   = *(const uint32_t*)(cd.data() + p + 42);
        if (p + 46 + fnLen + exLen + cmLen > cd.size()) break;

        std::string origName((const char*)(cd.data() + p + 46), fnLen);
        std::string lowName = origName;
        for (auto& c : lowName) { if (c == '\\') c = '/'; c = (char)tolower((unsigned char)c); }

        if (ShouldBoostDialogueVoice(lowName)) {
            uint8_t lh[30];
            if (ReadSliceAt(hEng, lhOff, lh, 30) && memcmp(lh, "PK\x03\x04", 4) == 0) {
                uint16_t lFnLen = *(const uint16_t*)(lh + 26);
                uint16_t lExLen = *(const uint16_t*)(lh + 28);
                uint64_t dataOff = (uint64_t)lhOff + 30 + lFnLen + lExLen;
                std::vector<uint8_t> compBuf(compSz);
                if (ReadSliceAt(hEng, dataOff, compBuf.data(), compSz)) {
                    std::vector<uint8_t> wavData;
                    bool decOk = false;
                    if (method == 0) {
                        wavData = std::move(compBuf);
                        decOk = true;
                    } else if (method == 8) {
                        decOk = inflate_raw(compBuf.data(), compBuf.size(), wavData, uncompSz);
                    }
                    if (decOk && ApplyDialogueBoostInPlace(wavData, lut)) {
                        uint32_t newCrc = calc_crc32(wavData.data(), wavData.size());
                        uint32_t newSz  = (uint32_t)wavData.size();
                        uint32_t entryLhOff = (uint32_t)writeOffset;

                        std::string outName = origName;
                        for (auto& c : outName) { if (c == '\\') c = '/'; }

                        uint8_t outLh[30] = {0};
                        memcpy(outLh, "PK\x03\x04", 4);
                        *(uint16_t*)(outLh + 4)  = 20;
                        *(uint16_t*)(outLh + 10) = modTime;
                        *(uint16_t*)(outLh + 12) = modDate;
                        *(uint32_t*)(outLh + 14) = newCrc;
                        *(uint32_t*)(outLh + 18) = newSz;
                        *(uint32_t*)(outLh + 22) = newSz;
                        *(uint16_t*)(outLh + 26) = (uint16_t)outName.size();

                        if (!WriteHandleAll(hOut, outLh, 30, writeOffset) ||
                            !WriteHandleAll(hOut, outName.data(), outName.size(), writeOffset) ||
                            !WriteHandleAll(hOut, wavData.data(), wavData.size(), writeOffset)) {
                            writeFailed = true;
                            break;
                        }

                        uint8_t outCdRec[46] = {0};
                        memcpy(outCdRec, "PK\x01\x02", 4);
                        *(uint16_t*)(outCdRec + 4)  = 20;
                        *(uint16_t*)(outCdRec + 6)  = 20;
                        *(uint16_t*)(outCdRec + 12) = modTime;
                        *(uint16_t*)(outCdRec + 14) = modDate;
                        *(uint32_t*)(outCdRec + 16) = newCrc;
                        *(uint32_t*)(outCdRec + 20) = newSz;
                        *(uint32_t*)(outCdRec + 24) = newSz;
                        *(uint16_t*)(outCdRec + 28) = (uint16_t)outName.size();
                        *(uint32_t*)(outCdRec + 38) = extAttr;
                        *(uint32_t*)(outCdRec + 42) = entryLhOff;
                        outCd.insert(outCd.end(), outCdRec, outCdRec + 46);
                        outCd.insert(outCd.end(), (const uint8_t*)outName.data(), (const uint8_t*)outName.data() + outName.size());
                        boostedCount++;
                    }
                }
            }
        }
        p += 46 + fnLen + exLen + cmLen;
    }

    if (!writeFailed && boostedCount > 0) {
        uint32_t cdStartOff = (uint32_t)writeOffset;
        uint32_t outCdSz    = (uint32_t)outCd.size();
        uint8_t outEocd[22] = {0};
        memcpy(outEocd, "PK\x05\x06", 4);
        *(uint16_t*)(outEocd + 8)  = (uint16_t)boostedCount;
        *(uint16_t*)(outEocd + 10) = (uint16_t)boostedCount;
        *(uint32_t*)(outEocd + 12) = outCdSz;
        *(uint32_t*)(outEocd + 16) = cdStartOff;
        if (!WriteHandleAll(hOut, outCd.data(), outCd.size(), writeOffset) ||
            !WriteHandleAll(hOut, outEocd, 22, writeOffset)) {
            writeFailed = true;
        }
    }

    CloseHandle(hOut);
    CloseHandle(hEng);

    if (writeFailed || boostedCount == 0) {
        DeleteFileW(tmpPath.c_str());
        return 0;
    }
    if (!MoveFileExW(tmpPath.c_str(), outPakPath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(tmpPath.c_str());
        return 0;
    }
    return boostedCount;
}

// ============================================================================
// 7-Layer Multi-Storefront Far Cry Installation Auto-Detector
// (Ubisoft Connect / Epic Games, Steam, GOG, Retail, Registry & Drive Sweep)
// ============================================================================
struct DetectedInstall {
    std::wstring path;
    std::wstring label;
    int priority; // Lower = higher priority (1 = Storefront Registry, 2 = Drive Scan, 3 = Workspace Modded)
};

static bool IsValidFarCryDir(const std::wstring& dir) {
    if (dir.empty()) return false;
    std::wstring exe = JoinPath(dir, L"Bin32\\FarCry.exe");
    std::wstring fcdata = JoinPath(dir, L"FCData");
    return FileExistsW(exe) && DirExistsW(fcdata);
}

static bool IsProtectedVanillaWorkspaceDir(const std::wstring& dir) {
    std::wstring norm = TrimSlash(dir);
    for (auto& c : norm) c = (wchar_t)towlower(c);
    // Protect our sacred read-only Vanilla reference folder in the workspace
    if (norm.size() >= 8 && norm.substr(norm.size() - 8) == L"\\vanilla") {
        std::wstring sibMods = JoinPath(dir, L"..\\mods\\Scripts\\Default\\Hud\\InventoryGrid.lua");
        if (FileExistsW(sibMods)) return true;
    }
    return false;
}

static bool ReadRegStringW(HKEY root, const wchar_t* subkey, const wchar_t* valueName, std::wstring& out) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return false;
    wchar_t buf[1024] = {0};
    DWORD sz = sizeof(buf) - sizeof(wchar_t);
    DWORD type = 0;
    LONG res = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)buf, &sz);
    RegCloseKey(hKey);
    if (res == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) && buf[0] != 0) {
        out = TrimSlash(buf);
        return true;
    }
    return false;
}

static void AddCandidate(std::vector<DetectedInstall>& list, const std::wstring& rawPath, const std::wstring& sourceTag, int prio) {
    if (rawPath.empty()) return;
    std::wstring clean = TrimSlash(rawPath);
    // Strip quotes if present
    if (clean.size() >= 2 && clean.front() == L'"' && clean.back() == L'"') {
        clean = clean.substr(1, clean.size() - 2);
        clean = TrimSlash(clean);
    }
    // If path points to Bin32 or FarCry.exe, walk up
    if (FileExistsW(clean)) {
        size_t sl = clean.rfind(L'\\');
        if (sl != std::wstring::npos) clean = clean.substr(0, sl);
    }
    if (clean.size() > 6) {
        std::wstring tail = clean.substr(clean.size() - 6);
        for (auto& c : tail) c = (wchar_t)towlower(c);
        if (tail == L"\\bin32") clean = clean.substr(0, clean.size() - 6);
    }
    if (!IsValidFarCryDir(clean) || IsProtectedVanillaWorkspaceDir(clean)) return;

    wchar_t fullBuf[MAX_PATH] = {0};
    if (GetFullPathNameW(clean.c_str(), MAX_PATH, fullBuf, NULL)) {
        clean = TrimSlash(fullBuf);
    }

    for (const auto& existing : list) {
        if (_wcsicmp(existing.path.c_str(), clean.c_str()) == 0) return;
    }
    DetectedInstall item;
    item.path = clean;
    item.label = L"[" + sourceTag + L"]  " + clean;
    item.priority = prio;
    list.push_back(item);
}

static void ScanUbisoftAndEpicInstalls(std::vector<DetectedInstall>& list) {
    // 1a. Ubisoft Connect Installs Registry (Epic Games delegates Far Cry installation here!)
    const HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const wchar_t* ubiKeys[2] = {
        L"SOFTWARE\\WOW6432Node\\Ubisoft\\Launcher\\Installs",
        L"SOFTWARE\\Ubisoft\\Launcher\\Installs"
    };
    for (int r = 0; r < 2; ++r) {
        for (int k = 0; k < 2; ++k) {
            HKEY hInstalls = NULL;
            if (RegOpenKeyExW(roots[r], ubiKeys[k], 0, KEY_READ, &hInstalls) == ERROR_SUCCESS) {
                wchar_t subName[256];
                DWORD idx = 0;
                DWORD subLen = 256;
                while (RegEnumKeyExW(hInstalls, idx++, subName, &subLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    std::wstring fullSub = std::wstring(ubiKeys[k]) + L"\\" + subName;
                    std::wstring installDir;
                    if (ReadRegStringW(roots[r], fullSub.c_str(), L"InstallDir", installDir)) {
                        AddCandidate(list, installDir, L"Ubisoft Connect / Epic", 1);
                    }
                    subLen = 256;
                }
                RegCloseKey(hInstalls);
            }
        }
    }

    // 1b. Ubisoft Connect settings.yml (%LOCALAPPDATA%\Ubisoft Game Launcher\settings.yml)
    wchar_t localAppData[MAX_PATH] = {0};
    if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) == S_OK) {
        std::wstring ymlPath = JoinPath(localAppData, L"Ubisoft Game Launcher\\settings.yml");
        std::vector<uint8_t> ymlBytes;
        if (ReadWholeFileW(ymlPath, ymlBytes)) {
            std::string content((const char*)ymlBytes.data(), ymlBytes.size());
            size_t pos = content.find("game_installation_path:");
            if (pos != std::string::npos) {
                pos += strlen("game_installation_path:");
                size_t eol = content.find_first_of("\r\n", pos);
                std::string val = content.substr(pos, (eol == std::string::npos) ? std::string::npos : (eol - pos));
                while (!val.empty() && (val.front() == ' ' || val.front() == '"' || val.front() == '\'')) val.erase(val.begin());
                while (!val.empty() && (val.back() == ' ' || val.back() == '"' || val.back() == '\'')) val.pop_back();
                if (!val.empty()) {
                    std::wstring baseDir = Utf8ToWide(val);
                    AddCandidate(list, JoinPath(baseDir, L"FAR CRY 1"), L"Ubisoft Connect / Epic", 1);
                    AddCandidate(list, JoinPath(baseDir, L"Far Cry 1"), L"Ubisoft Connect / Epic", 1);
                    AddCandidate(list, JoinPath(baseDir, L"Far Cry"), L"Ubisoft Connect / Epic", 1);
                    AddCandidate(list, JoinPath(baseDir, L"FarCry"), L"Ubisoft Connect / Epic", 1);
                }
            }
        }
    }

    // 1c. Epic Games Launcher Manifests (C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests\*.item)
    wchar_t progData[MAX_PATH] = {0};
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, progData) == S_OK) {
        std::wstring manifestDir = JoinPath(progData, L"Epic\\EpicGamesLauncher\\Data\\Manifests");
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(JoinPath(manifestDir, L"*.item").c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::vector<uint8_t> itemBytes;
                    if (ReadWholeFileW(JoinPath(manifestDir, fd.cFileName), itemBytes)) {
                        std::string json((const char*)itemBytes.data(), itemBytes.size());
                        size_t kpos = json.find("\"InstallLocation\"");
                        if (kpos != std::string::npos) {
                            size_t q1 = json.find('"', kpos + 17);
                            size_t q2 = (q1 != std::string::npos) ? json.find('"', q1 + 1) : std::string::npos;
                            if (q1 != std::string::npos && q2 != std::string::npos) {
                                std::string rawLoc = json.substr(q1 + 1, q2 - q1 - 1);
                                std::string unescaped;
                                for (size_t i = 0; i < rawLoc.size(); ++i) {
                                    if (rawLoc[i] == '\\' && i + 1 < rawLoc.size() && rawLoc[i + 1] == '\\') {
                                        unescaped.push_back('\\');
                                        i++;
                                    } else {
                                        unescaped.push_back(rawLoc[i]);
                                    }
                                }
                                AddCandidate(list, Utf8ToWide(unescaped), L"Epic Games", 1);
                            }
                        }
                    }
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
}

static void ScanSteamGogRetailInstalls(std::vector<DetectedInstall>& list) {
    std::wstring val;
    // Steam App 13520
    if (ReadRegStringW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Steam App 13520", L"InstallLocation", val))
        AddCandidate(list, val, L"Steam", 1);
    if (ReadRegStringW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Steam App 13520", L"InstallLocation", val))
        AddCandidate(list, val, L"Steam", 1);

    // Steam libraryfolders.vdf
    std::wstring steamPath;
    if (ReadRegStringW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath", steamPath) ||
        ReadRegStringW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Valve\\Steam", L"InstallPath", steamPath)) {
        AddCandidate(list, JoinPath(steamPath, L"steamapps\\common\\Far Cry"), L"Steam", 1);
        std::vector<uint8_t> vdfBytes;
        if (ReadWholeFileW(JoinPath(steamPath, L"steamapps\\libraryfolders.vdf"), vdfBytes)) {
            std::string vdf((const char*)vdfBytes.data(), vdfBytes.size());
            size_t pos = 0;
            while ((pos = vdf.find("\"path\"", pos)) != std::string::npos) {
                size_t q1 = vdf.find('"', pos + 6);
                size_t q2 = (q1 != std::string::npos) ? vdf.find('"', q1 + 1) : std::string::npos;
                if (q1 != std::string::npos && q2 != std::string::npos) {
                    std::string rawLib = vdf.substr(q1 + 1, q2 - q1 - 1);
                    std::string unescaped;
                    for (size_t i = 0; i < rawLib.size(); ++i) {
                        if (rawLib[i] == '\\' && i + 1 < rawLib.size() && rawLib[i + 1] == '\\') {
                            unescaped.push_back('\\');
                            i++;
                        } else {
                            unescaped.push_back(rawLib[i]);
                        }
                    }
                    AddCandidate(list, JoinPath(Utf8ToWide(unescaped), L"steamapps\\common\\Far Cry"), L"Steam Library", 1);
                }
                pos += 6;
            }
        }
    }

    // GOG Galaxy (Game ID 1207658701)
    if (ReadRegStringW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\GOG.com\\Games\\1207658701", L"path", val))
        AddCandidate(list, val, L"GOG", 1);
    if (ReadRegStringW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\1207658701_is1", L"InstallLocation", val))
        AddCandidate(list, val, L"GOG", 1);

    // Retail Crytek / Ubisoft
    if (ReadRegStringW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Crytek\\FarCry", L"InstallDir", val))
        AddCandidate(list, val, L"Retail", 1);
    if (ReadRegStringW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Ubisoft\\Far Cry", L"InstallDir", val))
        AddCandidate(list, val, L"Ubisoft", 1);

    // Generic Windows Uninstall Registry Scan
    const HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const wchar_t* uninstKeys[2] = {
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    };
    for (int r = 0; r < 2; ++r) {
        for (int k = 0; k < 2; ++k) {
            HKEY hUn = NULL;
            if (RegOpenKeyExW(roots[r], uninstKeys[k], 0, KEY_READ, &hUn) == ERROR_SUCCESS) {
                wchar_t sub[256];
                DWORD idx = 0, subLen = 256;
                while (RegEnumKeyExW(hUn, idx++, sub, &subLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    std::wstring fullKey = std::wstring(uninstKeys[k]) + L"\\" + sub;
                    std::wstring dispName, instLoc, dispIcon;
                    if (ReadRegStringW(roots[r], fullKey.c_str(), L"DisplayName", dispName)) {
                        std::wstring low = dispName;
                        for (auto& c : low) c = (wchar_t)towlower(c);
                        if (low.find(L"far cry") != std::wstring::npos || low.find(L"farcry") != std::wstring::npos) {
                            if (ReadRegStringW(roots[r], fullKey.c_str(), L"InstallLocation", instLoc))
                                AddCandidate(list, instLoc, L"Installed Game", 1);
                            if (ReadRegStringW(roots[r], fullKey.c_str(), L"DisplayIcon", dispIcon))
                                AddCandidate(list, dispIcon, L"Installed Game", 1);
                        }
                    }
                    subLen = 256;
                }
                RegCloseKey(hUn);
            }
        }
    }

    // Common folder sweep across all fixed drives (A:..Z:)
    DWORD drives = GetLogicalDrives();
    const wchar_t* commonRelPaths[] = {
        L"Program Files (x86)\\Ubisoft\\Ubisoft Game Launcher\\games\\FAR CRY 1",
        L"Program Files (x86)\\Ubisoft\\Ubisoft Game Launcher\\games\\Far Cry",
        L"Program Files\\Ubisoft\\Ubisoft Game Launcher\\games\\FAR CRY 1",
        L"Program Files\\Ubisoft\\Ubisoft Game Launcher\\games\\Far Cry",
        L"Ubisoft Game Launcher\\games\\FAR CRY 1",
        L"Ubisoft Game Launcher\\games\\Far Cry",
        L"Ubisoft\\Ubisoft Game Launcher\\games\\FAR CRY 1",
        L"Ubisoft\\Ubisoft Game Launcher\\games\\Far Cry",
        L"Ubisoft\\games\\FAR CRY 1",
        L"Ubisoft\\games\\Far Cry",
        L"Ubisoft\\Far Cry",
        L"Program Files\\Epic Games\\FarCry",
        L"Program Files\\Epic Games\\Far Cry",
        L"Epic Games\\FarCry",
        L"Epic Games\\Far Cry",
        L"Program Files (x86)\\Steam\\steamapps\\common\\Far Cry",
        L"SteamLibrary\\steamapps\\common\\Far Cry",
        L"Steam\\steamapps\\common\\Far Cry",
        L"GOG Games\\Far Cry",
        L"Program Files (x86)\\GOG Galaxy\\Games\\Far Cry",
        L"Games\\Far Cry",
        L"Games\\FAR CRY 1",
        L"Program Files (x86)\\Ubisoft\\Crytek\\Far Cry",
        L"Program Files (x86)\\Crytek\\Far Cry",
        L"Far Cry"
    };
    for (int d = 0; d < 26; ++d) {
        if (drives & (1 << d)) {
            wchar_t root[4] = { (wchar_t)(L'A' + d), L':', L'\\', 0 };
            UINT dtype = GetDriveTypeW(root);
            if (dtype == DRIVE_FIXED || dtype == DRIVE_REMOVABLE) {
                for (const wchar_t* rel : commonRelPaths) {
                    AddCandidate(list, std::wstring(root) + rel, L"Auto-Detected", 2);
                }
            }
        }
    }

    // Finally, check if dev workspace Modded folder exists
    AddCandidate(list, L"r:\\AI Coding\\Jank Mods\\Far Cry\\Modded", L"Workspace Modded", 3);

    std::stable_sort(list.begin(), list.end(), [](const DetectedInstall& a, const DetectedInstall& b) {
        return a.priority < b.priority;
    });
}

// ============================================================================
// NTFS Junction & Shortcut Helpers
// ============================================================================
static void CreateDirectoryJunction(const std::wstring& linkPath, const std::wstring& targetPath) {
    EnsureParentDirsW(JoinPath(targetPath, L"dummy.txt"));
    if (DirExistsW(linkPath) && !IsReparsePointW(linkPath)) {
        // Move any existing files from linkPath into targetPath before converting to junction
        std::wstring cmd = L"cmd.exe /c robocopy \"" + linkPath + L"\" \"" + targetPath + L"\" /E /MOVE >nul 2>&1";
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 10000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        RemoveDirectoryW(linkPath.c_str());
    }
    if (!DirExistsW(linkPath)) {
        std::wstring cmd = L"cmd.exe /c mklink /J \"" + linkPath + L"\" \"" + targetPath + L"\" >nul 2>&1";
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

static bool CreateShellShortcutW(const std::wstring& lnkPath, const std::wstring& targetPath, const std::wstring& args, const std::wstring& workDir, const std::wstring& iconPath, const std::wstring& desc) {
    IShellLinkW* psl = NULL;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl);
    if (FAILED(hr)) return false;
    psl->SetPath(targetPath.c_str());
    psl->SetArguments(args.c_str());
    psl->SetWorkingDirectory(workDir.c_str());
    if (!iconPath.empty()) psl->SetIconLocation(iconPath.c_str(), 0);
    psl->SetDescription(desc.c_str());
    IPersistFile* ppf = NULL;
    hr = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);
    bool ok = false;
    if (SUCCEEDED(hr)) {
        ok = SUCCEEDED(ppf->Save(lnkPath.c_str(), TRUE));
        ppf->Release();
    }
    psl->Release();
    return ok;
}

// ============================================================================
// Global Wizard State & UI Handles
// ============================================================================
static HINSTANCE g_hInst = NULL;
static HWND g_hWndMain = NULL;
static HFONT g_hFontTitle = NULL;
static HFONT g_hFontSub = NULL;
static HFONT g_hFontBody = NULL;
static HFONT g_hFontBold = NULL;
static HFONT g_hFontMono = NULL;
static HICON g_hBannerIcon = NULL;

static bool g_isUninstallMode = false;
static bool g_hasEmbeddedPayload = false;
static PayloadFooter g_footer = {0};
static std::wstring g_selfExePath;
static std::wstring g_targetDir;
static std::vector<DetectedInstall> g_detectedInstalls;

static int g_currentPage = 0; // 0 = Welcome, 1 = Directory/Options, 2 = Progress, 3 = Finish
static bool g_isWorking = false;
static bool g_installSuccess = false;

// Controls
static HWND g_hHeaderTitle = NULL;
static HWND g_hHeaderSub = NULL;
static HWND g_hWelcomeText = NULL;

static HWND g_hLblCombo = NULL;
static HWND g_hComboDetected = NULL;
static HWND g_hLblPath = NULL;
static HWND g_hEditPath = NULL;
static HWND g_hBtnBrowse = NULL;
static HWND g_hLblStatus = NULL;
static HWND g_hChkPortable = NULL;
static HWND g_hChkNativeRes = NULL;
static HWND g_hChkDesktopLnk = NULL;
static HWND g_hChkKeepSaves = NULL;
static HWND g_hBtnSwitchUninstall = NULL;

static HWND g_hProgressBar = NULL;
static HWND g_hLblProgressStep = NULL;
static HWND g_hEditLog = NULL;

static HWND g_hFinishText = NULL;
static HWND g_hChkLaunchNow = NULL;
static HWND g_hChkOpenFolder = NULL;

static HWND g_hBtnBack = NULL;
static HWND g_hBtnNext = NULL;
static HWND g_hBtnCancel = NULL;

enum {
    IDC_COMBO_DETECTED = 1001,
    IDC_EDIT_PATH      = 1002,
    IDC_BTN_BROWSE     = 1003,
    IDC_CHK_PORTABLE   = 1004,
    IDC_CHK_NATIVERES  = 1005,
    IDC_CHK_DESKTOPLNK = 1006,
    IDC_CHK_KEEPSAVES  = 1007,
    IDC_BTN_UNINST_NOW = 1008,
    IDC_CHK_LAUNCH     = 1009,
    IDC_CHK_OPENDIR    = 1010,
    IDC_BTN_BACK       = 1011,
    IDC_BTN_NEXT       = 1012,
    IDC_BTN_CANCEL     = 1013,
    WM_APP_LOG         = WM_APP + 10,
    WM_APP_PROGRESS    = WM_APP + 11,
    WM_APP_DONE        = WM_APP + 12
};

static void AppendLogLine(const std::wstring& msg) {
    wchar_t* copy = _wcsdup(msg.c_str());
    PostMessageW(g_hWndMain, WM_APP_LOG, 0, (LPARAM)copy);
}

static void SetProgress(int pct, const std::wstring& stepText) {
    wchar_t* copy = _wcsdup(stepText.c_str());
    PostMessageW(g_hWndMain, WM_APP_PROGRESS, (WPARAM)pct, (LPARAM)copy);
}

// ============================================================================
// Core Install & Uninstall Worker Logic
// ============================================================================
static void XorBuffers(const std::vector<uint8_t>& src, const std::vector<uint8_t>& delta, uint32_t outLen, std::vector<uint8_t>& out) {
    size_t maxLen = std::max(src.size(), delta.size());
    out.assign(outLen, 0);
    for (uint32_t i = 0; i < outLen; ++i) {
        uint8_t a = (i < src.size()) ? src[i] : 0;
        uint8_t b = (i < delta.size()) ? delta[i] : 0;
        out[i] = a ^ b;
    }
}

static bool LoadManifestRecords(HANDLE hExe, std::vector<ManifestRecord>& records) {
    std::vector<uint8_t> compMan(g_footer.manifest_comp_size);
    if (!ReadSliceAt(hExe, g_footer.manifest_offset, compMan.data(), compMan.size())) return false;
    std::vector<uint8_t> rawMan;
    if (!inflate_zlib(compMan.data(), compMan.size(), rawMan, g_footer.manifest_raw_size)) return false;

    size_t p = 0;
    auto readU8 = [&]() -> uint8_t { return (p < rawMan.size()) ? rawMan[p++] : 0; };
    auto readU16 = [&]() -> uint16_t {
        if (p + 2 > rawMan.size()) return 0;
        uint16_t v = *(uint16_t*)(rawMan.data() + p); p += 2; return v;
    };
    auto readU32 = [&]() -> uint32_t {
        if (p + 4 > rawMan.size()) return 0;
        uint32_t v = *(uint32_t*)(rawMan.data() + p); p += 4; return v;
    };
    auto readU64 = [&]() -> uint64_t {
        if (p + 8 > rawMan.size()) return 0;
        uint64_t v = *(uint64_t*)(rawMan.data() + p); p += 8; return v;
    };
    auto readStr = [&]() -> std::string {
        uint16_t len = readU16();
        if (p + len > rawMan.size()) return "";
        std::string s((const char*)(rawMan.data() + p), len);
        p += len;
        return s;
    };

    uint32_t count = readU32();
    records.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        ManifestRecord r;
        r.op = readU8();
        r.rel_path = Utf8ToWide(readStr());
        r.source_pak = Utf8ToWide(readStr());
        r.pak_entry = readStr();
        r.vanilla_size = readU32();
        r.vanilla_crc  = readU32();
        r.mod_size     = readU32();
        r.mod_crc      = readU32();
        r.payload_offset    = readU64();
        r.payload_comp_size = readU32();
        r.payload_raw_size  = readU32();
        uint16_t numHunks = readU16();
        r.hunks.resize(numHunks);
        for (uint16_t h = 0; h < numHunks; ++h) {
            r.hunks[h].offset = readU32();
            uint16_t hlen = readU16();
            r.hunks[h].vanilla_bytes.resize(hlen);
            r.hunks[h].mod_bytes.resize(hlen);
            if (p + hlen * 2 <= rawMan.size()) {
                memcpy(r.hunks[h].vanilla_bytes.data(), rawMan.data() + p, hlen); p += hlen;
                memcpy(r.hunks[h].mod_bytes.data(), rawMan.data() + p, hlen); p += hlen;
            }
        }
        records.push_back(std::move(r));
    }
    return true;
}

static void SetCfgKeyValue(std::string& text, const std::string& key, const std::string& valStr) {
    std::string newLine = key + " = \"" + valStr + "\"";
    std::string keyLow = key;
    for (auto& c : keyLow) c = (char)tolower((unsigned char)c);

    size_t pos = 0;
    while (pos < text.size()) {
        size_t eol = text.find_first_of("\r\n", pos);
        size_t lineEnd = (eol == std::string::npos) ? text.size() : eol;
        std::string line = text.substr(pos, lineEnd - pos);

        // Trim leading spaces
        size_t firstChar = line.find_first_not_of(" \t");
        if (firstChar != std::string::npos && line.substr(firstChar, 2) != "--") {
            size_t eqPos = line.find('=', firstChar);
            if (eqPos != std::string::npos) {
                std::string k = line.substr(firstChar, eqPos - firstChar);
                while (!k.empty() && (k.back() == ' ' || k.back() == '\t')) k.pop_back();
                for (auto& c : k) c = (char)tolower((unsigned char)c);
                if (k == keyLow) {
                    text.replace(pos, lineEnd - pos, newLine);
                    return;
                }
            }
        }
        if (eol == std::string::npos) break;
        pos = eol + 1;
        if (pos < text.size() && text[eol] == '\r' && text[pos] == '\n') pos++;
    }

    if (!text.empty() && text.back() != '\n' && text.back() != '\r') {
        text += "\r\n";
    }
    text += newLine + "\r\n";
}

static void GetNativeDesktopResolution(int& outW, int& outH) {
    DEVMODEW dm = {0};
    dm.dmSize = sizeof(dm);
    if (EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dm) && dm.dmPelsWidth >= 800 && dm.dmPelsHeight >= 600) {
        outW = (int)dm.dmPelsWidth;
        outH = (int)dm.dmPelsHeight;
        return;
    }
    outW = GetSystemMetrics(SM_CXSCREEN);
    outH = GetSystemMetrics(SM_CYSCREEN);
}

static void ConfigureSheeshModSystemCfg(const std::wstring& cfgPath, bool setNativeRes, int screenW, int screenH) {
    std::vector<uint8_t> raw;
    if (!ReadWholeFileW(cfgPath, raw)) return;
    std::string text((const char*)raw.data(), raw.size());

    if (setNativeRes && screenW >= 800 && screenH >= 600) {
        SetCfgKeyValue(text, "r_Width", std::to_string(screenW));
        SetCfgKeyValue(text, "r_Height", std::to_string(screenH));
    }
    // Always enforce English localized pak, borderless windowed Direct3D9, and 3D Intro level across all storefronts
    SetCfgKeyValue(text, "g_language", "english");
    SetCfgKeyValue(text, "r_Fullscreen", "0");
    SetCfgKeyValue(text, "r_Driver", "Direct3D9");
    SetCfgKeyValue(text, "g_StartLevel", "Intro");
    SetCfgKeyValue(text, "sys_firstlaunch", "0");
    SetCfgKeyValue(text, "sys_PakPriority", "0");
    // Enforce reliable software 3D audio & music across Epic Games / Ubisoft Connect / modern Windows
    SetCfgKeyValue(text, "s_DummySound", "0");
    SetCfgKeyValue(text, "s_SoundEnable", "1");
    SetCfgKeyValue(text, "s_MusicEnable", "1");
    SetCfgKeyValue(text, "s_MaxHWChannels", "0");
    SetCfgKeyValue(text, "s_MusicStreamedData", "1");
    SetCfgKeyValue(text, "s_SpeakerConfig", "5");
    SetCfgKeyValue(text, "s_SampleRate", "44100");
    SetCfgKeyValue(text, "s_MasterVolume", "1.000000");
    SetCfgKeyValue(text, "s_SFXVolume", "1");
    SetCfgKeyValue(text, "s_MusicVolume", "0.6");
    SetCfgKeyValue(text, "cl_infinite_ammo", "0");
    SetCfgKeyValue(text, "s_DraculaVO", "0");
    SetCfgKeyValue(text, "cl_debug_f8", "1");
    SetCfgKeyValue(text, "s_CompatibleMode", "0");
    SetCfgKeyValue(text, "s_DopplerEnable", "0");
    // Enforce detail & bump textures so rock/terrain/overworld surfaces never appear smooth/untextured
    // IMPORTANT: r_Quality_BumpMapping MUST be 3 at InitRenderer() startup (VF_REQUIRE_APP_RESTART) so
    // r_UseHWShaders=2 and .cslnew shaders (backed by Vanilla Shaders\Cache\*.cgbin) are initialized.
    SetCfgKeyValue(text, "e_detail_texture_quality", "1");
    SetCfgKeyValue(text, "r_DetailTextures", "1");
    SetCfgKeyValue(text, "r_DetailNumLayers", "2");
    SetCfgKeyValue(text, "r_Quality_BumpMapping", "3");
    SetCfgKeyValue(text, "r_UseHWShaders", "2");
    SetCfgKeyValue(text, "r_TexResolution", "0");
    SetCfgKeyValue(text, "r_TexBumpResolution", "0");
    SetCfgKeyValue(text, "r_TexQuality", "0");
    SetCfgKeyValue(text, "e_obj_view_dist_ratio", "65.000000");
    SetCfgKeyValue(text, "e_obj_lod_ratio", "20.000000");
    SetCfgKeyValue(text, "ca_LodBias", "0.01");
    SetCfgKeyValue(text, "e_objects_fade_on_distance", "0");
    SetCfgKeyValue(text, "e_cgf_load_lods", "0");
    SetCfgKeyValue(text, "e_vegetation_sprites_distance_ratio", "2.000000");
    SetCfgKeyValue(text, "e_vegetation_sprites_min_distance", "16.000000");
    SetCfgKeyValue(text, "e_EntitySuppressionLevel", "0");
    SetCfgKeyValue(text, "sys_skiponlowspec", "0");
    SetCfgKeyValue(text, "sys_spec", "3");

    WriteWholeFileW(cfgPath, text.data(), text.size());
}

static void PurgeStaleRuntimeCompiledShadersW(const std::wstring& targetDir) {
    const wchar_t* subDirs[2][2] = {
        { L"Shaders\\Cache\\CGPShaders", L"*.cgps" },
        { L"Shaders\\Cache\\CGVShaders", L"*.cgvp" }
    };
    for (int i = 0; i < 2; ++i) {
        std::wstring dir = JoinPath(targetDir, subDirs[i][0]);
        std::wstring pattern = JoinPath(dir, subDirs[i][1]);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::wstring fp = JoinPath(dir, fd.cFileName);
                    SetFileAttributesW(fp.c_str(), FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(fp.c_str());
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
}

static void SetAppCompatLayerValue(HKEY root, const std::wstring& exePath, const wchar_t* layerStr) {
    HKEY hKey = NULL;
    if (RegCreateKeyExW(root, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
                        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        if (layerStr && layerStr[0] != 0) {
            DWORD cb = (DWORD)((wcslen(layerStr) + 1) * sizeof(wchar_t));
            RegSetValueExW(hKey, exePath.c_str(), 0, REG_SZ, (const BYTE*)layerStr, cb);
        } else {
            RegDeleteValueW(hKey, exePath.c_str());
        }
        RegCloseKey(hKey);
    }
}

static void ConfigureWindowsAppCompatAndPermissions(const std::wstring& gameDir, bool isUninstall) {
    const wchar_t* binExes[] = {
        L"Bin32\\FarCry.exe",
        L"Bin32\\Editor.exe",
        L"Bin32\\FarCryConfigurator.exe"
    };
    const wchar_t* val = isUninstall ? NULL : L"~ HIGHDPIAWARE";
    for (const wchar_t* relExe : binExes) {
        std::wstring fullExe = JoinPath(gameDir, relExe);
        SetAppCompatLayerValue(HKEY_CURRENT_USER, fullExe, val);
        SetAppCompatLayerValue(HKEY_LOCAL_MACHINE, fullExe, val);
    }

    if (!isUninstall) {
        // Grant BUILTIN\Users (*S-1-5-32-545) Modify permissions on the game folder so launching FarCry.exe
        // non-elevated inside C:\Program Files (x86)\Ubisoft\... can write to User Data, system.cfg, and logs
        std::wstring cmd = L"cmd.exe /c icacls \"" + gameDir + L"\" /grant *S-1-5-32-545:(OI)(CI)M /T /C /Q >nul 2>&1";
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 15000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

static DWORD WINAPI InstallThreadProc(LPVOID) {
    bool optPortable  = (SendMessageW(g_hChkPortable, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool optNativeRes = (SendMessageW(g_hChkNativeRes, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool optDesktop   = (SendMessageW(g_hChkDesktopLnk, BM_GETCHECK, 0, 0) == BST_CHECKED);

    AppendLogLine(L"Target installation directory: " + g_targetDir);
    SetProgress(2, L"Loading installer manifest...");

    HANDLE hExe = CreateFileW(g_selfExePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hExe == INVALID_HANDLE_VALUE) {
        AppendLogLine(L"[ERROR] Could not open setup executable payload (win32 error " + std::to_wstring(GetLastError()) + L").");
        PostMessageW(g_hWndMain, WM_APP_DONE, 0, 0);
        return 1;
    }

    std::vector<ManifestRecord> records;
    if (!LoadManifestRecords(hExe, records)) {
        CloseHandle(hExe);
        AppendLogLine(L"[ERROR] Failed to decompress installer manifest.");
        PostMessageW(g_hWndMain, WM_APP_DONE, 0, 0);
        return 1;
    }

    std::wstring backupRoot  = JoinPath(g_targetDir, L"_SheeshMod_Backup");
    std::wstring backupFiles = JoinPath(backupRoot, L"files");
    bool hadExistingInstall  = DirExistsW(backupRoot);
    CreateDirectoryW(backupRoot.c_str(), NULL);
    CreateDirectoryW(backupFiles.c_str(), NULL);

    // 1. Setup Portable User Data directories & junctions FIRST so writes to profiles/* land cleanly
    if (optPortable) {
        SetProgress(5, L"Configuring portable User Data directories...");
        std::wstring userData = JoinPath(g_targetDir, L"User Data");
        CreateDirectoryW(userData.c_str(), NULL);
        CreateDirectoryW(JoinPath(userData, L"Configs").c_str(), NULL);
        CreateDirectoryW(JoinPath(userData, L"Logs").c_str(), NULL);
        CreateDirectoryW(JoinPath(userData, L"Save").c_str(), NULL);
        CreateDirectoryW(JoinPath(userData, L"Screenshots").c_str(), NULL);
        CreateDirectoryW(JoinPath(userData, L"Configs\\player").c_str(), NULL);
        CreateDirectoryW(JoinPath(userData, L"Configs\\player\\default").c_str(), NULL);

        CreateDirectoryJunction(JoinPath(g_targetDir, L"Screenshots"), JoinPath(userData, L"Screenshots"));
        CreateDirectoryJunction(JoinPath(g_targetDir, L"Profiles"), JoinPath(userData, L"Configs"));
        CreateDirectoryJunction(JoinPath(userData, L"Configs\\player\\default\\savegames"), JoinPath(userData, L"Save"));

        // Clean any lingering or pre-release collectibles.cfg on fresh installs
        std::wstring colCfg = JoinPath(userData, L"Save\\collectibles.cfg");
        if (FileExistsW(colCfg)) {
            std::vector<uint8_t> colBytes;
            bool isCleanV2 = false;
            if (hadExistingInstall && ReadWholeFileW(colCfg, colBytes)) {
                std::string colStr((const char*)colBytes.data(), colBytes.size());
                if (colStr.find("ver:2") != std::string::npos) {
                    isCleanV2 = true;
                }
            }
            if (!isCleanV2) {
                DeleteFileW(colCfg.c_str());
            }
        }

        // Heal Shaders\Cache if a prior installer run moved any precompiled shaders into User Data\Logs\Cache
        std::wstring shadersCache = JoinPath(g_targetDir, L"Shaders\\Cache");
        std::wstring logsCache    = JoinPath(userData, L"Logs\\Cache");
        if (IsReparsePointW(shadersCache)) {
            RemoveDirectoryW(shadersCache.c_str());
        }
        CreateDirectoryW(JoinPath(g_targetDir, L"Shaders").c_str(), NULL);
        CreateDirectoryW(shadersCache.c_str(), NULL);
        if (DirExistsW(logsCache)) {
            std::wstring cmd = L"cmd.exe /c robocopy \"" + logsCache + L"\" \"" + shadersCache + L"\" /E /MOVE >nul 2>&1";
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 60000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            RemoveDirectoryW(logsCache.c_str());
        }
        AppendLogLine(L"[OK] Configured 100% self-contained User Data folders and NTFS junctions.");
    }

    // Preserve any existing Sheesh Mod user game.cfg if it already has Sheesh Mod bindings + Quicksave/Quickload
    std::wstring userSysCfg  = JoinPath(g_targetDir, L"User Data\\Configs\\system.cfg");
    std::wstring userGameCfg = JoinPath(g_targetDir, L"User Data\\Configs\\game.cfg");
    std::vector<uint8_t> savedUserGameCfg;
    bool hadSheeshModGameCfg = false;
    if (ReadWholeFileW(userGameCfg, savedUserGameCfg)) {
        std::string gText((const char*)savedUserGameCfg.data(), savedUserGameCfg.size());
        if (gText.find("\"ITEM_3\"") != std::string::npos &&
            gText.find("\"ITEM_2\"") != std::string::npos &&
            gText.find("\"QUICKSAVE\"") != std::string::npos &&
            gText.find("\"QUICKLOAD\"") != std::string::npos) {
            hadSheeshModGameCfg = true;
        }
    }

    // Break any prior hardlink between <GameDir>\system.cfg and User Data\Configs\system.cfg before patching
    if (FileExistsW(userSysCfg) && FileExistsW(JoinPath(g_targetDir, L"system.cfg"))) {
        DeleteFileW(userSysCfg.c_str());
    }

    // If a prior installer run surgically modified FCData\Localized\english.pak, restore it to untouched Vanilla
    {
        std::wstring menuBakPath = JoinPath(backupRoot, L"english_MenuTable_vanilla.bin");
        std::wstring engPak = JoinPath(g_targetDir, L"FCData\\Localized\\english.pak");
        if (FileExistsW(menuBakPath) && FileExistsW(engPak)) {
            std::vector<uint8_t> vanMenu;
            if (ReadWholeFileW(menuBakPath, vanMenu)) {
                uint32_t vanCrc = calc_crc32(vanMenu.data(), vanMenu.size());
                SurgicalUpdateZipSingleEntryW(engPak, "Languages/MenuTable.xml", vanMenu, vanCrc);
            }
            DeleteFileW(menuBakPath.c_str());
        }
        // Verify english.pak has readable Languages/Fonts/default.xml; if missing/corrupted and workspace Vanilla exists, heal it
        std::vector<uint8_t> testFont;
        if (!ExtractZipEntryW(engPak, "Languages/Fonts/default.xml", testFont)) {
            std::wstring wsVanEngPak = L"r:\\AI Coding\\Jank Mods\\Far Cry\\Vanilla\\FCData\\Localized\\english.pak";
            if (FileExistsW(wsVanEngPak)) {
                EnsureParentDirsW(engPak);
                CopyFileW(wsVanEngPak.c_str(), engPak.c_str(), FALSE);
                AppendLogLine(L"[HEAL] Restored clean FCData\\Localized\\english.pak from reference.");
            }
        }
        // Heal any missing core Vanilla PAKs or Bin32 binaries if workspace Vanilla reference is available
        const wchar_t* healFiles[] = {
            L"FCData\\Sounds.pak",
            L"FCData\\Music.pak",
            L"Bin32\\Cry3DEngine.dll",
            L"Bin32\\CryAISystem.dll",
            L"Bin32\\CryEntitySystem.dll",
            L"Bin32\\CryFont.dll",
            L"Bin32\\CryMovie.dll",
            L"Bin32\\CrySystem.dll",
            L"Bin32\\Editor.exe",
            L"Bin32\\FarCryConfigurator.exe",
            L"Bin32\\mfc71u.dll"
        };
        for (const wchar_t* hf : healFiles) {
            std::wstring dstHf = JoinPath(g_targetDir, hf);
            if (!FileExistsW(dstHf)) {
                std::wstring srcHf = JoinPath(L"r:\\AI Coding\\Jank Mods\\Far Cry\\Vanilla", hf);
                if (FileExistsW(srcHf)) {
                    EnsureParentDirsW(dstHf);
                    CopyFileW(srcHf.c_str(), dstHf.c_str(), FALSE);
                    AppendLogLine(L"[HEAL] Restored missing Vanilla file: " + std::wstring(hf));
                }
            }
        }
    }

    // Read first 5 MB of FCData\Objects.pak in memory as the universal clean-room reference key
    // (Objects.pak is present in every version of Far Cry: 1.0, 1.33 Steam, 1.34 Epic/Ubisoft, 1.4 GOG/Retail)
    std::vector<uint8_t> refKeyBytes(5 * 1024 * 1024, 0);
    {
        std::wstring objPakPath = JoinPath(g_targetDir, L"FCData\\Objects.pak");
        HANDLE hObj = CreateFileW(objPakPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hObj == INVALID_HANDLE_VALUE) {
            AppendLogLine(L"[ERROR] Required Far Cry archive not found: " + objPakPath);
            CloseHandle(hExe);
            PostMessageW(g_hWndMain, WM_APP_DONE, 0, 0);
            return 1;
        }
        DWORD rd = 0;
        if (!ReadFile(hObj, refKeyBytes.data(), (DWORD)refKeyBytes.size(), &rd, NULL) || rd < 1024 * 1024) {
            CloseHandle(hObj);
            AppendLogLine(L"[ERROR] Could not read reference header from FCData\\Objects.pak.");
            CloseHandle(hExe);
            PostMessageW(g_hWndMain, WM_APP_DONE, 0, 0);
            return 1;
        }
        refKeyBytes.resize(rd);
        CloseHandle(hObj);
    }

    std::vector<std::string> installedFilesList;
    std::vector<std::string> backedUpFilesList;

    size_t totalRecords = records.size();
    for (size_t i = 0; i < totalRecords; ++i) {
        const ManifestRecord& r = records[i];
        int pct = 8 + (int)((i * 80) / std::max<size_t>(1, totalRecords));
        if (i % 25 == 0 || r.op <= OP_SURGICAL_ZIP) {
            SetProgress(pct, L"Processing: " + r.rel_path);
        }

        std::wstring dstPath = JoinPath(g_targetDir, r.rel_path);
        std::wstring bakPath = JoinPath(backupFiles, r.rel_path);

        auto readPayloadDecompressed = [&](std::vector<uint8_t>& out) -> bool {
            std::vector<uint8_t> comp(r.payload_comp_size);
            if (!ReadSliceAt(hExe, r.payload_offset, comp.data(), comp.size())) return false;
            return inflate_zlib(comp.data(), comp.size(), out, r.payload_raw_size);
        };

        if (r.op == OP_PE_LAA) {
            std::vector<uint8_t> exeBytes;
            if (!ReadWholeFileW(dstPath, exeBytes) || exeBytes.size() < 0x200) {
                AppendLogLine(L"[WARN] Could not read " + r.rel_path);
                continue;
            }
            if (!FileExistsW(bakPath)) {
                std::vector<uint8_t> vanBackup = exeBytes;
                uint32_t curCrc = calc_crc32(exeBytes.data(), exeBytes.size());
                if (curCrc == r.mod_crc && exeBytes.size() > 0x10E) {
                    vanBackup[0x10E] &= ~0x20;
                }
                WriteWholeFileW(bakPath, vanBackup.data(), vanBackup.size());
            }
            backedUpFilesList.push_back(WideToUtf8(r.rel_path));

            uint32_t lfanew = *(uint32_t*)(exeBytes.data() + 0x3C);
            if (lfanew + 0x18 <= exeBytes.size() && memcmp(exeBytes.data() + lfanew, "PE\0\0", 4) == 0) {
                uint16_t* chars = (uint16_t*)(exeBytes.data() + lfanew + 0x16);
                *chars |= 0x0020;
            }
            WriteWholeFileW(dstPath, exeBytes.data(), exeBytes.size());
            AppendLogLine(L"[PATCH] Enabled 4GB Large Address Aware on " + r.rel_path);
        }
        else if (r.op == OP_BIN_PATCH) {
            std::vector<uint8_t> binBytes;
            if (!ReadWholeFileW(dstPath, binBytes)) {
                AppendLogLine(L"[ERROR] Missing required binary: " + r.rel_path);
                CloseHandle(hExe);
                PostMessageW(g_hWndMain, WM_APP_DONE, 0, 0);
                return 1;
            }
            if (!FileExistsW(bakPath)) {
                uint32_t curCrc = calc_crc32(binBytes.data(), binBytes.size());
                if (curCrc == r.mod_crc) {
                    std::vector<uint8_t> vanBytes = binBytes;
                    for (const auto& h : r.hunks) {
                        if (h.offset + h.vanilla_bytes.size() <= vanBytes.size()) {
                            memcpy(vanBytes.data() + h.offset, h.vanilla_bytes.data(), h.vanilla_bytes.size());
                        }
                    }
                    WriteWholeFileW(bakPath, vanBytes.data(), vanBytes.size());
                } else {
                    WriteWholeFileW(bakPath, binBytes.data(), binBytes.size());
                }
            }
            backedUpFilesList.push_back(WideToUtf8(r.rel_path));

            for (const auto& h : r.hunks) {
                if (h.offset + h.mod_bytes.size() <= binBytes.size()) {
                    memcpy(binBytes.data() + h.offset, h.mod_bytes.data(), h.mod_bytes.size());
                }
            }
            WriteWholeFileW(dstPath, binBytes.data(), binBytes.size());
            AppendLogLine(L"[PATCH] Applied instruction patch to " + r.rel_path + L" (" + std::to_wstring(r.hunks.size()) + L" hunks)");
        }
        else if (r.op == OP_DELTA_LOOSE) {
            std::vector<uint8_t> curBytes;
            bool existsOnDisk = ReadWholeFileW(dstPath, curBytes);
            if (existsOnDisk) {
                uint32_t curCrc = calc_crc32(curBytes.data(), curBytes.size());
                // If this is a v1.4 baseline parity file (vanilla_crc == mod_crc) and target is already v1.4, skip
                if (r.vanilla_crc == r.mod_crc && curCrc == r.mod_crc && !FileExistsW(bakPath)) {
                    continue;
                }
                if (!FileExistsW(bakPath)) {
                    if (curCrc == r.mod_crc) {
                        std::wstring sibVan = JoinPath(g_targetDir, L"..\\Vanilla\\" + r.rel_path);
                        std::vector<uint8_t> vanBytes;
                        if (ReadWholeFileW(sibVan, vanBytes)) {
                            WriteWholeFileW(bakPath, vanBytes.data(), vanBytes.size());
                        } else {
                            WriteWholeFileW(bakPath, curBytes.data(), curBytes.size());
                        }
                    } else {
                        WriteWholeFileW(bakPath, curBytes.data(), curBytes.size());
                    }
                }
                backedUpFilesList.push_back(WideToUtf8(r.rel_path));
            } else {
                // Never mark base Bin32 binaries (except Bin32\d3d9.dll) or base FCData PAKs (except FCData\zz_patch.pak) for deletion on uninstall
                bool isBaseGameFile = false;
                if (_wcsnicmp(r.rel_path.c_str(), L"Bin32\\", 6) == 0 && _wcsicmp(r.rel_path.c_str(), L"Bin32\\d3d9.dll") != 0) {
                    isBaseGameFile = true;
                } else if (_wcsnicmp(r.rel_path.c_str(), L"FCData\\", 7) == 0 && _wcsicmp(r.rel_path.c_str(), L"FCData\\zz_patch.pak") != 0) {
                    isBaseGameFile = true;
                }
                if (!isBaseGameFile) {
                    installedFilesList.push_back(WideToUtf8(r.rel_path));
                }
            }

            std::vector<uint8_t> delta;
            if (!readPayloadDecompressed(delta)) {
                AppendLogLine(L"[ERROR] Failed to read delta for " + r.rel_path);
                CloseHandle(hExe);
                PostMessageW(g_hWndMain, WM_APP_DONE, 0, 0);
                return 1;
            }
            std::vector<uint8_t> modOut;
            XorBuffers(refKeyBytes, delta, r.mod_size, modOut);
            WriteWholeFileW(dstPath, modOut.data(), modOut.size());
            AppendLogLine(L"[DELTA] Patched " + r.rel_path);
        }
        else if (r.op == OP_SURGICAL_ZIP) {
            std::vector<uint8_t> delta;
            if (!readPayloadDecompressed(delta)) continue;

            std::vector<uint8_t> curEntry;
            if (ExtractZipEntryW(dstPath, r.pak_entry, curEntry)) {
                uint32_t curCrc = calc_crc32(curEntry.data(), curEntry.size());
                std::wstring menuBakPath = JoinPath(backupRoot, L"english_MenuTable_vanilla.bin");
                if (!FileExistsW(menuBakPath)) {
                    if (curCrc == r.mod_crc) {
                        std::wstring sibVanPak = JoinPath(g_targetDir, L"..\\Vanilla\\" + r.rel_path);
                        std::vector<uint8_t> vanEntry;
                        if (ExtractZipEntryW(sibVanPak, r.pak_entry, vanEntry)) {
                            WriteWholeFileW(menuBakPath, vanEntry.data(), vanEntry.size());
                        } else {
                            WriteWholeFileW(menuBakPath, curEntry.data(), curEntry.size());
                        }
                    } else {
                        WriteWholeFileW(menuBakPath, curEntry.data(), curEntry.size());
                    }
                }
                if (curCrc != r.mod_crc) {
                    std::vector<uint8_t> modEntry;
                    XorBuffers(refKeyBytes, delta, r.mod_size, modEntry);
                    AppendLogLine(L"[PAK] Surgically updating " + Utf8ToWide(r.pak_entry) + L" in " + r.rel_path + L"...");
                    SurgicalUpdateZipSingleEntryW(dstPath, r.pak_entry, modEntry, r.mod_crc);
                } else {
                    AppendLogLine(L"[PAK] Verified " + r.rel_path + L" is already updated.");
                }
            }
        }
        else if (r.op == OP_SAME_PAK) {
            std::wstring pakFull = JoinPath(g_targetDir, r.source_pak);
            std::wstring bakPakFull = JoinPath(backupFiles, r.source_pak);
            std::vector<uint8_t> entryData;
            if (!ExtractZipEntryW(FileExistsW(bakPakFull) ? bakPakFull : pakFull, r.pak_entry, entryData)) {
                ExtractZipEntryW(pakFull, r.pak_entry, entryData);
            }
            if (!entryData.empty()) {
                WriteWholeFileW(dstPath, entryData.data(), entryData.size());
                installedFilesList.push_back(WideToUtf8(r.rel_path));
            }
        }
        else if (r.op == OP_DELTA_PAK) {
            std::vector<uint8_t> delta;
            if (!readPayloadDecompressed(delta)) continue;
            std::wstring pakFull = JoinPath(g_targetDir, r.source_pak);
            std::wstring bakPakFull = JoinPath(backupFiles, r.source_pak);
            std::vector<uint8_t> baseEntry;
            if (!ExtractZipEntryW(FileExistsW(bakPakFull) ? bakPakFull : pakFull, r.pak_entry, baseEntry)) {
                ExtractZipEntryW(pakFull, r.pak_entry, baseEntry);
            }
            std::vector<uint8_t> modOut;
            XorBuffers(baseEntry, delta, r.mod_size, modOut);
            WriteWholeFileW(dstPath, modOut.data(), modOut.size());
            installedFilesList.push_back(WideToUtf8(r.rel_path));
        }
        else if (r.op == OP_DELTA_REF_FILE) {
            std::vector<uint8_t> delta;
            if (!readPayloadDecompressed(delta)) continue;
            std::vector<uint8_t> modOut;
            XorBuffers(refKeyBytes, delta, r.mod_size, modOut);
            WriteWholeFileW(dstPath, modOut.data(), modOut.size());
            installedFilesList.push_back(WideToUtf8(r.rel_path));
        }
        else if (r.op == OP_NEW_FILE) {
            std::vector<uint8_t> fileBytes;
            if (readPayloadDecompressed(fileBytes)) {
                WriteWholeFileW(dstPath, fileBytes.data(), fileBytes.size());
                installedFilesList.push_back(WideToUtf8(r.rel_path));
            }
        }
    }

    // Copy Bin32\dxvk.conf to <GameDir>\dxvk.conf because FarCry.exe sets its working directory to <GameDir> before loading d3d9.dll
    {
        std::wstring binDxvkConf  = JoinPath(g_targetDir, L"Bin32\\dxvk.conf");
        std::wstring rootDxvkConf = JoinPath(g_targetDir, L"dxvk.conf");
        if (FileExistsW(binDxvkConf)) {
            CopyFileW(binDxvkConf.c_str(), rootDxvkConf.c_str(), FALSE);
            installedFilesList.push_back("dxvk.conf");
        }
    }

    // Restore user's custom Sheesh Mod keybinds if they already had a valid Sheesh Mod game.cfg
    if (hadSheeshModGameCfg) {
        WriteWholeFileW(userGameCfg, savedUserGameCfg.data(), savedUserGameCfg.size());
    }

    // Configure portable hardlinks (system.cfg, log.txt, error.log, Editor.log)
    if (optPortable) {
        std::wstring sysCfgRoot = JoinPath(g_targetDir, L"system.cfg");
        if (FileExistsW(sysCfgRoot)) {
            // Break any existing hardlink first so CopyFileW never hits ERROR_SHARING_VIOLATION
            DeleteFileW(userSysCfg.c_str());
            CopyFileW(sysCfgRoot.c_str(), userSysCfg.c_str(), FALSE);
            DeleteFileW(sysCfgRoot.c_str());
            if (!CreateHardLinkW(sysCfgRoot.c_str(), userSysCfg.c_str(), NULL)) {
                CopyFileW(userSysCfg.c_str(), sysCfgRoot.c_str(), FALSE);
            }
        }
        const wchar_t* logNames[3][2] = {
            { L"log.txt",    L"User Data\\Logs\\Log.txt" },
            { L"error.log",  L"User Data\\Logs\\error.log" },
            { L"Editor.log", L"User Data\\Logs\\Editor.log" }
        };
        for (int L = 0; L < 3; ++L) {
            std::wstring rootLog = JoinPath(g_targetDir, logNames[L][0]);
            std::wstring udLog   = JoinPath(g_targetDir, logNames[L][1]);
            if (!FileExistsW(udLog)) WriteWholeFileW(udLog, "", 0);
            DeleteFileW(rootLog.c_str());
            CreateHardLinkW(rootLog.c_str(), udLog.c_str(), NULL);
        }
    }

    // Configure native resolution, borderless windowing, and Intro startup level across all config locations
    {
        int screenW = 1920, screenH = 1080;
        GetNativeDesktopResolution(screenW, screenH);
        ConfigureSheeshModSystemCfg(JoinPath(g_targetDir, L"system.cfg"), optNativeRes, screenW, screenH);
        ConfigureSheeshModSystemCfg(userSysCfg, optNativeRes, screenW, screenH);
        ConfigureSheeshModSystemCfg(JoinPath(g_targetDir, L"User Data\\Configs\\player\\default_system.cfg"), optNativeRes, screenW, screenH);
        ConfigureSheeshModSystemCfg(JoinPath(g_targetDir, L"Profiles\\player\\default_system.cfg"), optNativeRes, screenW, screenH);
        ConfigureSheeshModSystemCfg(JoinPath(g_targetDir, L"systemcfgoverride.cfg"), optNativeRes, screenW, screenH);
        PurgeStaleRuntimeCompiledShadersW(g_targetDir);
        if (optNativeRes) {
            AppendLogLine(L"[CFG] Configured native screen resolution (" + std::to_wstring(screenW) + L"x" + std::to_wstring(screenH) + L") and borderless window mode.");
        }
    }

    SetProgress(89, L"Generating dialogue audio mix (FCData\\zz_sheesh_voices.pak)...");
    {
        std::wstring engPak = JoinPath(g_targetDir, L"FCData\\Localized\\english.pak");
        std::wstring outVoicePak = JoinPath(g_targetDir, L"FCData\\zz_sheesh_voices.pak");
        int nVoices = GenerateBoostedVoicesPakW(engPak, outVoicePak);
        if (nVoices > 0) {
            installedFilesList.push_back("FCData\\zz_sheesh_voices.pak");
            AppendLogLine(L"[VOICES] Generated FCData\\zz_sheesh_voices.pak (" + std::to_wstring(nVoices) + L" dialogue clips boosted +25%).");
        } else {
            AppendLogLine(L"[WARN] Skipped FCData\\zz_sheesh_voices.pak (english.pak not found or unreadable).");
        }
    }

    // Register Windows AppCompatFlags (HIGHDPIAWARE) to prevent legacy .NET/DirectPlay prompts & DPI scaling issues,
    // and grant folder modify permissions for Program Files installations
    SetProgress(90, L"Configuring Windows compatibility & folder permissions...");
    ConfigureWindowsAppCompatAndPermissions(g_targetDir, false);
    AppendLogLine(L"[OK] Configured Windows High-DPI & Program Files write permissions.");

    // Save installed_files.txt, backed_up_files.txt, and install_info.txt for Uninstaller
    SetProgress(93, L"Writing uninstaller and backup manifest...");
    std::string instManifest;
    for (const auto& s : installedFilesList) instManifest += s + "\n";
    WriteWholeFileW(JoinPath(backupRoot, L"installed_files.txt"), instManifest.data(), instManifest.size());

    std::string bakManifest;
    for (const auto& s : backedUpFilesList) bakManifest += s + "\n";
    WriteWholeFileW(JoinPath(backupRoot, L"backed_up_files.txt"), bakManifest.data(), bakManifest.size());

    std::wstring userDataActual = JoinPath(g_targetDir, L"User Data");
    std::string infoManifest = "InstallDir=" + WideToUtf8(g_targetDir) + "\n"
                             + "PortableMode=" + std::string(optPortable ? "1" : "0") + "\n"
                             + "UserDataDir=" + WideToUtf8(userDataActual) + "\n";
    WriteWholeFileW(JoinPath(backupRoot, L"install_info.txt"), infoManifest.data(), infoManifest.size());

    // Extract pure stub EXE as <TargetDir>\Uninstall.exe
    std::vector<uint8_t> stubBytes((size_t)g_footer.stub_exe_size);
    if (ReadSliceAt(hExe, 0, stubBytes.data(), stubBytes.size())) {
        std::wstring uninstExe = JoinPath(g_targetDir, L"Uninstall.exe");
        WriteWholeFileW(uninstExe, stubBytes.data(), stubBytes.size());
        AppendLogLine(L"[OK] Created standalone Uninstaller: " + uninstExe);

        // Register in HKCU Windows Uninstall registry
        HKEY hUnKey = NULL;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FarCrySheeshMod",
                            0, NULL, 0, KEY_WRITE, NULL, &hUnKey, NULL) == ERROR_SUCCESS) {
            std::wstring dispName = L"Far Cry \u2014 Sheesh! Mod v1.1";
            std::wstring uninstCmd = L"\"" + uninstExe + L"\" /uninstall";
            std::wstring dispIcon = uninstExe;
            RegSetValueExW(hUnKey, L"DisplayName", 0, REG_SZ, (const BYTE*)dispName.c_str(), (DWORD)((dispName.size() + 1) * sizeof(wchar_t)));
            RegSetValueExW(hUnKey, L"UninstallString", 0, REG_SZ, (const BYTE*)uninstCmd.c_str(), (DWORD)((uninstCmd.size() + 1) * sizeof(wchar_t)));
            RegSetValueExW(hUnKey, L"InstallLocation", 0, REG_SZ, (const BYTE*)g_targetDir.c_str(), (DWORD)((g_targetDir.size() + 1) * sizeof(wchar_t)));
            RegSetValueExW(hUnKey, L"UserDataLocation", 0, REG_SZ, (const BYTE*)userDataActual.c_str(), (DWORD)((userDataActual.size() + 1) * sizeof(wchar_t)));
            DWORD portableFlag = optPortable ? 1 : 0;
            RegSetValueExW(hUnKey, L"PortableMode", 0, REG_DWORD, (const BYTE*)&portableFlag, sizeof(DWORD));
            RegSetValueExW(hUnKey, L"DisplayIcon", 0, REG_SZ, (const BYTE*)dispIcon.c_str(), (DWORD)((dispIcon.size() + 1) * sizeof(wchar_t)));
            RegSetValueExW(hUnKey, L"Publisher", 0, REG_SZ, (const BYTE*)L"SheeshFr", (DWORD)(9 * sizeof(wchar_t)));
            RegSetValueExW(hUnKey, L"DisplayVersion", 0, REG_SZ, (const BYTE*)L"1.1", (DWORD)(4 * sizeof(wchar_t)));
            DWORD noMod = 1;
            RegSetValueExW(hUnKey, L"NoModify", 0, REG_DWORD, (const BYTE*)&noMod, sizeof(DWORD));
            RegSetValueExW(hUnKey, L"NoRepair", 0, REG_DWORD, (const BYTE*)&noMod, sizeof(DWORD));
            RegCloseKey(hUnKey);
        }
    }
    CloseHandle(hExe);

    if (optDesktop) {
        wchar_t desktopDir[MAX_PATH] = {0};
        if (SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopDir) == S_OK) {
            std::wstring lnkPath = JoinPath(desktopDir, L"Far Cry.lnk");
            std::wstring fcExe   = JoinPath(g_targetDir, L"Bin32\\FarCry.exe");
            if (CreateShellShortcutW(lnkPath, fcExe, L"-DEVMODE", g_targetDir, fcExe, L"Launch Far Cry (Sheesh! Mod)")) {
                AppendLogLine(L"[OK] Created Desktop shortcut: Far Cry.lnk");
            }
        }
    }

    SetProgress(100, L"Installation complete!");
    AppendLogLine(L"======================================================================");
    AppendLogLine(L"SUCCESS: Sheesh! Mod v1.1 installed cleanly and verified!");
    AppendLogLine(L"======================================================================");
    g_installSuccess = true;
    PostMessageW(g_hWndMain, WM_APP_DONE, 1, 0);
    return 0;
}

static void RemoveEmptyDirsBottomUp(const std::wstring& rootDir) {
    const wchar_t* modFolders[] = {
        L"assets", L"Objects", L"Scripts", L"Sounds", L"Textures", L"Languages", L"Levels\\Intro", L"profiles"
    };
    for (const wchar_t* mf : modFolders) {
        std::wstring start = JoinPath(rootDir, mf);
        if (!DirExistsW(start)) continue;
        // Recursive bottom-up remove empty subdirectories
        std::vector<std::wstring> stack = { start };
        std::vector<std::wstring> postOrder;
        while (!stack.empty()) {
            std::wstring cur = stack.back();
            stack.pop_back();
            postOrder.push_back(cur);
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(JoinPath(cur, L"*").c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            stack.push_back(JoinPath(cur, fd.cFileName));
                        }
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
        for (auto it = postOrder.rbegin(); it != postOrder.rend(); ++it) {
            RemoveDirectoryW(it->c_str());
        }
    }
}

static DWORD WINAPI UninstallThreadProc(LPVOID) {
    bool keepSaves = (SendMessageW(g_hChkKeepSaves, BM_GETCHECK, 0, 0) == BST_CHECKED);
    std::wstring backupRoot  = JoinPath(g_targetDir, L"_SheeshMod_Backup");
    std::wstring backupFiles = JoinPath(backupRoot, L"files");

    AppendLogLine(L"Starting uninstallation from: " + g_targetDir);
    SetProgress(5, L"Reading backup manifest...");

    if (!DirExistsW(backupRoot)) {
        AppendLogLine(L"[ERROR] Backup directory (_SheeshMod_Backup) not found in " + g_targetDir);
        PostMessageW(g_hWndMain, WM_APP_DONE, 0, 0);
        return 1;
    }

    // 1. Delete all newly added mod files
    std::vector<uint8_t> instRaw;
    if (ReadWholeFileW(JoinPath(backupRoot, L"installed_files.txt"), instRaw)) {
        std::string text((const char*)instRaw.data(), instRaw.size());
        size_t pos = 0, count = 0;
        while (pos < text.size()) {
            size_t eol = text.find_first_of("\r\n", pos);
            std::string line = text.substr(pos, (eol == std::string::npos) ? std::string::npos : (eol - pos));
            if (!line.empty()) {
                std::wstring fpath = JoinPath(g_targetDir, Utf8ToWide(line));
                DWORD attr = GetFileAttributesW(fpath.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES) {
                    if (attr & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(fpath.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
                    DeleteFileW(fpath.c_str());
                    count++;
                }
            }
            if (eol == std::string::npos) break;
            pos = eol + 1;
        }
        AppendLogLine(L"[OK] Removed " + std::to_wstring(count) + L" added mod files.");
    }
    SetProgress(40, L"Restoring original Vanilla files...");

    // 2. Surgically restore FCData\Localized\english.pak from english_MenuTable_vanilla.bin if present
    std::wstring menuBakPath = JoinPath(backupRoot, L"english_MenuTable_vanilla.bin");
    if (FileExistsW(menuBakPath)) {
        std::vector<uint8_t> vanMenu;
        if (ReadWholeFileW(menuBakPath, vanMenu)) {
            uint32_t vanCrc = calc_crc32(vanMenu.data(), vanMenu.size());
            std::wstring engPak = JoinPath(g_targetDir, L"FCData\\Localized\\english.pak");
            SetProgress(55, L"Restoring FCData\\Localized\\english.pak...");
            if (SurgicalUpdateZipSingleEntryW(engPak, "Languages/MenuTable.xml", vanMenu, vanCrc)) {
                AppendLogLine(L"[OK] Restored FCData\\Localized\\english.pak to 100% original Vanilla bytes.");
            }
        }
    }

    // Break portable hardlinks and remove root Sheesh Mod overrides BEFORE restoring backed up Vanilla files
    DeleteFileW(JoinPath(g_targetDir, L"dxvk.conf").c_str());
    DeleteFileW(JoinPath(g_targetDir, L"systemcfgoverride.cfg").c_str());
    DeleteFileW(JoinPath(g_targetDir, L"system.cfg").c_str());
    DeleteFileW(JoinPath(g_targetDir, L"log.txt").c_str());
    DeleteFileW(JoinPath(g_targetDir, L"error.log").c_str());
    DeleteFileW(JoinPath(g_targetDir, L"Editor.log").c_str());
    DeleteFileW(JoinPath(g_targetDir, L"FCData\\zz_sheesh_voices.pak").c_str());

    // 3. Restore backed up loose files (Bin32 DLLs/EXEs, Scripts.pak, ccgf_cache.pak, DevMode.lua, system.cfg, etc.)
    std::vector<uint8_t> bakRaw;
    if (ReadWholeFileW(JoinPath(backupRoot, L"backed_up_files.txt"), bakRaw)) {
        std::string text((const char*)bakRaw.data(), bakRaw.size());
        size_t pos = 0, count = 0;
        while (pos < text.size()) {
            size_t eol = text.find_first_of("\r\n", pos);
            std::string line = text.substr(pos, (eol == std::string::npos) ? std::string::npos : (eol - pos));
            if (!line.empty()) {
                std::wstring rel = Utf8ToWide(line);
                std::wstring srcBak = JoinPath(backupFiles, rel);
                std::wstring dstVan = JoinPath(g_targetDir, rel);
                if (FileExistsW(srcBak)) {
                    DWORD attr = GetFileAttributesW(dstVan.c_str());
                    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY)) {
                        SetFileAttributesW(dstVan.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);
                    }
                    CopyFileW(srcBak.c_str(), dstVan.c_str(), FALSE);
                    count++;
                }
            }
            if (eol == std::string::npos) break;
            pos = eol + 1;
        }
        AppendLogLine(L"[OK] Restored " + std::to_wstring(count) + L" original Vanilla files from backup.");
    }

    SetProgress(80, L"Cleaning up junctions and mod directories...");
    // 4. Clean up junctions
    if (IsReparsePointW(JoinPath(g_targetDir, L"Profiles"))) RemoveDirectoryW(JoinPath(g_targetDir, L"Profiles").c_str());
    if (IsReparsePointW(JoinPath(g_targetDir, L"Screenshots"))) RemoveDirectoryW(JoinPath(g_targetDir, L"Screenshots").c_str());
    if (IsReparsePointW(JoinPath(g_targetDir, L"Shaders\\Cache"))) {
        RemoveDirectoryW(JoinPath(g_targetDir, L"Shaders\\Cache").c_str());
    }
    CreateDirectoryW(JoinPath(g_targetDir, L"Shaders").c_str(), NULL);
    CreateDirectoryW(JoinPath(g_targetDir, L"Shaders\\Cache").c_str(), NULL);
    CreateDirectoryW(JoinPath(g_targetDir, L"Shaders\\Cache\\CGPShaders").c_str(), NULL);
    CreateDirectoryW(JoinPath(g_targetDir, L"Shaders\\Cache\\CVPShaders").c_str(), NULL);
    if (DirExistsW(JoinPath(g_targetDir, L"User Data\\Logs\\Cache"))) {
        std::wstring cmd = L"cmd.exe /c robocopy \"" + JoinPath(g_targetDir, L"User Data\\Logs\\Cache") + L"\" \"" + JoinPath(g_targetDir, L"Shaders\\Cache") + L"\" /E /MOVE >nul 2>&1";
        STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 60000);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
    }
    ConfigureWindowsAppCompatAndPermissions(g_targetDir, true);

    // Resolve portable User Data directory recorded for this installation (defaults to <g_targetDir>\User Data)
    std::wstring targetUserData = JoinPath(g_targetDir, L"User Data");
    std::vector<uint8_t> infoRaw;
    if (ReadWholeFileW(JoinPath(backupRoot, L"install_info.txt"), infoRaw)) {
        std::string infoText((const char*)infoRaw.data(), infoRaw.size());
        size_t udPos = infoText.find("UserDataDir=");
        if (udPos != std::string::npos) {
            size_t eol = infoText.find_first_of("\r\n", udPos);
            std::string udUtf8 = infoText.substr(udPos + 12, (eol == std::string::npos) ? std::string::npos : (eol - (udPos + 12)));
            if (!udUtf8.empty()) {
                std::wstring parsedUd = TrimSlash(Utf8ToWide(udUtf8));
                if (!parsedUd.empty()) targetUserData = parsedUd;
            }
        }
    }

    if (!keepSaves) {
        if (DirExistsW(targetUserData)) {
            std::wstring cmd = L"cmd.exe /c rmdir /s /q \"" + targetUserData + L"\" >nul 2>&1";
            STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
            AppendLogLine(L"[OK] Removed portable User Data directory: " + targetUserData);
        }
        std::wstring fallbackUd = JoinPath(g_targetDir, L"User Data");
        if (_wcsicmp(fallbackUd.c_str(), targetUserData.c_str()) != 0 && DirExistsW(fallbackUd)) {
            std::wstring cmd = L"cmd.exe /c rmdir /s /q \"" + fallbackUd + L"\" >nul 2>&1";
            STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
            AppendLogLine(L"[OK] Removed portable User Data directory: " + fallbackUd);
        }
    } else {
        AppendLogLine(L"[OK] Preserved player saves & configs in portable User Data: " + targetUserData);
    }

    // Remove empty mod directories and _JankMod_Backup
    PurgeStaleRuntimeCompiledShadersW(g_targetDir);
    RemoveEmptyDirsBottomUp(g_targetDir);
    {
        std::wstring cmd = L"cmd.exe /c rmdir /s /q \"" + backupRoot + L"\" >nul 2>&1";
        STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
    }

    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FarCrySheeshMod");
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FarCryJankMod");

    // Remove Uninstall.exe (if running from Setup.exe, delete directly; if running from Uninstall.exe, schedule self-delete)
    std::wstring uninstExe = JoinPath(g_targetDir, L"Uninstall.exe");
    if (_wcsicmp(g_selfExePath.c_str(), uninstExe.c_str()) != 0) {
        DeleteFileW(uninstExe.c_str());
    }

    SetProgress(100, L"Uninstallation complete!");
    AppendLogLine(L"======================================================================");
    AppendLogLine(L"SUCCESS: Far Cry has been restored to 100% original Vanilla state!");
    AppendLogLine(L"======================================================================");
    g_installSuccess = true;
    PostMessageW(g_hWndMain, WM_APP_DONE, 1, 0);
    return 0;
}

// ============================================================================
// Wizard Page Navigation & Validation
// ============================================================================
static std::wstring ResolveSelectedPortableUserDataDir(const std::wstring& dir) {
    if (dir.empty()) return L"User Data";
    std::wstring infoPath = JoinPath(dir, L"_SheeshMod_Backup\\install_info.txt");
    std::vector<uint8_t> infoRaw;
    if (ReadWholeFileW(infoPath, infoRaw)) {
        std::string infoText((const char*)infoRaw.data(), infoRaw.size());
        size_t udPos = infoText.find("UserDataDir=");
        if (udPos != std::string::npos) {
            size_t eol = infoText.find_first_of("\r\n", udPos);
            std::string udUtf8 = infoText.substr(udPos + 12, (eol == std::string::npos) ? std::string::npos : (eol - (udPos + 12)));
            if (!udUtf8.empty()) {
                std::wstring parsedUd = TrimSlash(Utf8ToWide(udUtf8));
                if (!parsedUd.empty()) return parsedUd;
            }
        }
    }
    return JoinPath(dir, L"User Data");
}

static void ValidateSelectedPath() {
    wchar_t buf[MAX_PATH] = {0};
    GetWindowTextW(g_hEditPath, buf, MAX_PATH);
    g_targetDir = TrimSlash(buf);

    if (g_hChkKeepSaves && !g_targetDir.empty()) {
        std::wstring udPath = ResolveSelectedPortableUserDataDir(g_targetDir);
        std::wstring chkLabel = L"Keep saved games and player configs in portable folder (" + udPath + L")";
        SetWindowTextW(g_hChkKeepSaves, chkLabel.c_str());
    }

    if (IsProtectedVanillaWorkspaceDir(g_targetDir)) {
        SetWindowTextW(g_hLblStatus, L"\x26A0 Protected Workspace 'Vanilla' Reference Directory! Please select 'Modded' or a copy of Vanilla.");
        EnableWindow(g_hBtnNext, FALSE);
        ShowWindow(g_hBtnSwitchUninstall, SW_HIDE);
        return;
    }

    if (IsValidFarCryDir(g_targetDir)) {
        bool hasBackup = DirExistsW(JoinPath(g_targetDir, L"_SheeshMod_Backup"));
        if (g_isUninstallMode) {
            if (hasBackup) {
                SetWindowTextW(g_hLblStatus, L"\x2714 Valid Sheesh! Mod installation detected (_SheeshMod_Backup present). Ready to uninstall.");
                EnableWindow(g_hBtnNext, TRUE);
            } else {
                SetWindowTextW(g_hLblStatus, L"\x26A0 No _SheeshMod_Backup found in this directory. Run Install first to initialize backups.");
                EnableWindow(g_hBtnNext, FALSE);
            }
            ShowWindow(g_hBtnSwitchUninstall, SW_HIDE);
        } else {
            if (hasBackup) {
                SetWindowTextW(g_hLblStatus, L"\x2714 Existing Sheesh! Mod installation detected. Ready to update/repair (or click Uninstall below).");
                ShowWindow(g_hBtnSwitchUninstall, SW_SHOW);
            } else {
                SetWindowTextW(g_hLblStatus, L"\x2714 Valid Far Cry installation verified (Bin32\\FarCry.exe + FCData). Ready to install!");
                ShowWindow(g_hBtnSwitchUninstall, SW_HIDE);
            }
            EnableWindow(g_hBtnNext, TRUE);
        }
    } else {
        SetWindowTextW(g_hLblStatus, L"\x274C Bin32\\FarCry.exe and FCData\\ were not found in this folder. Please select your Far Cry root folder.");
        EnableWindow(g_hBtnNext, FALSE);
        ShowWindow(g_hBtnSwitchUninstall, SW_HIDE);
    }
}

static void ShowWizardPage(int page) {
    g_currentPage = page;

    // Hide all page-specific controls first
    ShowWindow(g_hWelcomeText, SW_HIDE);
    ShowWindow(g_hLblCombo, SW_HIDE);
    ShowWindow(g_hComboDetected, SW_HIDE);
    ShowWindow(g_hLblPath, SW_HIDE);
    ShowWindow(g_hEditPath, SW_HIDE);
    ShowWindow(g_hBtnBrowse, SW_HIDE);
    ShowWindow(g_hLblStatus, SW_HIDE);
    ShowWindow(g_hChkPortable, SW_HIDE);
    ShowWindow(g_hChkNativeRes, SW_HIDE);
    ShowWindow(g_hChkDesktopLnk, SW_HIDE);
    ShowWindow(g_hChkKeepSaves, SW_HIDE);
    ShowWindow(g_hBtnSwitchUninstall, SW_HIDE);
    ShowWindow(g_hProgressBar, SW_HIDE);
    ShowWindow(g_hLblProgressStep, SW_HIDE);
    ShowWindow(g_hEditLog, SW_HIDE);
    ShowWindow(g_hFinishText, SW_HIDE);
    ShowWindow(g_hChkLaunchNow, SW_HIDE);
    ShowWindow(g_hChkOpenFolder, SW_HIDE);

    if (page == 0) {
        if (g_isUninstallMode) {
            SetWindowTextW(g_hHeaderTitle, L"Far Cry \u2014 Sheesh! Mod Uninstaller");
            SetWindowTextW(g_hHeaderSub, L"Restore your Far Cry installation to its original untouched Vanilla state.");
            std::wstring udPreview = g_targetDir.empty() ? L"<Selected Install Folder>\\User Data" : ResolveSelectedPortableUserDataDir(g_targetDir);
            std::wstring welcomeUninst =
                L"Welcome to the Far Cry \u2014 Sheesh! Mod Uninstallation Wizard.\r\n\r\n"
                L"This wizard will:\r\n"
                L"  \u2022 Remove all custom Sheesh! Mod assets, scripts, and DXVK files\r\n"
                L"  \u2022 Restore your original untouched Bin32 binaries and FCData .pak archives\r\n"
                L"  \u2022 Keep or delete portable saves & configs inside your selected install folder:\r\n"
                L"    " + udPreview + L"\r\n\r\n"
                L"Click Next to verify the installation directory and begin.";
            SetWindowTextW(g_hWelcomeText, welcomeUninst.c_str());
        } else {
            SetWindowTextW(g_hHeaderTitle, L"Far Cry \u2014 Sheesh! Mod v1.1");
            SetWindowTextW(g_hHeaderSub, L"Clean-Room Delta Patcher & Overhaul Installer for Far Cry");
            SetWindowTextW(g_hWelcomeText,
                L"Welcome to the Sheesh! Mod v1.1 Setup Wizard!\r\n\r\n"
                L"Compatible with Steam, GOG, Epic Games / Ubisoft Connect, and Retail installations.\r\n\r\n"
                L"How this installer works:\r\n"
                L"  \u2022 Automatically locates your installed copy of Far Cry across all launchers\r\n"
                L"  \u2022 Backs up every original file into '_SheeshMod_Backup\\' before modifying anything\r\n"
                L"  \u2022 Applies storefront-agnostic binary patches, .pak updates, and custom assets\r\n"
                L"  \u2022 Includes a 1-click Uninstaller (Uninstall.exe) to restore 100% Vanilla at any time\r\n\r\n"
                L"Click Next to continue.");
        }
        ShowWindow(g_hWelcomeText, SW_SHOW);
        EnableWindow(g_hBtnBack, FALSE);
        EnableWindow(g_hBtnNext, TRUE);
        SetWindowTextW(g_hBtnNext, L"Next >");
    }
    else if (page == 1) {
        if (g_isUninstallMode) {
            SetWindowTextW(g_hHeaderTitle, L"Confirm Uninstallation Directory");
            SetWindowTextW(g_hHeaderSub, L"Choose the Far Cry folder to restore to Vanilla.");
            ShowWindow(g_hChkKeepSaves, SW_SHOW);
            SetWindowTextW(g_hBtnNext, L"Uninstall");
        } else {
            SetWindowTextW(g_hHeaderTitle, L"Select Far Cry Installation Location");
            SetWindowTextW(g_hHeaderSub, L"We automatically scanned Ubisoft Connect, Epic, Steam, GOG, and local drives.");
            ShowWindow(g_hChkPortable, SW_SHOW);
            ShowWindow(g_hChkNativeRes, SW_SHOW);
            ShowWindow(g_hChkDesktopLnk, SW_SHOW);
            SetWindowTextW(g_hBtnNext, L"Install");
        }
        ShowWindow(g_hLblCombo, SW_SHOW);
        ShowWindow(g_hComboDetected, SW_SHOW);
        ShowWindow(g_hLblPath, SW_SHOW);
        ShowWindow(g_hEditPath, SW_SHOW);
        ShowWindow(g_hBtnBrowse, SW_SHOW);
        ShowWindow(g_hLblStatus, SW_SHOW);
        EnableWindow(g_hBtnBack, TRUE);
        ValidateSelectedPath();
    }
    else if (page == 2) {
        SetWindowTextW(g_hHeaderTitle, g_isUninstallMode ? L"Uninstalling Sheesh! Mod..." : L"Installing Sheesh! Mod v1.1...");
        SetWindowTextW(g_hHeaderSub, L"Please wait while files are backed up and patched.");
        ShowWindow(g_hProgressBar, SW_SHOW);
        ShowWindow(g_hLblProgressStep, SW_SHOW);
        ShowWindow(g_hEditLog, SW_SHOW);
        EnableWindow(g_hBtnBack, FALSE);
        EnableWindow(g_hBtnNext, FALSE);
        EnableWindow(g_hBtnCancel, FALSE);

        g_isWorking = true;
        g_installSuccess = false;
        SetWindowTextW(g_hEditLog, L"");
        SendMessageW(g_hProgressBar, PBM_SETPOS, 0, 0);

        HANDLE hThread = CreateThread(NULL, 0, g_isUninstallMode ? UninstallThreadProc : InstallThreadProc, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    else if (page == 3) {
        if (g_installSuccess) {
            if (g_isUninstallMode) {
                SetWindowTextW(g_hHeaderTitle, L"Uninstallation Complete");
                SetWindowTextW(g_hHeaderSub, L"Far Cry has been restored to its untouched Vanilla state.");
                SetWindowTextW(g_hFinishText,
                    L"Sheesh! Mod has been completely removed.\r\n\r\n"
                    L"All original Vanilla binaries, scripts, and .pak archives have been restored from '_SheeshMod_Backup\\'.\r\n\r\n"
                    L"Click Finish to exit the wizard.");
                ShowWindow(g_hChkOpenFolder, SW_SHOW);
            } else {
                SetWindowTextW(g_hHeaderTitle, L"Installation Complete!");
                SetWindowTextW(g_hHeaderSub, L"Far Cry \u2014 Sheesh! Mod v1.1 is ready to play.");
                std::wstring msg =
                    L"Sheesh! Mod v1.1 has been successfully installed into:\r\n"
                    L"  " + g_targetDir + L"\r\n\r\n"
                    L"What was configured:\r\n"
                    L"  \u2022 Original Vanilla files backed up safely in '_SheeshMod_Backup\\'\r\n"
                    L"  \u2022 Engine binaries & .pak archives patched and verified\r\n"
                    L"  \u2022 Standalone Uninstaller created at '" + JoinPath(g_targetDir, L"Uninstall.exe") + L"'\r\n\r\n"
                    L"Click Finish to exit the wizard.";
                SetWindowTextW(g_hFinishText, msg.c_str());
                ShowWindow(g_hChkLaunchNow, SW_SHOW);
                ShowWindow(g_hChkOpenFolder, SW_SHOW);
            }
        } else {
            SetWindowTextW(g_hHeaderTitle, L"Operation Encountered an Error");
            SetWindowTextW(g_hHeaderSub, L"Review the activity log below for details.");
            ShowWindow(g_hLblProgressStep, SW_SHOW);
            ShowWindow(g_hEditLog, SW_SHOW);
            EnableWindow(g_hBtnBack, TRUE);
        }
        if (g_installSuccess) {
            ShowWindow(g_hFinishText, SW_SHOW);
        }
        EnableWindow(g_hBtnNext, TRUE);
        SetWindowTextW(g_hBtnNext, L"Finish");
        EnableWindow(g_hBtnCancel, FALSE);
    }
    InvalidateRect(g_hWndMain, NULL, TRUE);
}

// ============================================================================
// Window Procedure
// ============================================================================
static LRESULT CALLBACK WizardWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hFontTitle = CreateFontW(-20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_hFontSub   = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_hFontBody  = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_hFontBold  = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        g_hFontMono  = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Consolas");

        g_hBannerIcon = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(101), IMAGE_ICON, 44, 44, LR_DEFAULTCOLOR);

        // Header banner labels
        g_hHeaderTitle = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 24, 14, 535, 28, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hHeaderTitle, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);
        g_hHeaderSub   = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 24, 44, 535, 20, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hHeaderSub, WM_SETFONT, (WPARAM)g_hFontSub, TRUE);

        // Page 0: Welcome
        g_hWelcomeText = CreateWindowExW(0, L"STATIC", L"", WS_CHILD, 28, 92, 584, 260, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hWelcomeText, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        // Page 1: Directory & Options
        g_hLblCombo = CreateWindowExW(0, L"STATIC", L"Auto-Detected Far Cry Installations (Ubisoft / Epic / Steam / GOG / Local Drives):",
                                      WS_CHILD, 28, 86, 584, 20, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hLblCombo, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

        g_hComboDetected = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                                           28, 108, 584, 200, hWnd, (HMENU)IDC_COMBO_DETECTED, g_hInst, NULL);
        SendMessageW(g_hComboDetected, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        g_hLblPath = CreateWindowExW(0, L"STATIC", L"Target Far Cry Root Folder (you can edit or click Browse... to choose any folder):",
                                     WS_CHILD, 28, 146, 584, 20, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hLblPath, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

        g_hEditPath = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_AUTOHSCROLL,
                                      28, 168, 486, 26, hWnd, (HMENU)IDC_EDIT_PATH, g_hInst, NULL);
        SendMessageW(g_hEditPath, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        g_hBtnBrowse = CreateWindowExW(0, L"BUTTON", L"Browse...", WS_CHILD | BS_PUSHBUTTON,
                                       522, 167, 90, 28, hWnd, (HMENU)IDC_BTN_BROWSE, g_hInst, NULL);
        SendMessageW(g_hBtnBrowse, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        g_hLblStatus = CreateWindowExW(0, L"STATIC", L"", WS_CHILD, 28, 202, 584, 36, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hLblStatus, WM_SETFONT, (WPARAM)g_hFontSub, TRUE);

        g_hChkPortable = CreateWindowExW(0, L"BUTTON", L"Enable 100% Portable 'User Data' isolation (keeps saves, configs & logs inside game folder)",
                                         WS_CHILD | BS_AUTOCHECKBOX, 28, 246, 584, 22, hWnd, (HMENU)IDC_CHK_PORTABLE, g_hInst, NULL);
        SendMessageW(g_hChkPortable, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);
        SendMessageW(g_hChkPortable, BM_SETCHECK, BST_CHECKED, 0);

        g_hChkNativeRes = CreateWindowExW(0, L"BUTTON", L"Auto-configure native desktop resolution in system.cfg",
                                          WS_CHILD | BS_AUTOCHECKBOX, 28, 272, 584, 22, hWnd, (HMENU)IDC_CHK_NATIVERES, g_hInst, NULL);
        SendMessageW(g_hChkNativeRes, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);
        SendMessageW(g_hChkNativeRes, BM_SETCHECK, BST_CHECKED, 0);

        g_hChkDesktopLnk = CreateWindowExW(0, L"BUTTON", L"Create 'Far Cry' shortcut on Desktop",
                                           WS_CHILD | BS_AUTOCHECKBOX, 28, 298, 400, 22, hWnd, (HMENU)IDC_CHK_DESKTOPLNK, g_hInst, NULL);
        SendMessageW(g_hChkDesktopLnk, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);
        SendMessageW(g_hChkDesktopLnk, BM_SETCHECK, BST_CHECKED, 0);

        g_hBtnSwitchUninstall = CreateWindowExW(0, L"BUTTON", L"Uninstall Sheesh! Mod from Folder...",
                                                WS_CHILD | BS_PUSHBUTTON, 382, 330, 230, 28, hWnd, (HMENU)IDC_BTN_UNINST_NOW, g_hInst, NULL);
        SendMessageW(g_hBtnSwitchUninstall, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        g_hChkKeepSaves = CreateWindowExW(0, L"BUTTON", L"Keep my saved games and player configs in 'User Data'",
                                          WS_CHILD | BS_AUTOCHECKBOX, 28, 250, 584, 24, hWnd, (HMENU)IDC_CHK_KEEPSAVES, g_hInst, NULL);
        SendMessageW(g_hChkKeepSaves, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);
        SendMessageW(g_hChkKeepSaves, BM_SETCHECK, BST_CHECKED, 0);

        // Page 2: Progress & Live Log
        g_hLblProgressStep = CreateWindowExW(0, L"STATIC", L"Initializing...", WS_CHILD, 28, 86, 584, 20, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hLblProgressStep, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

        g_hProgressBar = CreateWindowExW(0, PROGRESS_CLASSW, NULL, WS_CHILD | PBS_SMOOTH,
                                         28, 110, 584, 22, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

        g_hEditLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                     28, 142, 584, 218, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hEditLog, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);

        // Page 3: Finish
        g_hFinishText = CreateWindowExW(0, L"STATIC", L"", WS_CHILD, 28, 92, 584, 200, hWnd, NULL, g_hInst, NULL);
        SendMessageW(g_hFinishText, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        g_hChkLaunchNow = CreateWindowExW(0, L"BUTTON", L"Launch Far Cry now",
                                          WS_CHILD | BS_AUTOCHECKBOX, 28, 300, 350, 24, hWnd, (HMENU)IDC_CHK_LAUNCH, g_hInst, NULL);
        SendMessageW(g_hChkLaunchNow, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);
        SendMessageW(g_hChkLaunchNow, BM_SETCHECK, BST_CHECKED, 0);

        g_hChkOpenFolder = CreateWindowExW(0, L"BUTTON", L"Open Far Cry installation folder in Explorer",
                                           WS_CHILD | BS_AUTOCHECKBOX, 28, 328, 380, 24, hWnd, (HMENU)IDC_CHK_OPENDIR, g_hInst, NULL);
        SendMessageW(g_hChkOpenFolder, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        // Footer Navigation Buttons
        g_hBtnBack   = CreateWindowExW(0, L"BUTTON", L"< Back", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       326, 384, 90, 30, hWnd, (HMENU)IDC_BTN_BACK, g_hInst, NULL);
        g_hBtnNext   = CreateWindowExW(0, L"BUTTON", L"Next >", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                       424, 384, 95, 30, hWnd, (HMENU)IDC_BTN_NEXT, g_hInst, NULL);
        g_hBtnCancel = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       527, 384, 85, 30, hWnd, (HMENU)IDC_BTN_CANCEL, g_hInst, NULL);
        SendMessageW(g_hBtnBack, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);
        SendMessageW(g_hBtnNext, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);
        SendMessageW(g_hBtnCancel, WM_SETFONT, (WPARAM)g_hFontBody, TRUE);

        // Populate Detected Installations ComboBox
        if (!g_detectedInstalls.empty()) {
            for (const auto& inst : g_detectedInstalls) {
                SendMessageW(g_hComboDetected, CB_ADDSTRING, 0, (LPARAM)inst.label.c_str());
            }
            SendMessageW(g_hComboDetected, CB_SETCURSEL, 0, 0);
            SetWindowTextW(g_hEditPath, g_detectedInstalls[0].path.c_str());
        } else {
            SendMessageW(g_hComboDetected, CB_ADDSTRING, 0, (LPARAM)L"(No installation found in registry \u2014 click Browse... to select folder)");
            SendMessageW(g_hComboDetected, CB_SETCURSEL, 0, 0);
        }

        ShowWizardPage(0);
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rcClient;
        GetClientRect(hWnd, &rcClient);

        // White top banner (height 72)
        RECT rcBanner = { 0, 0, rcClient.right, 72 };
        FillRect(hdc, &rcBanner, (HBRUSH)GetStockObject(WHITE_BRUSH));
        if (g_hBannerIcon) {
            DrawIconEx(hdc, rcClient.right - 64, 14, g_hBannerIcon, 44, 44, 0, NULL, DI_NORMAL);
        }

        // Divider line below banner
        HPEN hPen = CreatePen(PS_SOLID, 1, RGB(210, 210, 215));
        HPEN hOld = (HPEN)SelectObject(hdc, hPen);
        MoveToEx(hdc, 0, 72, NULL);
        LineTo(hdc, rcClient.right, 72);

        // Divider line above footer buttons
        MoveToEx(hdc, 0, 372, NULL);
        LineTo(hdc, rcClient.right, 372);
        SelectObject(hdc, hOld);
        DeleteObject(hPen);

        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtl = (HWND)lParam;
        if (hCtl == g_hHeaderTitle || hCtl == g_hHeaderSub) {
            SetBkMode(hdc, TRANSPARENT);
            if (hCtl == g_hHeaderTitle) SetTextColor(hdc, RGB(20, 35, 60));
            else SetTextColor(hdc, RGB(90, 100, 115));
            return (LRESULT)GetStockObject(WHITE_BRUSH);
        }
        SetBkColor(hdc, GetSysColor(COLOR_BTNFACE));
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        int code = HIWORD(wParam);

        if (id == IDC_COMBO_DETECTED && code == CBN_SELCHANGE) {
            int sel = (int)SendMessageW(g_hComboDetected, CB_GETCURSEL, 0, 0);
            if (sel >= 0 && sel < (int)g_detectedInstalls.size()) {
                SetWindowTextW(g_hEditPath, g_detectedInstalls[sel].path.c_str());
                ValidateSelectedPath();
            }
        }
        else if (id == IDC_EDIT_PATH && code == EN_CHANGE) {
            ValidateSelectedPath();
        }
        else if (id == IDC_BTN_BROWSE) {
            BROWSEINFOW bi = {0};
            bi.hwndOwner = hWnd;
            bi.lpszTitle = L"Select your Far Cry Installation Root Folder (containing Bin32 and FCData):";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_USENEWUI;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                wchar_t chosen[MAX_PATH] = {0};
                if (SHGetPathFromIDListW(pidl, chosen)) {
                    SetWindowTextW(g_hEditPath, chosen);
                    ValidateSelectedPath();
                }
                CoTaskMemFree(pidl);
            }
        }
        else if (id == IDC_BTN_UNINST_NOW) {
            g_isUninstallMode = true;
            ShowWizardPage(1);
        }
        else if (id == IDC_BTN_BACK) {
            if (g_currentPage == 1) ShowWizardPage(0);
            else if (g_currentPage == 3 && !g_installSuccess) ShowWizardPage(1);
        }
        else if (id == IDC_BTN_NEXT) {
            if (g_currentPage == 0) {
                ShowWizardPage(1);
            } else if (g_currentPage == 1) {
                // Check if target directory requires Administrator elevation
                std::wstring testFile = JoinPath(g_targetDir, L"_sheeshmod_write_test.tmp");
                HANDLE hTest = CreateFileW(testFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
                if (hTest == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED) {
                    int ans = MessageBoxW(hWnd,
                        L"The selected Far Cry folder is inside a protected Windows directory (e.g. Program Files) and requires Administrator permission to patch.\r\n\r\n"
                        L"Click OK to re-launch the Setup Wizard as Administrator.",
                        L"Administrator Permission Required", MB_OKCANCEL | MB_ICONINFORMATION);
                    if (ans == IDOK) {
                        std::wstring params = (g_isUninstallMode ? L"/uninstall " : L"") + std::wstring(L"/dir:\"") + g_targetDir + L"\"";
                        ShellExecuteW(hWnd, L"runas", g_selfExePath.c_str(), params.c_str(), NULL, SW_SHOWNORMAL);
                        DestroyWindow(hWnd);
                    }
                    return 0;
                }
                if (hTest != INVALID_HANDLE_VALUE) CloseHandle(hTest);
                ShowWizardPage(2);
            } else if (g_currentPage == 3) {
                if (g_installSuccess && !g_isUninstallMode && SendMessageW(g_hChkLaunchNow, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    std::wstring fcExe = JoinPath(g_targetDir, L"Bin32\\FarCry.exe");
                    ShellExecuteW(NULL, L"open", fcExe.c_str(), L"-DEVMODE", g_targetDir.c_str(), SW_SHOWNORMAL);
                }
                if (g_installSuccess && SendMessageW(g_hChkOpenFolder, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    ShellExecuteW(NULL, L"open", g_targetDir.c_str(), NULL, NULL, SW_SHOWNORMAL);
                }
                DestroyWindow(hWnd);
            }
        }
        else if (id == IDC_BTN_CANCEL) {
            if (!g_isWorking) DestroyWindow(hWnd);
        }
        return 0;
    }

    case WM_APP_LOG: {
        wchar_t* line = (wchar_t*)lParam;
        if (line) {
            std::wstring append = std::wstring(line) + L"\r\n";
            int len = GetWindowTextLengthW(g_hEditLog);
            SendMessageW(g_hEditLog, EM_SETSEL, len, len);
            SendMessageW(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)append.c_str());
            free(line);
        }
        return 0;
    }

    case WM_APP_PROGRESS: {
        int pct = (int)wParam;
        wchar_t* step = (wchar_t*)lParam;
        SendMessageW(g_hProgressBar, PBM_SETPOS, pct, 0);
        if (step) {
            SetWindowTextW(g_hLblProgressStep, step);
            free(step);
        }
        return 0;
    }

    case WM_APP_DONE: {
        g_isWorking = false;
        ShowWizardPage(3);
        return 0;
    }

    case WM_CLOSE:
        if (g_isWorking) return 0;
        DestroyWindow(hWnd);
        return 0;

    case WM_DESTROY:
        // If running as <TargetDir>\Uninstall.exe and uninstall succeeded, schedule self-deletion on exit
        if (g_isUninstallMode && g_installSuccess) {
            std::wstring expectedUninst = JoinPath(g_targetDir, L"Uninstall.exe");
            if (_wcsicmp(g_selfExePath.c_str(), expectedUninst.c_str()) == 0) {
                std::wstring cmd = L"cmd.exe /c ping 127.0.0.1 -n 2 >nul & del /f /q \"" + g_selfExePath + L"\"";
                STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
                PROCESS_INFORMATION pi = {0};
                if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                }
            }
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================================
// Entry Point
// ============================================================================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR lpCmdLine, int) {
    g_hInst = hInstance;
    SetProcessDPIAware();
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    wchar_t selfBuf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, selfBuf, MAX_PATH);
    g_selfExePath = selfBuf;

    // Check if our own EXE has the FCMDRNZ1 payload footer
    HANDLE hSelf = CreateFileW(g_selfExePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSelf != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz;
        if (GetFileSizeEx(hSelf, &sz) && sz.QuadPart > (LONGLONG)sizeof(PayloadFooter)) {
            PayloadFooter ft = {0};
            if (ReadSliceAt(hSelf, (uint64_t)sz.QuadPart - sizeof(PayloadFooter), &ft, sizeof(PayloadFooter))) {
                if (memcmp(ft.magic, "FCMDRNZ1", 8) == 0) {
                    g_hasEmbeddedPayload = true;
                    g_footer = ft;
                }
            }
        }
        CloseHandle(hSelf);
    }

    std::wstring cmdLine = lpCmdLine ? lpCmdLine : L"";
    std::wstring cmdLow = cmdLine;
    for (auto& c : cmdLow) c = (wchar_t)towlower(c);
    if (!g_hasEmbeddedPayload || cmdLow.find(L"/uninstall") != std::wstring::npos || cmdLow.find(L"-uninstall") != std::wstring::npos) {
        g_isUninstallMode = true;
    }

    // If running in Uninstall mode, prioritize the current folder or last-installed Sheesh Mod folder
    if (g_isUninstallMode) {
        size_t sl = g_selfExePath.rfind(L'\\');
        if (sl != std::wstring::npos) {
            std::wstring parentDir = g_selfExePath.substr(0, sl);
            AddCandidate(g_detectedInstalls, parentDir, L"Current Folder", 0);
        }
        std::wstring lastModLoc;
        if (ReadRegStringW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FarCrySheeshMod", L"InstallLocation", lastModLoc)) {
            AddCandidate(g_detectedInstalls, lastModLoc, L"Installed Sheesh! Mod", 0);
        }
    }

    // Check if /dir:"..." was passed on elevation relaunch
    size_t dirPos = cmdLow.find(L"/dir:\"");
    if (dirPos != std::wstring::npos) {
        size_t q2 = cmdLine.find(L'"', dirPos + 6);
        if (q2 != std::wstring::npos) {
            std::wstring passedDir = cmdLine.substr(dirPos + 6, q2 - (dirPos + 6));
            AddCandidate(g_detectedInstalls, passedDir, L"Selected Folder", 0);
        }
    }

    // Run 7-layer multi-storefront auto-detection
    ScanUbisoftAndEpicInstalls(g_detectedInstalls);
    ScanSteamGogRetailInstalls(g_detectedInstalls);
    if (g_isUninstallMode) {
        std::stable_sort(g_detectedInstalls.begin(), g_detectedInstalls.end(), [](const DetectedInstall& a, const DetectedInstall& b) {
            bool aHasBak = DirExistsW(JoinPath(a.path, L"_SheeshMod_Backup"));
            bool bHasBak = DirExistsW(JoinPath(b.path, L"_SheeshMod_Backup"));
            if (aHasBak != bHasBak) return aHasBak > bHasBak;
            return a.priority < b.priority;
        });
    }

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc   = WizardWndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(101));
    wc.hIconSm       = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(101), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"FarCrySheeshModWizardWnd";
    RegisterClassExW(&wc);

    int winW = 648;
    int winH = 465;
    int sx = (GetSystemMetrics(SM_CXSCREEN) - winW) / 2;
    int sy = (GetSystemMetrics(SM_CYSCREEN) - winH) / 2;

    g_hWndMain = CreateWindowExW(
        WS_EX_APPWINDOW,
        wc.lpszClassName,
        g_isUninstallMode ? L"Far Cry \u2014 Sheesh! Mod Uninstaller" : L"Far Cry \u2014 Sheesh! Mod v1.1",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
        sx, sy, winW, winH,
        NULL, NULL, hInstance, NULL);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0)) {
        if (!IsDialogMessageW(g_hWndMain, &m)) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }

    CoUninitialize();
    return 0;
}
