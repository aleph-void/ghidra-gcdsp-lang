// Stub for the logging function DSPTool's sources refer to (written for the GCDSP test suite).
#include "Common/Logging/Log.h"
namespace Common::Log {
void GenericLogFmtImpl(LogLevel, LogType, const char*, int, fmt::string_view, const fmt::format_args&) {}
}
