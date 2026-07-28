using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CapabilityDenialSystem
{
    /// <summary>
    /// Handles IOCTL communication between User-Mode C# Daemon and Kernel-Mode Driver.
    /// Used to register the CDS Process ID with the driver for ObRegisterCallbacks protection.
    /// </summary>
    public static class KernelDriverCommunicator
    {
        // Device name matching the kernel driver's symbolic link
        private const string DEVICE_NAME = @"\\.\CdsProtect";

        // IOCTL Code: CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
        // Calculation: (0x22 << 16) | (0x800 << 2) | 0 = 0x222000
        private const uint IOCTL_CDS_REGISTER_PID = 0x222000;

        // P/Invoke: CreateFileW to open device handle
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        // P/Invoke: DeviceIoControl for IOCTL communication
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        // P/Invoke: CloseHandle
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        // Constants for CreateFile
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_SHARE_READ = 1;
        private const uint FILE_SHARE_WRITE = 2;

        /// <summary>
        /// Registers the CDS Process ID with the kernel driver.
        /// Must be called after the driver is loaded and before protection is needed.
        /// </summary>
        /// <param name="pid">The Process ID of the CDS daemon</param>
        /// <returns>True if registration succeeded, false otherwise</returns>
        public static bool RegisterCdsPid(int pid)
        {
            try
            {
                // Open handle to the kernel device
                SafeFileHandle deviceHandle = CreateFile(
                    DEVICE_NAME,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                if (deviceHandle.IsInvalid)
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[KernelDriver] Failed to open device. Error: {error}");
                    Console.WriteLine("[KernelDriver] Kernel protection inactive. Continuing in User-Mode only.");
                    return false;
                }

                try
                {
                    // Allocate unmanaged memory for PID
                    IntPtr pidBuffer = Marshal.AllocHGlobal(sizeof(int));
                    try
                    {
                        // Write PID to buffer
                        Marshal.WriteInt32(pidBuffer, pid);

                        // Call DeviceIoControl
                        uint bytesReturned;
                        bool result = DeviceIoControl(
                            deviceHandle,
                            IOCTL_CDS_REGISTER_PID,
                            pidBuffer,
                            (uint)sizeof(int),
                            IntPtr.Zero,
                            0,
                            out bytesReturned,
                            IntPtr.Zero);

                        if (result)
                        {
                            Console.WriteLine($"[KernelDriver] Successfully registered CDS PID: {pid}");
                            Console.WriteLine("[KernelDriver] Kernel-mode protection ACTIVE.");
                            return true;
                        }
                        else
                        {
                            int error = Marshal.GetLastWin32Error();
                            Console.WriteLine($"[KernelDriver] IOCTL failed. Error: {error}");
                            return false;
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pidBuffer);
                    }
                }
                finally
                {
                    deviceHandle.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[KernelDriver] Exception during registration: {ex.Message}");
                Console.WriteLine("[KernelDriver] Kernel protection inactive. Continuing in User-Mode only.");
                return false;
            }
        }
    }
}
