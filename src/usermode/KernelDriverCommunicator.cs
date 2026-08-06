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
        private const uint IOCTL_CDS_REGISTER_PID = 0x222000;
        private const string DEVICE_PATH = @"\\.\CdsProtect";

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            ref int lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        public static void RegisterCdsPid()
        {
            try
            {
                using (SafeFileHandle hDevice = CreateFile(
                    DEVICE_PATH,
                    0xC0000000, // GENERIC_READ | GENERIC_WRITE
                    0,
                    IntPtr.Zero,
                    3, // OPEN_EXISTING
                    0,
                    IntPtr.Zero))
                {
                    if (hDevice.IsInvalid)
                    {
                        CdsLogger.Audit("KernelDriverCommunicator", $"Warning: Failed to open kernel device. Error: {Marshal.GetLastWin32Error()}. Is the driver loaded?");
                        return;
                    }

                    int currentPid = Process.GetCurrentProcess().Id;
                    uint bytesReturned;
                    bool success = DeviceIoControl(
                        hDevice,
                        IOCTL_CDS_REGISTER_PID,
                        ref currentPid,
                        (uint)sizeof(int),
                        IntPtr.Zero,
                        0,
                        out bytesReturned,
                        IntPtr.Zero);

                    if (success)
                    {
                        CdsLogger.Audit("KernelDriverCommunicator", $"Successfully registered PID {currentPid} with Kernel Driver for Ring 0 protection.");
                    }
                    else
                    {
                        CdsLogger.Audit("KernelDriverCommunicator", $"Warning: IOCTL call failed. Error: {Marshal.GetLastWin32Error()}");
                    }
                }
            }
            catch (Exception ex)
            {
                CdsLogger.Audit("KernelDriverCommunicator", $"Exception during kernel communication: {ex.Message}");
            }
        }
    }
}
