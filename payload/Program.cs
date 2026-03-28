using System.Diagnostics;
using System.Runtime.InteropServices;

static class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int MessageBoxW(nint h, string t, string c, uint f);

    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    static extern nint GetModuleHandleW(nint n);

    [ThreadStatic]
    static int tls_val;

    static int Main()
    {
        var p = Process.GetCurrentProcess();
        uint pid = GetCurrentProcessId();
        string name = p.ProcessName;
        string path = p.MainModule?.FileName ?? "unknown";
        nint imagebase = GetModuleHandleW(0);

        tls_val = 42;
        int child = -1;
        var t = new System.Threading.Thread(() => { tls_val = 99; child = tls_val; });
        t.Start(); t.Join();

        int gc_ok = 0;
        var list = new System.Collections.Generic.List<byte[]>();
        for (int i = 0; i < 100; i++) list.Add(new byte[1024]);
        list.Clear();
        System.GC.Collect();
        gc_ok = 1;

        string info =
            "pid: " + pid + "\n" +
            "process: " + name + "\n" +
            "host path: " + path + "\n" +
            "host imagebase: 0x" + imagebase.ToString("x") + "\n" +
            "modules loaded: " + p.Modules.Count + "\n\n" +
            "tls main=" + tls_val + " child=" + child + " (expect 42/99)\n" +
            "gc: " + (gc_ok == 1 ? "ok" : "fail");

        try { System.IO.File.WriteAllText(@"C:\Users\n\Desktop\runpe_proof.txt", info); } catch {}

        MessageBoxW(0, info, "nativeaot reflective load", 0x40);
        return 0;
    }
}
