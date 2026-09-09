using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

public static class AstRulePackBuggy
{
    public static async Task RunAsync(object gate, IEnumerable<int> values)
    {
        Task.Run(() => 42);
        Task.Factory.StartNew(() => 7);
        lock (gate)
        {
            await Task.Delay(1);
        }
        Parallel.ForEach(values, async item => { await Task.Delay(item); });

        var t = Task.Run(() => 1);
        var r = t.Result;
        t.GetAwaiter().GetResult();
        t.Wait();
        Task.Delay(10);
        ThreadPool.QueueUserWorkItem(_ => {});
        Thread.Sleep(100);
        new Thread(() => {});

        MD5.Create();
        SHA1.Create();
        new DESCryptoServiceProvider();
        new BinaryFormatter();
        new Random();
        new XmlDocument();

        try
        {
            var a = 1;
        }
        catch (Exception)
        {
        }

        try
        {
            var b = 2;
        }
        catch (Exception ex)
        {
            throw ex;
        }

        GC.Collect();
        Process.Start("calc.exe");
        goto target;
        target:
        Console.WriteLine("debug");
        new HttpClient();
    }
}
