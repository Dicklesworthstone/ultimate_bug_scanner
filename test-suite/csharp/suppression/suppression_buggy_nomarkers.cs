// GH #91 suppression fixture (bead A7) for the C# module, twin of
// suppression_buggy.cs: identical buggy code with every suppression marker
// removed, so a scan of this file must reproduce the native csharp findings
// (shell-backed process launches, Process.Start without validation, weak MD5
// hash creation, blocking Thread.Sleep, per-call HttpClient) that the
// markered twin suppresses.

using System;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;

public static class SuppressionBuggy
{
    // Arrangement 1: previous-line marker.
    public static void LaunchShellPrevLine(string userInput)
    {
        Process.Start("cmd.exe", "/C " + userInput);
    }

    // Arrangement 2: trailing marker on the flagged line itself.
    public static void LaunchToolTrailing()
    {
        var tool = new ProcessStartInfo("notepad.exe", "notes.txt");
        Process.Start(tool);
    }

    // Arrangement 3: multi-line statement, marker on a continuation line.
    public static void LaunchShellMultiline(string userInput)
    {
        Process.Start("cmd.exe", "/C " +
            userInput);
    }

    // Arrangement 4: formatter-relocated marker on the first line inside a block.
    public static void WeakHashInBlock()
    {
        using (var digest = MD5.Create())
        {
            _ = digest;
        }
    }

    // Arrangement 5: the marked twin names public diagnostic identifiers.
    // Pattern and AST diagnostics have separate identities for these calls.
    // This control omits both scopes and must retain both findings.
    // The matching code is identical to the marked operations.
    public static void RuleScopedPrevLine()
    {
        Thread.Sleep(5);
    }

    public static void RuleScopedTrailing()
    {
        var client = new HttpClient();
        _ = client;
    }
}
