// GH #91 suppression fixture (bead A7) for the C# module, twin of
// suppression_buggy_nomarkers.cs (identical buggy code, no markers).
// Every native csharp finding below (the path:line code-sample lines the
// module rg-based categories print natively) carries a suppression marker
// in one of the documented arrangements, so a scan of this file must report
// zero finding lines, while the nomarkers twin reproduces them.
// Note: comments here deliberately avoid apostrophes; the shared lexer masks
// single-quote strings for C#, so a stray apostrophe would swallow markers.
// Prose never spells out the marker token, which would parse as a marker.

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
        // ubs:ignore -- fixture: marker on the line immediately above the finding
        Process.Start("cmd.exe", "/C " + userInput);
    }

    // Arrangement 2: trailing marker on the flagged line itself.
    public static void LaunchToolTrailing()
    {
        var tool = new ProcessStartInfo("notepad.exe", "notes.txt");
        Process.Start(tool); // ubs:ignore -- fixture: trailing marker on the flagged line
    }

    // Arrangement 3: multi-line statement, marker on a continuation line.
    public static void LaunchShellMultiline(string userInput)
    {
        Process.Start("cmd.exe", "/C " +
            userInput); // ubs:ignore -- fixture: marker on a physical line of a multi-line statement
    }

    // Arrangement 4: formatter-relocated marker on the first line inside a block.
    public static void WeakHashInBlock()
    {
        using (var digest = MD5.Create())
        {   // ubs:ignore -- fixture: formatter moved the marker off the flagged line into the block
            _ = digest;
        }
    }

    // Arrangement 5: rule-scoped markers (rule id in square brackets). The
    // csharp module code-sample lines carry no rule id, so a previous-line
    // scope suppresses through the runner flat same-line/previous-line path,
    // while the trailing scope is honored by the interval engine itself (the
    // bracketed rule id shows up in the printed sample line).
    public static void RuleScopedPrevLine()
    {
        // ubs:ignore[cs.thread-sleep-blocks] -- fixture: rule-scoped marker above the finding
        Thread.Sleep(5);
    }

    public static void RuleScopedTrailing()
    {
        var client = new HttpClient(); // ubs:ignore[cs.httpclient-per-call] -- fixture: rule-scoped trailing marker
        _ = client;
    }
}
