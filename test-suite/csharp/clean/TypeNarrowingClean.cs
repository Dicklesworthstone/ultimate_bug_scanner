using System.Collections.Generic;

public static class TypeNarrowingClean
{
    public static int? Run(string rawInput, Dictionary<string, string> cache)
    {
        if (string.IsNullOrWhiteSpace(rawInput))
        {
            return null;
        }

        if (!cache.TryGetValue("token", out var token) || token == null)
        {
            return null;
        }

        return rawInput.Trim().Length + token.Length;
    }
}
