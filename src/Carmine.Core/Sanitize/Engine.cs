using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Carmine.Core.Sanitize.Rules;

namespace Carmine.Core.Sanitize;

public static partial class Engine
{
    // Shorter values are only replaced where a rule matched, so a short password doesn't clobber ordinary words.
    private const int MinCopyLength = 8;
    private const int Free = -1;
    private const int Copy = -2;

    private static readonly SearchValues<char> LabelStops = SearchValues.Create("<>" + Shared.Space);

    // Values that point at a secret instead of holding one: shell and Windows variables, command substitution,
    // template variables, placeholders, masks, and labels from an earlier pass. Also values that hold nothing.
    // Matched against the value with A-Z lowered, which is all that JavaScript's i flag folds.
    [GeneratedRegex("""^(?:\$[a-z0-9_]+|\$\{[^}]*\}|\$\([^)]*\)|%[a-z0-9_]+%|\{\{[^}]*\}\}|<[^<>]+>|\*+|\[(?:redacted|filtered|hidden|masked|removed)\]|null|undefined|true|false|none|nil)\z""")]
    private static partial Regex Reference();

    private sealed record Hit(string Rule, RuleBy By, string Kind, string Reason, string Value, DecodedJwt? Jwt)
    {
        public int Start { get; set; }
        public int End { get; set; }
    }

    private sealed record Region(int Start, int End, string Value, Hit? Hit);

    public static SanitizeResult Sanitize(string input, IReadOnlyList<Rule>? rules = null)
    {
        // Which taken finding (by index) or copy covers each character of the input.
        var owner = new int[input.Length];
        Array.Fill(owner, Free);
        var taken = ResolveOverlaps(input, FindAll(input, rules ?? RuleList.All), owner);
        // Before the regions are read, because a copy can widen a taken finding.
        var copies = FindCopies(input, taken, owner);
        var regions = taken.Select(hit => new Region(hit.Start, hit.End, hit.Value, hit)).Concat(copies).OrderBy(r => r.Start).ToList();

        var firstHit = new Dictionary<string, Hit>();
        foreach (var hit in taken.OrderBy(h => h.Start)) firstHit.TryAdd(hit.Value, hit);

        var labels = new Dictionary<string, string>();
        var changes = new List<Change>();
        var jwts = new List<LabeledJwt>();
        var output = new StringBuilder(input.Length);
        var pos = 0;
        var line = 1;
        foreach (var region in regions)
        {
            var source = firstHit[region.Value];
            if (!labels.TryGetValue(region.Value, out var label))
            {
                label = $"{source.Kind}#{labels.Count + 1}";
                labels.Add(region.Value, label);
                if (source.Jwt is { } jwt) jwts.Add(new LabeledJwt(label, jwt.Header, jwt.Claims));
            }
            line += CountNewlines(input, pos, region.Start);
            output.Append(input, pos, region.Start - pos).Append('<').Append(label).Append('>');
            var reason = region.Hit?.Reason ?? $"same value as {label}";
            changes.Add(new Change(label, source.Kind, region.Hit?.Rule ?? source.Rule, reason, line, region.Start, region.End, region.Value));
            line += CountNewlines(input, region.Start, region.End);
            pos = region.End;
        }
        return new SanitizeResult(output.Append(input, pos, input.Length - pos).ToString(), changes, jwts);
    }

    private static List<Hit> FindAll(string input, IReadOnlyList<Rule> rules) =>
    [
        .. from rule in rules
           from f in rule.Find(input)
           let value = f.End > f.Start ? input[f.Start..f.End] : ""
           where value.Length > 0 && !Reference().IsMatch(Shared.AsciiLower(value)) && !IsLabels(value)
           select new Hit(rule.Name, rule.By, f.Kind, f.Reason, value, f.Jwt) { Start = f.Start, End = f.End },
    ];

    // Most specific wins: format before context, then the longer span. A finding that overlaps one already
    // taken merges into it, so the union is replaced and nothing next to the specific match leaks. When it
    // overlaps several, each keeps its label and the letters and digits between them go to a neighbour.
    private static List<Hit> ResolveOverlaps(string input, List<Hit> hits, int[] owner)
    {
        var taken = new List<Hit>();
        void Claim(int id, int start, int end)
        {
            Array.Fill(owner, id, start, end - start);
            var t = taken[id];
            t.Start = Math.Min(t.Start, start);
            t.End = Math.Max(t.End, end);
        }
        // OrderBy is stable, as JavaScript's sort is.
        foreach (var hit in hits.OrderBy(h => h.By == RuleBy.Format ? 0 : 1).ThenByDescending(h => h.End - h.Start).ThenBy(h => h.Start))
        {
            var ids = new HashSet<int>();
            for (var i = hit.Start; i < hit.End; i++) if (owner[i] >= 0) ids.Add(owner[i]);
            if (ids.Count == 0)
            {
                taken.Add(hit);
                Array.Fill(owner, taken.Count - 1, hit.Start, hit.End - hit.Start);
            }
            else if (ids.Count == 1)
            {
                Claim(ids.First(), hit.Start, hit.End);
            }
            else
            {
                for (var i = hit.Start; i < hit.End;)
                {
                    if (owner[i] >= 0)
                    {
                        i++;
                        continue;
                    }
                    var end = i;
                    while (end < hit.End && owner[end] < 0) end++;
                    if (HasLetterOrNumber(input, i, end)) Claim(i > hit.Start ? owner[i - 1] : owner[end], i, end);
                    i = end;
                }
            }
        }
        return taken;
    }

    // Scans once. Values often share a prefix (every JWT starts eyJhbGci), so a prefix leads to the lengths
    // worth trying rather than to every value. Text that a merge replaced around a value counts as a copy of
    // that value too, so it goes wherever it repeats, even around a finding of the same value.
    private static List<Region> FindCopies(string input, List<Hit> taken, int[] owner)
    {
        var valueOfText = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var t in taken)
        {
            var merged = input[t.Start..t.End];
            if (merged != t.Value && merged.Length >= MinCopyLength) valueOfText[merged] = t.Value;
        }
        var anyMerged = valueOfText.Count > 0;
        foreach (var t in taken) if (t.Value.Length >= MinCopyLength) valueOfText[t.Value] = t.Value;

        var lengthsByPrefix = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        foreach (var text in valueOfText.Keys)
        {
            var prefix = text[..MinCopyLength];
            if (!lengthsByPrefix.TryGetValue(prefix, out var lengths)) lengthsByPrefix[prefix] = lengths = [];
            if (!lengths.Contains(text.Length))
            {
                lengths.Add(text.Length);
                lengths.Sort((a, b) => b - a);
            }
        }

        var copies = new List<Region>();
        // A copy goes on free text, or widens a taken finding of the same value that it covers.
        bool Place(int start, int end, string value)
        {
            var ids = new HashSet<int>();
            for (var i = start; i < end; i++) if (owner[i] != Free) ids.Add(owner[i]);
            if (ids.Count == 0)
            {
                Array.Fill(owner, Copy, start, end - start);
                copies.Add(new Region(start, end, value, null));
                return true;
            }
            var id = ids.First();
            if (ids.Count > 1 || id == Copy || taken[id].Value != value) return false;
            var t = taken[id];
            Array.Fill(owner, id, start, end - start);
            t.Start = Math.Min(t.Start, start);
            t.End = Math.Max(t.End, end);
            return true;
        }
        if (valueOfText.Count == 0) return copies;
        var texts = valueOfText.GetAlternateLookup<ReadOnlySpan<char>>();
        var prefixes = lengthsByPrefix.GetAlternateLookup<ReadOnlySpan<char>>();
        for (var at = 0; at + MinCopyLength <= input.Length; at++)
        {
            if ((!anyMerged && owner[at] != Free) || !prefixes.TryGetValue(input.AsSpan(at, MinCopyLength), out var lengths)) continue;
            foreach (var n in lengths)
            {
                if (at + n <= input.Length && texts.TryGetValue(input.AsSpan(at, n), out var value) && Place(at, at + n, value))
                {
                    at += n - 1;
                    break;
                }
            }
        }
        return copies;
    }

    // A loop rather than IndexOf, which would scan to the end of a long line for every change.
    private static int CountNewlines(string text, int from, int to)
    {
        var n = 0;
        for (var i = from; i < to; i++) if (text[i] == '\n') n++;
        return n;
    }

    // Output of an earlier pass: labels with only punctuation between them, such as <jwt#1>|<jwt#2>, and at
    // least one label on the first line. JavaScript reads this by code point (the u flag), so a letter
    // outside the BMP counts as a letter.
    private static bool IsLabels(string value)
    {
        var labelOnFirstLine = false;
        var lineEnded = false;
        for (var i = 0; i < value.Length;)
        {
            if (value[i] == '<')
            {
                var end = LabelEnd(value, i);
                if (end < 0) return false;
                labelOnFirstLine |= !lineEnded;
                i = end;
                continue;
            }
            if (value[i] == '>' || IsLetterOrNumber(CodePointAt(value, i, value.Length, out var width))) return false;
            lineEnded |= value[i] is '\n' or '\r' or '\u2028' or '\u2029';
            i += width;
        }
        return labelOnFirstLine;
    }

    // Where <[^<>\s]+#\d+> starting at i ends, or -1.
    private static int LabelEnd(string value, int i)
    {
        var close = value.AsSpan(i + 1).IndexOfAny(LabelStops);
        if (close < 0 || value[i + 1 + close] != '>') return -1;
        close += i + 1;
        var hash = value.LastIndexOf('#', close - 1, close - i - 1);
        return hash > i + 1 && hash < close - 1 && !value.AsSpan(hash + 1, close - hash - 1).ContainsAnyExceptInRange('0', '9') ? close + 1 : -1;
    }

    // /[\p{L}\p{N}]/u over input[start..end], where a surrogate pair cut by either end is two lone surrogates.
    private static bool HasLetterOrNumber(string input, int start, int end)
    {
        for (var i = start; i < end;)
        {
            if (IsLetterOrNumber(CodePointAt(input, i, end, out var width))) return true;
            i += width;
        }
        return false;
    }

    private static int CodePointAt(string s, int i, int end, out int width)
    {
        width = char.IsHighSurrogate(s[i]) && i + 1 < end && char.IsLowSurrogate(s[i + 1]) ? 2 : 1;
        return width == 2 ? char.ConvertToUtf32(s[i], s[i + 1]) : s[i];
    }

    private static bool IsLetterOrNumber(int codePoint) =>
        CharUnicodeInfo.GetUnicodeCategory(codePoint) is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter
            or UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter
            or UnicodeCategory.DecimalDigitNumber or UnicodeCategory.LetterNumber or UnicodeCategory.OtherNumber;
}
