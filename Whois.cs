using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

using Whois.NET;

namespace Whois
{
    public static class Whois
    {
        public static string Who_is(string domain, bool debug = false)
        {
            if (debug) Debugger.Launch();
            var response = WhoisClient.Query(domain);
            var (raw, endMatter) = RemoveEndMatter(response.Raw);
            var json = new JSON
            {
                AddressRange = response.AddressRange?.ToString(),
                Raw = (from line in response.Raw.Split(['\r', '\n']) where line.Length > 0 select line).ToArray(),
                OrganizationName = response.OrganizationName,
                RespondedServers = response.RespondedServers,
                RegistrarRegistrationExpirationDate = ExtractPartFromRaw("Registrar Registration Expiration Date", "", raw),
                DomainStatus = ExtractPartFromRaw("Domain Status", "", raw).Split(' ')[0],
                NameServers = ExtractPartFromRaw("Name Server", ",", raw).ToLower(),
                AllParts = ExtractAllPartsFromRaw(raw),
                EndMatter = endMatter
            };
            return JsonConvert.SerializeObject(json);
        }

        private static (string raw, string[] moreInformation) RemoveEndMatter(string raw)
        {
            var miFound = false;
            var miList = new List<string>();
            var lines = (from line in raw.Split(['\r', '\n']) where line.Length > 0 select line).ToArray();
            var miFoundAt = lines.Count();
            for (var i = 0; i < lines.Count(); i++)
            {
                var line = lines[i];
                if (line.Contains(">>> Last update of WHOIS database"))
                {
                    miFound = true;
                    miFoundAt = i;
                }
                if (miFound)
                {
                    miList.Add(line.Trim());
                }
            }
            return (string.Join("\r\n", lines.Take(miFoundAt)), miList.ToArray());
        }

        private static (string raw, string[] domainServiceProvider) RemoveDomainServiceProvider(string raw)
        {
            var dsrFound = false;
            var dsrList = new List<string>();
            var lines = (from line in raw.Split(['\r', '\n']) where line.Length > 0 select line).ToArray();
            var dsrFoundAt = lines.Count();
            for (var i = 0; i < lines.Count(); i++)
            {
                var line = lines[i];
                if (dsrFound)
                {
                    dsrList.Add(line.Trim());
                }
                if (line.Contains("Domain Service Provider:"))
                {
                    dsrFound = true;
                    dsrFoundAt = i;
                }
            }
            return (string.Join("\r\n", lines.Take(dsrFoundAt)), dsrList.ToArray());
        }

        private static Dictionary<string, List<string>> ExtractAllPartsFromRaw(string raw)
        {
            var result = new Dictionary<string, List<string>>();
            raw = raw.Replace("For more information on Whois status codes, please visit", "More information: For more information on Whois status codes, please visit");
            raw = raw.Replace(">>>", "").Replace("<<<", "");
            var pairs = (from line
                        in raw.Split(['\r', '\n'])
                         where line.Length > 0
                         let pos = line.IndexOf(':')
                         let pair = new string[] {
                             pos == -1 ? line : line.Substring(0, pos).Trim(),
                             pos == -1 ? "" : line.Substring(pos + 1).Trim()
                         }
                         select pair);
            foreach (var pair in pairs)
            {
                if (result.ContainsKey(pair[0]))
                {
                    if (pair[1].Length > 0)
                        result[pair[0]].Add(pair[1]);
                }
                else
                {
                    var l = new List<string>() { pair[1] };
                    result[pair[0]] = l;
                }
            }
            return result;
        }

        private static string ExtractPartFromRaw(string v, string sep, string raw)
        {
            return string.Join(sep, (from line
                                    in raw.Split(['\r', '\n'])
                                     where line.Length > 0 && line.Contains(v)
                                     select line.Substring(line.IndexOf(":") + 1).Trim()).ToArray());
        }
    }
}
