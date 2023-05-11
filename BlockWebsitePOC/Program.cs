using NETCONLib;
using NetFwTypeLib;
using System.Net;

public static class FirewallManager
{
    static List<string> GetIPAddresses(string hostname)
    {
        IPAddress[] addresses = Dns.GetHostAddresses(hostname);
        List<string> addressList = new List<string>();

        foreach (IPAddress address in addresses)
        {
            addressList.Add(address.ToString());
        }

        return addressList;
    }
    static void Main(string[] args)
    {
        BlockWebsite("www.facebook.com");
        //UnblockWebsite("www.facebook.com");
    }

    static void BlockWebsite(string hostname)
    {
        string website = hostname;
        List<string> ipAddresses = GetIPAddresses(website);
        const int maxAddressesPerRule = 100;

        var firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

        for (int i = 0; i < ipAddresses.Count; i += maxAddressesPerRule)
        {
            var rule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));

            int addressesToAdd = Math.Min(maxAddressesPerRule, ipAddresses.Count - i);
            string addresses = string.Join(",", ipAddresses.GetRange(i, addressesToAdd));

            rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            rule.Description = $"Block access to {website}";
            rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
            rule.Enabled = true;
            rule.InterfaceTypes = "All";
            rule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
            rule.RemoteAddresses = addresses;
            rule.Name = $"Block access to {website} ({i / maxAddressesPerRule + 1})";

            //firewallPolicy.Rules.Add(rule);
            firewallPolicy.Rules.Remove(rule.Name);
        }
    }

    static void UnblockWebsite(string hostname)
    {
        // Get the current firewall policy
        INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));

        // Find the rule with the remote addresses to unblock
        INetFwRules firewallRules = firewallPolicy.Rules;
        string website = hostname;
        List<string> remoteAddresses = GetIPAddresses(website); // replace with a method to get the remote addresses of the website
        foreach (INetFwRule rule in firewallRules)
        {
            if (rule.RemoteAddresses == string.Join(",", remoteAddresses))
            {
                // Remove the rule from the firewall policy
                firewallRules.Remove(rule.Name);
                break;
            }
        }
    }
}

