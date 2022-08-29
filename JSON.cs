using NetTools;

namespace Whois
{
    internal class JSON
    {
        public object AddressRange { get; set; }
        public object Raw { get; set; }
        public object OrganizationName { get; set; }
        public object RespondedServers { get; set; }
        public object RegistrarRegistrationExpirationDate { get; internal set; }
        public object DomainStatus { get; internal set; }
        public object NameServers { get; internal set; }
        public object AllParts { get; internal set; }
        public object DomainServiceProvider { get; internal set; }
        public string[] EndMatter { get; internal set; }
    }
}