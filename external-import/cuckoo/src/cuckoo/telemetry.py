from stix2.v21.bundle import Bundle
from stix2.v21.common import ExternalReference
from stix2.v21.observables import File, NetworkTraffic, WindowsRegistryKey
from stix2.v21.sdo import Indicator, Report
from cuckoo.cuckoo import (
    cuckooReport,
    cuckooReportDropped,
    cuckooReportICMP,
    cuckooReportNetwork,
    cuckooReportSignature,
    cuckooReportTCPUDP,
)
from datetime import datetime
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2.v21 import (
    IPv4Address,
    AttackPattern,
    DomainName,
    Process,
    Relationship,
)


class openCTIInterface:
    def __init__(
        self,
        report: cuckooReport,
        helper: OpenCTIConnectorHelper,
        update,
        labels=[],
        CreateIndicator=False,
        CuckooURL="",
        EnableNetTraffic=False,
        EnableRegKeys=False,
        ReportScore=0,
    ):
        self.API = helper.api
        self.helper = helper
        self.CreateIndicator = CreateIndicator
        self.report = report
        self.labels = labels
        self.update = update
        self.cuckoo_url = CuckooURL
        self.EnableNetTraffic = EnableNetTraffic
        self.EnableRegKeys = EnableRegKeys
        self.ReportScore = ReportScore
        try:
            self.octiLabels = self.API.label.list()  # Get labels Once ;)
        except:
            self.octiLabels = self.API.label.list()

        self.processAndSubmit()  # This is where the magic happens

    # Get and Return STIX Patterning
    def getStixPattern(self, IOC, TYPE):
        IOCTypes = {
            "MD5": {
                "prefix": "file:hashes.'MD5'",
            },
            "SHA1": {
                "prefix": "file:hashes.'SHA-1'",
            },
            "SHA256": {
                "prefix": "file:hashes.'SHA-256'",
            },
            "SHA512": {
                "prefix": "file:hashes.'SHA-512'",
            },
            "IPV4": {
                "prefix": "ipv4-addr:value",
            },
            "IPV6": {
                "prefix": "ipv6-addr:value",
            },
            "FQDN": {
                "prefix": "domain-name:value",
            },
            "URL": {"prefix": "url:value"},
            "EMAIL": {
                "prefix": "email-addr:value",
            },
            "MAC": {
                "prefix": "mac-addr:value",
            },
            "PROCESS": {
                "prefix": "process:command_line",
            },
            "NETWORK-TRAFFIC": {
                "prefix": "network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value"
            },
        }
        return f"[{IOCTypes[TYPE.upper()]['prefix']}='{IOC.upper()}']"

    # STIX-erize IP info
    def createIPObs(self, hosts):
        IPObs = []
        for host in hosts:
            IPObs.append(IPv4Address(value=host))
            if self.CreateIndicator:
                STIXPattern = self.getStixPattern(host, "ipv4")
                IPind = Indicator(name=host, pattern=STIXPattern, pattern_type="stix")
                IPObs.append(IPind)
        return IPObs

    # STIX-erize DNS info
    def createDNSObs(self, DNSOBJ):
        DNSObs = []
        DNSRel = []
        for host in DNSOBJ:
            IP = IPv4Address(value=host["ip"])
            DNS = DomainName(
                value=host["domain"]
            )  # , resolves_to_refs=IP.id) ref https://github.com/OpenCTI-Platform/client-python/issues/155
            Rel = Relationship(
                source_ref=DNS.id, target_ref=IP.id, relationship_type="resolves-to"
            )

            if self.CreateIndicator:
                STIXPattern = self.getStixPattern(host["domain"], "FQDN")
                DNSind = Indicator(
                    name=host["domain"], pattern=STIXPattern, pattern_type="stix"
                )
                STIXPattern = self.getStixPattern(host["ip"], "ipv4")
                IPind = Indicator(
                    name=host["ip"], pattern=STIXPattern, pattern_type="stix"
                )
                DNSObs.extend((DNSind, IPind))
            DNSObs.extend((IP, DNS))
            DNSRel.append(Rel)

        return [DNSObs, DNSRel]

    def createRegKeysObs(self, reg_keys):
        return [WindowsRegistryKey(key=key) for key in reg_keys]

    def createProcessObs(self, procs):
        return [
            Process(
                pid=proc.pid,
                command_line=proc.command_line,
            )
            for proc in procs
        ]

    def createNetTrafficBlock(self, traffic: cuckooReportTCPUDP, protocol):
        srcIP = IPv4Address(value=traffic.src)
        dstIP = IPv4Address(value=traffic.dst)
        traffic = NetworkTraffic(
            src_ref=srcIP.id,
            dst_ref=dstIP.id,
            src_port=traffic.sport,
            dst_port=traffic.dport,
            protocols=[protocol],
        )
        return traffic

    def createNetICMPlock(self, traffic: cuckooReportICMP, protocol):
        srcIP = IPv4Address(value=traffic.src)
        dstIP = IPv4Address(value=traffic.dst)
        traffic = NetworkTraffic(
            src_ref=srcIP.id, dst_ref=dstIP.id, protocols=[protocol]
        )
        return traffic

    def createNetTrafficObs(self, traffic: cuckooReportNetwork):
        TCPCons, UDPCons, ICMPCons = [], [], []
        TCPCons.extend(
            self.createNetTrafficBlock(packet, "tcp") for packet in traffic.tcp
        )

        UDPCons.extend(
            self.createNetTrafficBlock(packet, "udp") for packet in traffic.udp
        )

        ICMPCons.extend(
            self.createNetICMPlock(packet, "icmp") for packet in traffic.icmp
        )

        return {"TCP": TCPCons, "UDP": UDPCons, "ICMP": ICMPCons}

    def createPrimaryBinary(self, file: cuckooReportDropped, external_references):
        hashes = {
            "MD5": file.md5.upper(),
            "SHA-1": file.sha1.upper(),
            "SHA-256": file.sha256.upper(),
            "SHA-512": file.sha512.upper(),
            "SSDEEP": file.ssdeep.upper(),
        }

        STIXPattern = self.getStixPattern(file.sha256, "sha256")

        size = 0
        try:
            if file.size:
                size = file.size
        except:
            pass

        Filex = File(hashes=hashes, size=size, name=file.name, mime_type=file.type)
        ind = Indicator(
            name=file.name,
            pattern=STIXPattern,
            pattern_type="stix",
            external_references=external_references,
        )

        rel = Relationship(
            source_ref=Filex.id, relationship_type="based-on", target_ref=ind.id
        )

        return [Filex, ind, rel]

    def createBinarieObs(self, objects):
        exec = ["PE32", "script", "batch", "intel", "executable", "HTML"]

        exec_files = []
        iocs = []

        for payload in objects:
            exec_files.extend(payload for value in exec if value.lower() in payload.type)
        for file in exec_files:
            hashes = {
                "MD5": file.md5.upper(),
                "SHA-1": file.sha1.upper(),
                "SHA-256": file.sha256.upper(),
                "SHA-512": file.sha512.upper(),
                "SSDEEP": file.ssdeep.upper(),
            }
            iocs.append(
                File(hashes=hashes, size=file.size, name=file.name, mime_type=file.type)
            )
            if self.CreateIndicator:
                STIXPattern = self.getStixPattern(file.sha256.upper(), "sha256")
                fileind = Indicator(
                    name=file.name, pattern=STIXPattern, pattern_type="stix"
                )
                iocs.append(fileind)

        return iocs

    def createCuckooReport(
        self, report: cuckooReport, object_refs=[], external_refs=[]
    ):
        if report.target.category == "url":
            name = f"Cuckoo Sandbox Report {str(report.info.id)} - {report.target.url}"
            desc = f"Cuckoo Sandbox Report {str(report.info.id)} - {report.target.url}"
        else:
            name = f"Cuckoo Sandbox Report {str(report.info.id)} - {report.target.file.name}"

            desc = f"Cuckoo Sandbox Report {str(report.info.id)} - {report.target.file.name}\nAnalyzied File:\n  SHA256: {report.target.file.sha256}\n  SHA1:{report.target.file.sha1}\n  MD5:{report.target.file.md5}"

        conf = int(report.info.score * 100)

        conf = min(conf, 100)
        report = Report(
            name=name,
            report_types="sandbox-report",
            published=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            object_refs=object_refs,
            description=desc,
            external_references=external_refs,
            confidence=conf,
        )

        return report

    def create_attack_pattern(self, attack_pattern: cuckooReportSignature):
        ATP = None
        mID = attack_pattern.ttp[0]["TTP"] if len(attack_pattern.ttp) > 1 else None
        if mID:
            ATP = self.API.attack_pattern.read(
                filters={
                    "key": "x_mitre_id",
                    "values": [mID],
                }
            )
        else:
            ATP = self.API.attack_pattern.read(
                filters={
                    "key": "name",
                    "values": [attack_pattern.name],
                }
            )
        if ATP:
            return ATP["standard_id"]

        ATP = AttackPattern(
            name=attack_pattern.name,
            description=f"[Cuckoo Sandbox] {attack_pattern.description}",
        )


        return ATP

    def getAttackPatterns(self, signatures):
        return [self.create_attack_pattern(sig) for sig in signatures]

    def get_related(
        self,
        ips,
        fqdns,
        processes,
        network_traffic,
        dropped_binaries,
        AttackPatterns,
        reg_keys,
    ):
        IDs = list(ips)

        IDs.extend(iter(fqdns))
        IDs.extend(iter(processes))
        IDs.extend(iter(dropped_binaries))
        IDs.extend(iter(AttackPatterns))
        if reg_keys:
            IDs.extend(iter(reg_keys))
        if network_traffic:
            for type in ["TCP", "UDP", "ICMP"]:
                IDs.extend(iter(network_traffic[type]))
        return IDs

    def processAndSubmit(self):
        # Create SDO's / Cyber Obs
        ext_ref = ExternalReference(
            source_name=f"Cuckoo Sandbox Report {str(self.report.info.id)}",
            url=f"{self.cuckoo_url}/analysis/{str(self.report.info.id)}/summary",
            external_id=str(self.report.info.id),
        )

        if self.report.network.hosts:
            ips = self.createIPObs(self.report.network.hosts)
        else:
            ips = []

        if self.report.network.domains:
            fqdns = self.createDNSObs(self.report.network.domains)
        else:
            fqdns = [[], []]

        if self.report.process:
            processes = self.createProcessObs(self.report.process)
        else:
            processes = []

        if self.EnableRegKeys:
            if self.report.behavior and self.report.behavior.regkey_written:
                registry_keys = self.createRegKeysObs(
                    self.report.behavior.regkey_written
                )
            else:
                registry_keys = None
        else:
            registry_keys = None

        if self.EnableNetTraffic and self.report.network:
            network_traffic = self.createNetTrafficObs(self.report.network)
        else:
            network_traffic = None
        if self.report.dropped:
            dropped_binaries = self.createBinarieObs(self.report.dropped)
        else:
            dropped_binaries = []

        if self.report.signatures:
            AttackPatterns = self.getAttackPatterns(self.report.signatures)
        else:
            AttackPatterns = []

        self.helper.log_info(fqdns)

        # Get all IDs from ATPs/CyberObs
        IDs = self.get_related(
            ips,
            fqdns[0],
            processes,
            network_traffic,
            dropped_binaries,
            AttackPatterns,
            registry_keys,
        )

        # Create Main binary and link All ATPs/Cyber Obs
        payload = self.createPrimaryBinary(self.report.target.file, ext_ref)
        payload_relations = []
        bundle_ids = []
        for ID in IDs:
            try:
                IDx = ID.id
                bundle_ids.append(
                    ID
                )  # Get list for bundle w/o Attack Patterns that exisit
            except:
                IDx = ID
            payload_relations.append(
                Relationship(
                    relationship_type="related-to",
                    source_ref=payload[0].id,
                    target_ref=IDx,
                )
            )
        payload_relations.extend(
            Relationship(
                relationship_type="related-to",
                source_ref=payload[0].id,
                target_ref=ATP,
            )
            for ATP in AttackPatterns
        )

        IDs.append(payload[0])  # Add Observeable
        IDs.append(payload[1])  # Add Indicator
        bundle_ids.extend((payload[0], payload[1]))
        payload_relations.append(payload[2])

        if int(self.report.info.score) >= self.ReportScore:
            # Create Report and link All ATPs/Cyber Obs/Payload
            report = self.createCuckooReport(self.report, IDs, ext_ref)
            b = Bundle(
                report, bundle_ids, payload_relations, fqdns[1]
            )  # fqdns[1] is the Resolves-to relations
        else:
            b = Bundle(bundle_ids, payload_relations, fqdns[1])

        self.helper.send_stix2_bundle(b.serialize())

        return None
