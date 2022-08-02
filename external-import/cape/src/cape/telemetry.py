from datetime import datetime
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from cape.cape import (
    cuckooPayload,
    cuckooReport,
    cuckooReportDomain,
    cuckooReportHost,
    cuckooReportICMP,
    cuckooReportNetwork,
    cuckooReportProcess,
    cuckooReportTCPUDP,
    cuckooReportTTP,
    cuckooTarget,
)
from stix2.v21 import (
    IPv4Address,
    DomainName,
    Process,
    Relationship,
    Malware,
    ExternalReference,
    Bundle,
    File,
    NetworkTraffic,
    WindowsRegistryKey,
    Indicator,
    Report,
    TLP_AMBER,
    TLP_GREEN,
    TLP_RED,
    TLP_WHITE,
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

    def get_or_create_label(self, labelValue):
        labels = self.octiLabels
        for labelX in labels:
            if labelValue.lower() == labelX["value"].lower():
                return labelX["id"]

        try:
            label = self.API.label.create(value=labelValue)
        except:
            return None
        return label["id"]

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
            host: cuckooReportHost
            IPObs.append(IPv4Address(value=host.ip))
            if self.CreateIndicator:
                STIXPattern = self.getStixPattern(host.ip, "ipv4")
                IPind = Indicator(
                    name=host.ip, pattern=STIXPattern, pattern_type="stix"
                )
                IPObs.append(IPind)
        return IPObs

    # STIX-erize DNS info
    def createDNSObs(self, DNSOBJ):
        DNSObs = []
        DNSRel = []
        for host in DNSOBJ:
            host: cuckooReportDomain
            IP = IPv4Address(value=host.ip)
            DNS = DomainName(
                value=host.domain
            )  # , resolves_to_refs=IP.id) ref https://github.com/OpenCTI-Platform/client-python/issues/155
            Rel = Relationship(
                source_ref=DNS.id, target_ref=IP.id, relationship_type="resolves-to"
            )

            if self.CreateIndicator:
                STIXPattern = self.getStixPattern(host.domain, "FQDN")
                DNSind = Indicator(
                    name=host.domain, pattern=STIXPattern, pattern_type="stix"
                )
                STIXPattern = self.getStixPattern(host.ip, "ipv4")
                IPind = Indicator(
                    name=host.ip, pattern=STIXPattern, pattern_type="stix"
                )
                DNSObs.extend((DNSind, IPind))
            DNSObs.extend((IP, DNS))
            DNSRel.append(Rel)

        return [DNSObs, DNSRel]

    # Stix-erize Registry Keys
    def createRegKeysObs(self, reg_keys):
        return [WindowsRegistryKey(key=key) for key in reg_keys]

    # Sacrifised a Chicken Nugget to the Abstract Programing entity and they provided
    def createProcessObs(self, procs):
        ProcessObjects = []

        for proc in procs:
            proc: cuckooReportProcess
            ChildProcObjs = [[], []]

            ext = self.extractChildren(
                proc.children
            )  # Get Child Procesees list [Child, Children of Child]

            # This ID10T-ism is for not claiming grandchildren directly
            ChildProcObjs[0].extend(ext[0])  # Add Child to Children array
            ChildProcObjs[1].extend(
                ext[1]
            )  # Add Children of Child to ChildrenOfChildren array (For STIX)
            IDs = [child.id for child in ChildProcObjs[0]]  # Find all Child_ref ID's

            MainProc = Process(  # Create Parent Process
                pid=proc.pid,
                command_line=proc.environ.command_line,
                child_refs=IDs,
            )

            # Flatten List Insanity
            ProcessObjects.append(MainProc)  # Add Parent Process to Bundle
            ProcessObjects.extend(ChildProcObjs[0])  # Add Direct Children to Bundle
            ProcessObjects.extend(
                ChildProcObjs[1]
            )  # Add Children of Children (Main Process list) to bundle

        return ProcessObjects  # list(Process)

    def extractChildren(self, children):
        grand = []
        someObsecurechildren = []
        for Child in children:
            Child: cuckooReportProcess
            childs = [[], []]

            if len(Child.children) <= 0:  # No Granchildren this is easy ;)
                ChildProc = Process(
                    pid=Child.pid,
                    command_line=Child.environ.command_line,
                    child_refs=[],
                )
            else:
                ext = self.extractChildren(Child.children)

                # This ID10T-ism is for not claiming grandchildren directly
                childs[0].extend(ext[0])  # Add Child to Children array
                childs[1].extend(
                    ext[1]
                )  # Add Children of Child to ChildrenOfChildren array (For STIX)
                IDs = [childX.id for childX in childs[0]]  # Find all Child_ref ID's

                ChildProc = Process(  # Create Child-Parent Process iNcePtIon
                    pid=Child.pid,
                    command_line=Child.environ.command_line,
                    child_refs=IDs,
                )

                someObsecurechildren.extend(childs[1])  # Add Direct Children to Bundle
                someObsecurechildren.extend(
                    childs[0]
                )  # Add Children of Children (Main Process list) to bundle

            grand.append(ChildProc)
        return [grand, someObsecurechildren]

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

    def createPrimaryBinary(self, file: cuckooTarget, external_references):
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

        Filex = File(
            hashes=hashes,
            size=size,
            name=file.name,
            mime_type=file.type,
        )
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
        iocs = []

        for file in objects:
            file: cuckooPayload
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
            name = f"CAPE Sandbox Report {str(report.info.id)} - {report.target.url}"
            desc = f"CAPE Sandbox Report {str(report.info.id)} - {report.target.url}"
        else:
            name = (
                f"CAPE Sandbox Report {str(report.info.id)} - {report.target.file.name}"
            )

            desc = f"CAPE Sandbox Report {str(report.info.id)} - {report.target.file.name}\nAnalyzied File:\n  SHA256: {report.target.file.sha256}\n  SHA1:{report.target.file.sha1}\n  MD5:{report.target.file.md5}"

        conf = int(report.malscore * 100)
        reportLabels = ["sandbox", f"Score: {str(report.malscore)}"]

        conf = min(conf, 100)
        if conf > 70:
            reportLabels.append("Malicious")

        if report.detections:
            reportLabels.append(report.detections)

        labelIDs = [self.get_or_create_label(labelx) for labelx in reportLabels]
        if report.info.tlp:
            tlps = []

            if "GREEN" in report.info.tlp:
                tlps.append(TLP_GREEN["id"])
            elif "WHITE" in report.info.tlp:
                tlps.append(TLP_WHITE["id"])
            elif "AMBER" in report.info.tlp:
                tlps.append(TLP_AMBER["id"])
            elif "RED" in report.info.tlp:
                tlps.append(TLP_RED["id"])

        report = Report(
            name=name,
            report_types="sandbox-report",
            published=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            object_refs=object_refs,
            description=desc,
            external_references=external_refs,
            confidence=conf,
            labels=reportLabels,
        )

        return report

    def Get_TTP(self, TTP: cuckooReportTTP):
        try:
            ATP = self.API.attack_pattern.read(
                filters={
                    "key": "x_mitre_id",
                    "values": [TTP.ttp],
                }
            )
        except:
            return None

        return ATP

    def getTTPs(self, TTPs):
        ATPs = []
        for TTP in TTPs:
            TTP: cuckooReportTTP
            if TTPX := self.Get_TTP(TTP):
                ATPs.append(TTPX)

        return ATPs

    def Get_Malware(self, Detection: str):
        try:
            MalwareX = self.API.malware.read(
                filters={
                    "key": "name",
                    "values": [Detection],
                }
            )
        except:
            return None

        if not MalwareX:
            MalwareX = Malware(name=Detection, is_family=False)

        return MalwareX

    def get_related(
        self,
        ips,
        fqdns,
        processes,
        network_traffic,
        dropped_binaries,
        AttackPatterns,
        reg_keys,
        Malware,
    ):
        IDs = []

        if Malware:
            if isinstance(Malware, dict):
                IDs.append(Malware["standard_id"])
            else:
                IDs.append(Malware)

        IDs.extend(iter(ips))
        IDs.extend(iter(fqdns))
        IDs.extend(iter(processes))
        IDs.extend(iter(dropped_binaries))
        IDs.extend(ATP["standard_id"] for ATP in AttackPatterns if ATP)
        if reg_keys:
            IDs.extend(iter(reg_keys))
        if network_traffic:
            for type in ["TCP", "UDP", "ICMP"]:
                IDs.extend(iter(network_traffic[type]))
        return IDs

    def processAndSubmit(self):
        # Create SDO's / Cyber Obs
        ext_ref = ExternalReference(
            source_name=f"Cape Sandbox Report {str(self.report.info.id)}",
            url=f"{self.cuckoo_url}/analysis/{str(self.report.info.id)}/",
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
            if self.report.behavior:
                if self.report.behavior.write_keys:
                    registry_keys = self.createRegKeysObs(
                        self.report.behavior.write_keys
                    )
                else:
                    registry_keys = None
            else:
                registry_keys = None
        else:
            registry_keys = None

        if self.EnableNetTraffic:
            if self.report.network:
                network_traffic = self.createNetTrafficObs(self.report.network)
            else:
                network_traffic = None
        else:
            network_traffic = None

        if self.report.payloads:
            dropped_binaries = self.createBinarieObs(self.report.payloads)
        else:
            dropped_binaries = []

        if self.report.signatures:
            AttackPatterns = self.getTTPs(self.report.ttps)
        else:
            AttackPatterns = []

        if self.report.detections:
            Malware = self.Get_Malware(self.report.detections)
        else:
            Malware = None

        # Get all IDs from ATPs/CyberObs
        IDs = self.get_related(
            ips,
            fqdns[0],
            processes,
            network_traffic,
            dropped_binaries,
            AttackPatterns,
            registry_keys,
            Malware,
        )

        if self.report.target.file:
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
                if IDx:
                    payload_relations.append(
                        Relationship(
                            relationship_type="related-to",
                            source_ref=payload[0].id,
                            target_ref=IDx,
                        )
                    )
            for ATP in AttackPatterns:
                payload_relations.append(
                    Relationship(
                        relationship_type="related-to",
                        source_ref=payload[0].id,
                        target_ref=ATP["standard_id"],
                    )
                )
            if Malware:
                if "standard_id" in Malware:
                    ID = Malware["standard_id"]
                else:
                    ID = Malware["id"]

                Relationship(
                    relationship_type="related-to",
                    source_ref=payload[0].id,
                    target_ref=ID,
                )

            IDs.append(payload[0])  # Add Observeable
            IDs.append(payload[1])  # Add Indicator
            bundle_ids.append(payload[0])
            bundle_ids.append(payload[1])
            payload_relations.append(payload[2])

        if int(self.report.malscore) >= self.ReportScore:
            # Create Report and link All ATPs/Cyber Obs/Payload
            report = self.createCuckooReport(self.report, IDs, ext_ref)
            b = Bundle(
                report, bundle_ids, payload_relations, fqdns[1]
            )  # fqdns[1] is the Resolves-to relations
        else:
            b = Bundle(bundle_ids, payload_relations, fqdns[1])

        self.helper.send_stix2_bundle(b.serialize())

        return None
