from datetime import datetime
import requests
from requests.exceptions import HTTPError


# ------------------------------------------------------------------
# This is a Class to serialize the Cuckoo API /tasks/Summary JSON
# ------------------------------------------------------------------


class cuckooMachine:
    def __init__(self, json):
        self.json = json
        # Get Basic info
        self.label = self.json["label"]
        self.manager = self.json["manager"]
        self.name = self.json["name"]
        self.shutdown_on = self.json["shutdown_on"]
        self.started_on = self.json["started_on"]
        self.status = self.json["status"]

    def __str__(self):
        return self.name


class cuckooReportInfo:
    def __init__(self, report_json):
        self.json = report_json["info"]

        # Get Basic info
        self.id = self.json["id"]
        self.added = self.json["added"]
        self.started = self.json["started"]
        self.ended = self.json["ended"]
        self.duration = self.json["duration"]
        self.category = self.json["category"]
        self.route = self.json["route"]
        self.package = self.json["package"]
        self.score = self.json["score"]
        self.platform = self.json["platform"]
        self.machine = cuckooMachine(self.json["machine"])
        self.version = self.json["version"]

    def __str__(self):
        return self.id


class cuckooTarget:
    def __init__(self, report_json, target="file"):
        self.json = report_json["target"][target]

        # Get Basic info
        self.crc32 = self.json["crc32"]
        self.md5 = self.json["md5"]
        self.name = self.json["name"]
        self.path = self.json["path"]
        self.sha1 = self.json["sha1"]
        self.sha256 = self.json["sha256"]
        self.sha512 = self.json["sha512"]
        self.ssdeep = self.json["ssdeep"]
        self.type = self.json["type"]
        self.yara = self.getYara()
        self.urls = self.getURL()

    def getURL(self):
        return self.json["urls"]  # Fix me later

    def getYara(self):
        yara_matches = [
            {"name": match["name"], "meta": match["meta"]}
            for match in self.json["yara"]
        ]

    def __str__(self):
        return self.name


class cuckooReportTarget:
    def __init__(self, report_json):
        self.category = report_json["target"]["category"]

        if self.category == "url":
            self.url = report_json["target"]["url"]
        elif self.category == "file":
            self.file = cuckooTarget(report_json, "file")
        elif self.category == "archive":
            self.file = cuckooTarget(report_json, "file")
            self.archive = cuckooTarget(report_json, "archive")

    def __str__(self) -> str:
        if self.category in ["file", "archive"]:
            return self.file.name
        elif self.category == "url":
            return self.url


class cuckooReportSignature:
    def __init__(self, signature_json):

        self.json = signature_json

        # Get Basic info
        self.description = self.json["description"]
        self.markcount = self.json["markcount"]
        self.name = self.json["name"]
        self.families = self.json["families"]
        self.references = self.json["references"]
        self.severity = self.json["severity"]
        self.ttp = self.getTTPs()

    def getTTPs(self):
        return [
            {
                "TTP": TTP,
                "name": self.json["ttp"][TTP]["short"],
                "description": self.json["ttp"][TTP]["long"],
            }
            for TTP in self.json["ttp"].keys()
        ]

    def __str__(self):
        return self.name


class cuckooReportExtracted:
    def __init__(self, json):
        self.json = json

        self.category = self.json["category"]
        self.pid = self.json["pid"]
        self.info = self.json["info"]
        self.program = self.json["program"]
        self.raw = self.json["raw"]
        self.yara = self.getYara()
        self.first_seen = datetime.fromtimestamp(self.json["first_seen"])

    def getYara(self):
        yara_matches = [
            {"name": match["name"], "meta": match["meta"]}
            for match in self.json["yara"]
        ]

    def __str__(self):
        return f"[{str(self.pid)}][{self.category}] {self.raw.split('/')[-1]}"


class cuckooReportDropped:
    def __init__(self, json):
        self.json = json

        # Get Basic info
        self.crc32 = self.json["crc32"]
        self.md5 = self.json["md5"]
        self.name = self.json["name"]
        self.path = self.json["path"]
        self.filepath = self.json["filepath"]
        self.pids = self.json["pids"]
        self.sha1 = self.json["sha1"]
        self.sha256 = self.json["sha256"]
        self.sha512 = self.json["sha512"]
        self.ssdeep = self.json["ssdeep"]
        self.size = self.json["size"]
        self.type = self.json["type"]
        self.yara = self.getYara()
        self.urls = self.json["urls"]

    def getYara(self):
        yara_matches = [
            {"name": match["name"], "meta": match["meta"]}
            for match in self.json["yara"]
        ]

    def __str__(self):
        return self.name


class cuckooReportBuffer:
    def __init__(self, json):
        self.json = json

        # Get Basic info
        self.crc32 = self.json["crc32"]
        self.md5 = self.json["md5"]
        self.name = self.json["name"]
        self.path = self.json["path"]
        self.sha1 = self.json["sha1"]
        self.sha256 = self.json["sha256"]
        self.sha512 = self.json["sha512"]
        self.ssdeep = self.json["ssdeep"]
        self.size = self.json["size"]
        self.type = self.json["type"]
        self.yara = self.getYara()
        self.urls = self.json["urls"]

    def getYara(self):
        yara_matches = [
            {"name": match["name"], "meta": match["meta"]}
            for match in self.json["yara"]
        ]

    def __str__(self):
        return self.name


class cuckooReportDNSResponse:
    def __init__(self, json):
        self.json = json

        self.data = self.json["data"]
        self.type = self.json["type"]


class cuckooReportDNSRequest:
    def __init__(self, json):
        self.json = json

        self.request = self.json["request"]
        self.type = self.json["type"]
        self.answers = self.getDNSAnswers()

    def getDNSAnswers(self):
        answers = []
        for answer in self.json["answers"]:
            answerObj: cuckooReportDNSResponse = cuckooReportDNSResponse(answer)
            answers.append(answerObj)
        return answers

    def __str__(self):
        return self.request


class cuckooReportHTTPRequest:
    def __init__(self, json):
        self.json = json

        self.body = self.json["body"] if "body" in self.json else None
        self.count = self.json["count"] if "count" in self.json else None
        self.data = self.json["data"] if "data" in self.json else None
        self.host = self.json["host"] if "host" in self.json else None
        self.method = self.json["method"] if "method" in self.json else None
        self.path = self.json["path"] if "path" in self.json else None
        self.port = self.json["port"] if "port" in self.json else None
        self.data = self.json["uri"] if "uri" in self.json else None
        self.useragent = self.json["user-agent"] if "user-agent" in self.json else None
        self.version = self.json["version"] if "version" in self.json else None

    def __str__(self):
        return f"[{self.method}] {self.host}"


class cuckooReportHTTPResponse:
    def __init__(self, json):
        self.json = json

        self.dport = self.json["dport"]
        self.dst = self.json["dst"]
        self.host = self.json["host"]
        self.md5 = self.json["md5"]
        self.method = self.json["method"]
        self.path = self.json["path"]
        self.protocol = self.json["protocol"]
        self.request = self.json["request"]
        self.response = self.json["response"]
        self.sha1 = self.json["sha1"]
        self.sport = self.json["sport"]
        self.src = self.json["src"]
        self.status = self.json["status"]
        self.uri = self.json["uri"]

    def __str__(self):
        return f"[{str(self.status)}][{self.method}] {self.host}"


class cuckooReportICMP:
    def __init__(self, json):
        self.json = json

        self.data = self.json["data"]
        self.dst = self.json["dst"]
        self.src = self.json["src"]
        self.type = self.json["type"]

    def __str__(self):
        return f"{self.dst}"


class cuckooReportTCPUDP:
    def __init__(self, json):
        self.json = json

        self.dport = self.json["dport"]
        self.dst = self.json["dst"]
        self.offset = self.json["offset"]
        self.sport = self.json["sport"]
        self.src = self.json["src"]
        self.time = self.json["time"]

    def __str__(self):
        return f"{self.dst}"


class cuckooReportNetwork:
    def __init__(self, report_json):
        self.json = report_json["network"]

        # Get Basic info
        self.dead_hosts = self.json["dead_hosts"]
        self.dns_servers = self.json["dns_servers"]
        self.domains = self.json["domains"]
        self.hosts = self.json["hosts"]
        self.dns = self.getDNS()
        self.http = self.getHTTP()
        self.http_ex = self.getHTTPEX()
        self.icmp = self.getICMP()
        self.tcp = self.getpackets("tcp")
        self.udp = self.getpackets("udp")

    def getpackets(self, type="tcp"):
        packets = []
        for reqObj in self.json[type]:
            respObj: cuckooReportTCPUDP = cuckooReportTCPUDP(reqObj)
            packets.append(respObj)

        return packets

    def getICMP(self):
        requests = []
        for reqObj in self.json["icmp"]:
            respObj: cuckooReportICMP = cuckooReportICMP(reqObj)
            requests.append(respObj)

        return requests

    def getDNS(self):
        requests = []
        for reqObj in self.json["dns"]:
            respObj: cuckooReportDNSRequest = cuckooReportDNSRequest(reqObj)
            requests.append(respObj)

        return requests

    def getHTTP(self):
        requests = []
        for reqObj in self.json["http"]:
            respObj: cuckooReportHTTPRequest = cuckooReportHTTPRequest(reqObj)
            requests.append(respObj)

        return requests

    def getHTTPEX(self):
        requests = []
        if "http_ex" not in self.json:
            return []

        for reqObj in self.json["http_ex"]:
            respObj: cuckooReportHTTPResponse = cuckooReportHTTPResponse(reqObj)
            requests.append(respObj)

        return requests

    def __str__(self):
        return self.id


class cuckooReportBehaviorSummary:
    def __init__(self, report_json):

        self.json = report_json["behavior"]["summary"]

        # Get Basic info
        if "command_line" in self.json:
            self.command_line = self.json["command_line"]
        else:
            self.command_line = []

        if "connects_ip" in self.json:
            self.connects_ip = self.json["connects_ip"]
        else:
            self.connects_ip = []

        if "directory_created" in self.json:
            self.directory_created = self.json["directory_created"]
        else:
            self.directory_created = []

        if "directory_enumerated" in self.json:
            self.directory_enumerated = self.json["directory_enumerated"]
        else:
            self.directory_enumerated = []

        self.dll_loaded = self.json["dll_loaded"] if "dll_loaded" in self.json else []
        if "file_copied" in self.json:
            self.file_copied = self.json["file_copied"]
        else:
            self.file_copied = []

        if "file_created" in self.json:
            self.file_created = self.json["file_created"]
        else:
            self.file_created = []

        if "file_deleted" in self.json:
            self.file_deleted = self.json["file_deleted"]
        else:
            self.file_deleted = []

        if "file_exists" in self.json:
            self.file_exists = self.json["file_exists"]
        else:
            self.file_exists = []

        if "file_failed" in self.json:
            self.file_failed = self.json["file_failed"]
        else:
            self.file_failed = []

        self.file_moved = self.json["file_moved"] if "file_moved" in self.json else []
        if "file_opened" in self.json:
            self.file_opened = self.json["file_opened"]
        else:
            self.file_opened = []

        self.file_read = self.json["file_read"] if "file_read" in self.json else []
        if "file_recreated" in self.json:
            self.file_recreated = self.json["file_recreated"]
        else:
            self.file_recreated = []

        if "file_written" in self.json:
            self.file_written = self.json["file_written"]
        else:
            self.file_written = []

        self.guid = self.json["guid"] if "guid" in self.json else []
        self.mutex = self.json["mutex"] if "mutex" in self.json else []
        if "regkey_opened" in self.json:
            self.regkey_opened = self.json["regkey_opened"]
        else:
            self.regkey_opened = []

        if "regkey_read" in self.json:
            self.regkey_read = self.json["regkey_read"]
        else:
            self.regkey_read = []

        if "regkey_written" in self.json:
            self.regkey_written = self.json["regkey_written"]
        else:
            self.regkey_written = []

        if "wmi_query" in self.json:
            self.wmi_query = self.json["wmi_query"]
        else:
            self.wmi_query = []

        if "resolves_host" in self.json:
            self.resolves_host = self.json["resolves_host"]
        else:
            self.resolves_host = []

        if "guid" in self.json:
            self.guid = self.json["guid"]
        else:
            self.guid = []

        if "guid" in self.json:
            self.guid = self.json["guid"]
        else:
            self.guid = []
        if "guid" in self.json:
            self.guid = self.json["guid"]
        else:
            self.guid = []


class cuckooReportProcess:
    def __init__(self, process_json):

        self.json = process_json

        # Get Basic info
        if "command_line" in self.json:
            self.command_line = self.json["command_line"]
        else:
            self.command_line = []

        self.first_seen = self.json["first_seen"] if "first_seen" in self.json else 0
        self.pid = self.json["pid"] if "pid" in self.json else -1
        self.ppid = self.json["ppid"] if "ppid" in self.json else -1
        if "process_name" in self.json:
            self.process_name = self.json["process_name"]
        else:
            self.process_name = ""

        self.track = self.json["track"] if "track" in self.json else False


class cuckooReport:
    def __init__(self, report_json):
        self.report_json = report_json

        self.info = cuckooReportInfo(report_json) if "info" in report_json else None
        if "target" in report_json:
            self.target: cuckooReportTarget = cuckooReportTarget(report_json)
        else:
            self.target = None

        if "network" in report_json:
            self.network: cuckooReportNetwork = cuckooReportNetwork(report_json)
        else:
            self.network = None

        if "behavior" in report_json:

            if "processtree" in report_json["behavior"]:
                self.process = self.getProcesses(report_json["behavior"]["processtree"])
            else:
                self.process = []

            if "summary" in report_json["behavior"]:
                self.behavior: cuckooReportBehaviorSummary = (
                    cuckooReportBehaviorSummary(report_json)
                )
            else:
                self.behavior = None
        else:
            self.behavior = None
            self.process = []

        self.strings = report_json["strings"] if "strings" in report_json else []
        self.signatures = self.getReportSignatures()
        self.extracted = self.getReportExtracted()
        self.dropped = self.getReportDropped()
        self.buffer = self.getReportBuffer()

    def hasSignatures(self):
        return len(self.signatures) > 0

    def hasExtracted(self):
        return len(self.extracted) > 0

    def hasDropped(self):
        return len(self.dropped) > 0

    def hasBuffer(self):
        return len(self.buffer) > 0

    def getReportSignatures(self):
        signatures = []
        if "signatures" not in self.report_json:
            return []
        for sig in self.report_json["signatures"]:
            sigObj: cuckooReportSignature = cuckooReportSignature(sig)
            signatures.append(sigObj)

        return signatures

    def getReportExtracted(self):
        ExtractedObjects = []
        if "extracted" not in self.report_json:
            return []
        for objx in self.report_json["extracted"]:
            extObj: cuckooReportExtracted = cuckooReportExtracted(objx)
            ExtractedObjects.append(extObj)

        return ExtractedObjects

    def getReportDropped(self):
        DroppedObjects = []
        if "dropped" not in self.report_json:
            return []
        for objx in self.report_json["dropped"]:
            dropObj: cuckooReportDropped = cuckooReportDropped(objx)
            DroppedObjects.append(dropObj)

        return DroppedObjects

    def getReportBuffer(self):
        BufferObjects = []
        if "buffer" not in self.report_json:
            return []
        for objx in self.report_json["buffer"]:
            bufObj: cuckooReportBuffer = cuckooReportBuffer(objx)
            BufferObjects.append(bufObj)

        return BufferObjects

    def getProcesses(self, json):
        ProcessObjects = []
        for objx in json:
            ProcessObjects.extend(self.extractChildren(objx["children"]))
            ProcessObjects.append(cuckooReportProcess(objx))

        return ProcessObjects

    def extractChildren(self, children):
        grand = []

        for Child in children:
            if len(Child["children"]) <= 0:
                grand.append(cuckooReportProcess(Child))
            else:
                grand.append(cuckooReportProcess(Child))
                grand.extend(self.extractChildren(Child["children"]))

        return grand

    def __str__(self) -> str:
        return str(self.target)


class cuckoo:
    def __init__(self, connectorHelper, api_url, Verify=True):
        self.URL = api_url
        self.verify = Verify
        self.connectorHelper = connectorHelper

    def getCuckooTasks(self):
        EP = "tasks/list"
        Method = "GET"
        response = self._make_request(Method, EP)
        return response.json()["tasks"]

    def getTaskSummary(self, TaskID):
        EP = f"tasks/summary/{TaskID}"
        Method = "GET"
        response = self._make_request(Method, EP)
        return cuckooReport(response.json())

    def getTaskReport(self, TaskID):
        EP = f"tasks/report/{TaskID}"
        Method = "GET"
        response = self._make_request(Method, EP)
        return response.json()

    def _make_request(self, method, EP, data=None, params=None, host=None):
        try:
            URL = f"{self.URL}{EP}" if self.URL[-1] == "/" else f"{self.URL}/{EP}"
            if params and data:
                resp = requests.request(
                    method, URL, data=data, params=params, verify=self.verify
                )
            elif params:
                resp = requests.request(method, URL, params=params, verify=self.verify)
            elif data:
                resp = requests.request(method, URL, data=data, verify=self.verify)
            else:
                resp = requests.request(method, URL, verify=self.verify)

            if not resp.ok:
                self.connectorHelper.log_error(
                    f"Received response code {resp.status_code} from {URL}"
                )
                retry = 0
                while not resp.ok and retry < 5:
                    retry += 1
                    if params and data:
                        resp = requests.request(
                            method, URL, data=data, params=params, verify=self.verify
                        )
                    elif params:
                        resp = requests.request(
                            method, URL, params=params, verify=self.verify
                        )
                    elif data:
                        resp = requests.request(
                            method, URL, data=data, verify=self.verify
                        )
                    else:
                        resp = requests.request(method, URL, verify=self.verify)

            return resp
        except HTTPError as e:
            self.connectorHelper.log_error(str(e))
