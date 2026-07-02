import re
from pycti import OpenCTIConnectorHelper

FALCO_MITRE_MAP = {
    "Reverse Shell Detected": "74474351-51b6-4e69-90a1-a98f0d21e83c",
    "Sensitive file opened for reading by non-trusted program": "cef0a4e4-d389-473f-ac37-f76fd38c19c1",
    "Search Private Keys or Passwords": "cef0a4e4-d389-473f-ac37-f76fd38c19c1",
    "Terminal shell in container": "74474351-51b6-4e69-90a1-a98f0d21e83c",
    "Run shell untrusted": "74474351-51b6-4e69-90a1-a98f0d21e83c",
    "Netcat Remote Code Execution in Container": "74474351-51b6-4e69-90a1-a98f0d21e83c",
    "Drop and execute new binary in container": "74474351-51b6-4e69-90a1-a98f0d21e83c",
    "Linux Kernel Module Injection Detected": "74474351-51b6-4e69-90a1-a98f0d21e83c",
    "Redirect STDOUT/STDIN to Network Connection in Container": "74474351-51b6-4e69-90a1-a98f0d21e83c",
}

class FalcoMitreConnector:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

    def _extract_rule(self, description):
        match = re.search(r"Regla:\s*(.+)", description)
        if match:
            return match.group(1).strip()
        return None

    def _process_case(self, data):
        case_id = data["entity_id"]
        work_id = data.get("work_id")

        try:
            case = self.helper.api.case_incident.read(id=case_id)
            if not case:
                message = "Caso no encontrado"
                if work_id:
                    self.helper.api.work.to_processed(work_id, message)
                return message

            description = case.get("description", "")
            rule = self._extract_rule(description)

            if not rule:
                message = "No se encontró regla de Falco"
                if work_id:
                    self.helper.api.work.to_processed(work_id, message)
                return message

            mitre_id = FALCO_MITRE_MAP.get(rule)
            if not mitre_id:
                message = f"Sin mapeo MITRE para: {rule}"
                if work_id:
                    self.helper.api.work.to_processed(work_id, message)
                return message

            self.helper.api.stix_core_relationship.create(
                fromId=case_id,
                toId=mitre_id,
                relationship_type="related-to",
            )

            message = f"Técnica MITRE vinculada: {rule}"
            if work_id:
                self.helper.api.work.to_processed(work_id, message)
            return message

        except Exception as e:
            message = f"Error: {str(e)}"
            if work_id:
                self.helper.api.work.to_processed(work_id, message)
            return message

    def start(self):
        self.helper.listen(self._process_case)

if __name__ == "__main__":
    connector = FalcoMitreConnector()
    connector.start()
