import json

from Kathara.exceptions import MachineNotRunningError, MachineBinaryError
from Kathara.model.Lab import Lab

from ....foundation.checks.AbstractCheck import AbstractCheck
from ....foundation.model.CheckResult import CheckResult
from ....model.FailedCheck import FailedCheck
from ....model.SuccessfulCheck import SuccessfulCheck
from ....utils import key_exists


class BGPNeighborCheck(AbstractCheck):

    def __init__(self, lab: Lab, description: str = None):
        super().__init__(lab, description=description, priority=1010)

    def check(self, device_name: str, neighbors: list) -> list[CheckResult]:
        results = []

        try:
            stdout, stderr, exit_code = self.kathara_manager.exec(
                machine_name=device_name,
                command="vtysh -e 'show bgp summary json'",
                lab_hash=self.lab.hash,
                stream=False,
            )
        except MachineNotRunningError as e:
            results.append(FailedCheck(f"Checking {device_name} BGP neighbors", str(e)))
            return results
        except MachineBinaryError as e:
            results.append(FailedCheck(f"Checking {device_name} BGP neighbors", str(e)))
            return results
        except Exception as e:
            results.append(FailedCheck(f"Checking {device_name} BGP neighbors", str(e)))
            return results

        output = stdout.decode("utf-8") if stdout else None

        if stderr or exit_code != 0:
            results.append(
                FailedCheck(
                    f"Checking {device_name} BGP neighbors",
                    stderr.decode("utf-8") if stderr else f"Exit code: {exit_code}",
                )
            )
            return results
        output = json.loads(output)

        if "ipv4Unicast" in output:
            output = output["ipv4Unicast"]
        else:
            results.append(
                FailedCheck(
                    f"Checking {device_name} BGP neighbors",
                    f"{device_name} has no IPv4 BGP peerings",
                )
            )
            return results

        if "peers" in output:
            output = output["peers"]
        else:
            results.append(
                FailedCheck(
                    f"Checking {device_name} BGP neighbors",
                    f"{device_name} has no IPv4 BGP neighbors",
                )
            )
            return results

        for neighbor in neighbors:
            neighbor_ip = neighbor["ip"]
            neighbor_asn = neighbor["asn"]

            check_description = f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn}"

            if neighbor_ip not in output:
                results.append(
                    FailedCheck(check_description,
                                f"The peering between {device_name} and {neighbor_ip} is not configured.",
                                )
                )
                results.append(
                    FailedCheck(
                        f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn} established",
                        f"The peering between {device_name} and {neighbor_ip} is not configured.",
                    )
                )
                continue

            peer = output[neighbor_ip]

            if peer["remoteAs"] != neighbor_asn:
                results.append(
                    FailedCheck(check_description,
                                f"{device_name} has neighbor {neighbor_ip} with ASN: {peer['remoteAs']} instead of {neighbor_asn}",
                                )
                )
            else:
                results.append(SuccessfulCheck(check_description))

            if peer["state"] == "Established":
                results.append(
                    SuccessfulCheck(
                        f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn} established",
                    )
                )
            else:
                results.append(
                    FailedCheck(
                        f"{device_name} has bgp neighbor {neighbor_ip} AS{neighbor_asn} established",
                        f"The session is configured but is in the {peer['state']} state",
                    )
                )

        return results

    def run(self, device_to_neighbours: dict[str, list[str]]) -> list[CheckResult]:
        results = []
        for device_name, neighbors in device_to_neighbours.items():
            self.logger.info(f"Checking {device_name} BGP peerings...")
            check_result = self.check(device_name, neighbors)
            results.extend(check_result)
        return results

    def run_from_configuration(self, configuration: dict) -> list[CheckResult]:
        results = []
        if key_exists(["test", "protocols", "bgpd", "neighbors"], configuration):
            self.logger.info(f"Checking BGP neighbors...")
            results.extend(self.run(configuration["test"]["protocols"]['bgpd']['neighbors']))
        return results
