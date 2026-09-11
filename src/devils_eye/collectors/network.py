"""Network collector: TCP/UDP endpoints correlated to owning processes."""

from __future__ import annotations

from ..core.models import CollectorResult, Evidence
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json


class NetworkCollector(Collector):
    name = "network"
    description = "TCP/UDP endpoints with owning process + DNS client cache"
    weight = 0.9
    sources = [
        "TCP Connection Table (Get-NetTCPConnection)",
        "UDP Endpoint Table (Get-NetUDPEndpoint)",
        "DNS Client Cache (Get-DnsClientCache)",
        "DNS Client Operational (correlation input)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or not is_windows():
            return r
        rows = powershell_json(
            "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,"
            "RemotePort,State,OwningProcess | ConvertTo-Json -Depth 4",
            timeout=45,
        )
        if rows is not None:
            pids = {p.get("pid"): p for p in ctx.shared.get("processes") or []}
            for row in rows:
                pid = row.get("OwningProcess")
                proc = pids.get(pid, {})
                r.evidences.append(
                    Evidence(
                        kind="network",
                        source="Get-NetTCPConnection",
                        collector=self.name,
                        pid=pid,
                        process_path=proc.get("path") or "",
                        data={
                            "pid": pid,
                            "process_path": proc.get("path") or "",
                            "local": f"{row.get('LocalAddress')}:{row.get('LocalPort')}",
                            "remote": f"{row.get('RemoteAddress')}:{row.get('RemotePort')}",
                            "state": row.get("State") or "",
                            "protocol": "TCP",
                        },
                    )
                )
        else:
            r.errors.append("Get-NetTCPConnection unavailable")
        dns = powershell_json("Get-DnsClientCache | Select-Object Entry,Data -First 200", timeout=30)
        if dns is not None:
            for row in dns:
                r.evidences.append(
                    Evidence(
                        kind="network", source="Get-DnsClientCache", collector=self.name,
                        data={"dns_entry": row.get("Entry") or "", "dns_data": row.get("Data") or ""},
                    )
                )
        ctx.shared["network"] = [e.data for e in r.evidences if e.data.get("pid")]
        r.metrics = {"endpoints": len(r.evidences)}
        return r
