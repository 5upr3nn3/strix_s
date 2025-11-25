import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional
from uuid import uuid4


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

_global_tracer: Optional["Tracer"] = None


def get_global_tracer() -> Optional["Tracer"]:
    return _global_tracer


def set_global_tracer(tracer: "Tracer") -> None:
    global _global_tracer  # noqa: PLW0603
    _global_tracer = tracer


class Tracer:
    def __init__(self, run_name: str | None = None):
        self.run_name = run_name
        self.run_id = run_name or f"run-{uuid4().hex[:8]}"
        self.start_time = datetime.now(UTC).isoformat()
        self.end_time: str | None = None

        self.agents: dict[str, dict[str, Any]] = {}
        self.tool_executions: dict[int, dict[str, Any]] = {}
        self.chat_messages: list[dict[str, Any]] = []

        self.vulnerability_reports: list[dict[str, Any]] = []
        self.final_scan_result: str | None = None

        self.scan_results: dict[str, Any] | None = None
        self.scan_config: dict[str, Any] | None = None
        self.run_metadata: dict[str, Any] = {
            "run_id": self.run_id,
            "run_name": self.run_name,
            "start_time": self.start_time,
            "end_time": None,
            "targets": [],
            "status": "running",
        }
        self._run_dir: Path | None = None
        self._next_execution_id = 1
        self._next_message_id = 1
        self._saved_vuln_ids: set[str] = set()
        self._events_file: Any | None = None

        self.vulnerability_found_callback: Callable[[str, str, str, str], None] | None = None

    def set_run_name(self, run_name: str) -> None:
        self.run_name = run_name
        self.run_id = run_name

    def get_run_dir(self) -> Path:
        if self._run_dir is None:
            import os

            # Check for STRIX_RUNS_DIR environment variable (same as strix_viz uses)
            configured_runs_dir = os.environ.get("STRIX_RUNS_DIR")
            if configured_runs_dir:
                runs_dir = Path(configured_runs_dir).expanduser().resolve()
            else:
                runs_dir = Path.cwd() / "strix_runs"
            runs_dir.mkdir(exist_ok=True, parents=True)

            run_dir_name = self.run_name if self.run_name else self.run_id
            self._run_dir = runs_dir / run_dir_name
            self._run_dir.mkdir(exist_ok=True, parents=True)

            # Initialize events.jsonl file
            events_file_path = self._run_dir / "events.jsonl"
            try:
                self._events_file = events_file_path.open("a", encoding="utf-8")
                logger.info(f"Initialized events.jsonl at: {events_file_path}")
            except (OSError, IOError) as e:
                logger.error(f"Failed to open events.jsonl file at {events_file_path}: {e}")
                self._events_file = None

        return self._run_dir

    def _log_event(self, event_type: str, **kwargs: Any) -> None:
        """Log an event to events.jsonl file."""
        if self._events_file is None:
            self.get_run_dir()  # This will initialize _events_file
        
        if self._events_file is None:
            logger.error("Failed to initialize events.jsonl file")
            return

        event = {
            "ts": datetime.now(UTC).isoformat(),
            "type": event_type,
            **kwargs,
        }
        try:
            event_json = json.dumps(event, ensure_ascii=False)
            self._events_file.write(event_json + "\n")
            self._events_file.flush()
            logger.debug(f"Logged event: {event_type}")
        except (OSError, IOError, AttributeError) as e:
            logger.warning(f"Failed to write event to events.jsonl: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error writing event: {e}")

    def add_vulnerability_report(
        self,
        title: str,
        content: str,
        severity: str,
        agent_id: str | None = None,
        target: str | None = None,
    ) -> str:
        report_id = f"vuln-{len(self.vulnerability_reports) + 1:04d}"

        report = {
            "id": report_id,
            "title": title.strip(),
            "content": content.strip(),
            "severity": severity.lower().strip(),
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

        self.vulnerability_reports.append(report)
        logger.info(f"Added vulnerability report: {report_id} - {title}")

        if self.vulnerability_found_callback:
            self.vulnerability_found_callback(
                report_id, title.strip(), content.strip(), severity.lower().strip()
            )

        # Log vuln_found event for visualization
        self._log_event(
            event_type="vuln_found",
            agent_id=agent_id,
            target=target,
            vuln_id=report_id,
            severity=severity.lower().strip(),
            category=self._extract_category_from_title(title),
            description=content.strip()[:500],  # Truncate for event log
        )

        self.save_run_data()
        return report_id

    def _extract_category_from_title(self, title: str) -> str | None:
        """Extract vulnerability category from title."""
        title_lower = title.lower()
        categories = [
            "sql injection",
            "xss",
            "csrf",
            "idor",
            "ssrf",
            "xxe",
            "rce",
            "authentication",
            "authorization",
            "path traversal",
            "file upload",
            "mass assignment",
            "business logic",
            "race condition",
        ]
        for category in categories:
            if category in title_lower:
                return category.replace(" ", "_")
        return None

    def set_final_scan_result(
        self,
        content: str,
        success: bool = True,
    ) -> None:
        self.final_scan_result = content.strip()

        self.scan_results = {
            "scan_completed": True,
            "content": content,
            "success": success,
        }

        logger.info(f"Set final scan result: success={success}")
        self.save_run_data(mark_complete=True)

    def log_agent_creation(
        self, agent_id: str, name: str, task: str, parent_id: str | None = None
    ) -> None:
        agent_data: dict[str, Any] = {
            "id": agent_id,
            "name": name,
            "task": task,
            "status": "running",
            "parent_id": parent_id,
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
            "tool_executions": [],
        }

        self.agents[agent_id] = agent_data

        # Log agent_step event for visualization
        logger.info(f"About to log agent_step event for agent {agent_id}")
        self._log_event(
            event_type="agent_step",
            agent_id=agent_id,
            action="created",
            status="running",
            meta={"name": name, "task": task, "parent_id": parent_id},
        )
        logger.info(f"Agent step event logged for agent {agent_id}")

    def log_chat_message(
        self,
        content: str,
        role: str,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        message_id = self._next_message_id
        self._next_message_id += 1

        message_data = {
            "message_id": message_id,
            "content": content,
            "role": role,
            "agent_id": agent_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "metadata": metadata or {},
        }

        self.chat_messages.append(message_data)
        return message_id

    def log_tool_execution_start(self, agent_id: str, tool_name: str, args: dict[str, Any]) -> int:
        execution_id = self._next_execution_id
        self._next_execution_id += 1

        now = datetime.now(UTC).isoformat()
        execution_data = {
            "execution_id": execution_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "args": args,
            "status": "running",
            "result": None,
            "timestamp": now,
            "started_at": now,
            "completed_at": None,
        }

        self.tool_executions[execution_id] = execution_data

        if agent_id in self.agents:
            self.agents[agent_id]["tool_executions"].append(execution_id)

        # Extract target from args for visualization
        target = None
        if isinstance(args, dict):
            target = args.get("url") or args.get("target") or args.get("path")

        # Log mcp_tool_call event for visualization
        self._log_event(
            event_type="mcp_tool_call",
            agent_id=agent_id,
            tool=tool_name,
            target=target,
            status="running",
            args=args,
        )

        return execution_id

    def update_tool_execution(
        self, execution_id: int, status: str, result: Any | None = None
    ) -> None:
        if execution_id in self.tool_executions:
            execution_data = self.tool_executions[execution_id]
            execution_data["status"] = status
            execution_data["result"] = result
            execution_data["completed_at"] = datetime.now(UTC).isoformat()

            # Log tool completion event for visualization
            agent_id = execution_data.get("agent_id")
            tool_name = execution_data.get("tool_name")
            args = execution_data.get("args", {})

            target = None
            if isinstance(args, dict):
                target = args.get("url") or args.get("target") or args.get("path")

            result_summary = None
            if isinstance(result, str):
                result_summary = result[:200] + "..." if len(result) > 200 else result
            elif isinstance(result, dict):
                result_summary = str(result).replace("\n", " ")[:200]

            self._log_event(
                event_type="mcp_tool_call",
                agent_id=agent_id,
                tool=tool_name,
                target=target,
                status=status,
                args=args,
                result_summary=result_summary,
            )

    def update_agent_status(
        self, agent_id: str, status: str, error_message: str | None = None
    ) -> None:
        if agent_id in self.agents:
            self.agents[agent_id]["status"] = status
            self.agents[agent_id]["updated_at"] = datetime.now(UTC).isoformat()
            if error_message:
                self.agents[agent_id]["error_message"] = error_message

        # Log agent_step event for status changes
        self._log_event(
            event_type="agent_step",
            agent_id=agent_id,
            action="status_update",
            status=status,
            meta={"error_message": error_message} if error_message else {},
        )

    def set_scan_config(self, config: dict[str, Any]) -> None:
        self.scan_config = config
        self.run_metadata.update(
            {
                "targets": config.get("targets", []),
                "user_instructions": config.get("user_instructions", ""),
                "max_iterations": config.get("max_iterations", 200),
            }
        )
        self.get_run_dir()
        # Log initial scan start event
        self._log_event(
            event_type="scan_start",
            run_id=self.run_id,
            run_name=self.run_name,
            targets=config.get("targets", []),
            meta={"start_time": self.start_time},
        )

    def save_run_data(self, mark_complete: bool = False) -> None:
        try:
            run_dir = self.get_run_dir()
            if mark_complete:
                self.end_time = datetime.now(UTC).isoformat()

            if self.final_scan_result:
                penetration_test_report_file = run_dir / "penetration_test_report.md"
                with penetration_test_report_file.open("w", encoding="utf-8") as f:
                    f.write("# Security Penetration Test Report\n\n")
                    f.write(
                        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                    )
                    f.write(f"{self.final_scan_result}\n")
                logger.info(
                    f"Saved final penetration test report to: {penetration_test_report_file}"
                )

            if self.vulnerability_reports:
                vuln_dir = run_dir / "vulnerabilities"
                vuln_dir.mkdir(exist_ok=True)

                new_reports = [
                    report
                    for report in self.vulnerability_reports
                    if report["id"] not in self._saved_vuln_ids
                ]

                for report in new_reports:
                    vuln_file = vuln_dir / f"{report['id']}.md"
                    with vuln_file.open("w", encoding="utf-8") as f:
                        f.write(f"# {report['title']}\n\n")
                        f.write(f"**ID:** {report['id']}\n")
                        f.write(f"**Severity:** {report['severity'].upper()}\n")
                        f.write(f"**Found:** {report['timestamp']}\n\n")
                        f.write("## Description\n\n")
                        f.write(f"{report['content']}\n")
                    self._saved_vuln_ids.add(report["id"])

                if self.vulnerability_reports:
                    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                    sorted_reports = sorted(
                        self.vulnerability_reports,
                        key=lambda x: (severity_order.get(x["severity"], 5), x["timestamp"]),
                    )

                    vuln_csv_file = run_dir / "vulnerabilities.csv"
                    with vuln_csv_file.open("w", encoding="utf-8", newline="") as f:
                        import csv

                        fieldnames = ["id", "title", "severity", "timestamp", "file"]
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()

                        for report in sorted_reports:
                            writer.writerow(
                                {
                                    "id": report["id"],
                                    "title": report["title"],
                                    "severity": report["severity"].upper(),
                                    "timestamp": report["timestamp"],
                                    "file": f"vulnerabilities/{report['id']}.md",
                                }
                            )

                if new_reports:
                    logger.info(
                        f"Saved {len(new_reports)} new vulnerability report(s) to: {vuln_dir}"
                    )
                logger.info(f"Updated vulnerability index: {vuln_csv_file}")

            logger.info(f"📊 Essential scan data saved to: {run_dir}")

        except (OSError, RuntimeError):
            logger.exception("Failed to save scan data")

    def _calculate_duration(self) -> float:
        try:
            start = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
            if self.end_time:
                end = datetime.fromisoformat(self.end_time.replace("Z", "+00:00"))
                return (end - start).total_seconds()
        except (ValueError, TypeError):
            pass
        return 0.0

    def get_agent_tools(self, agent_id: str) -> list[dict[str, Any]]:
        return [
            exec_data
            for exec_data in self.tool_executions.values()
            if exec_data.get("agent_id") == agent_id
        ]

    def get_real_tool_count(self) -> int:
        return sum(
            1
            for exec_data in self.tool_executions.values()
            if exec_data.get("tool_name") not in ["scan_start_info", "subagent_start_info"]
        )

    def get_total_llm_stats(self) -> dict[str, Any]:
        from strix.tools.agents_graph.agents_graph_actions import _agent_instances

        total_stats = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
            "cache_creation_tokens": 0,
            "cost": 0.0,
            "requests": 0,
            "failed_requests": 0,
        }

        for agent_instance in _agent_instances.values():
            if hasattr(agent_instance, "llm") and hasattr(agent_instance.llm, "_total_stats"):
                agent_stats = agent_instance.llm._total_stats
                total_stats["input_tokens"] += agent_stats.input_tokens
                total_stats["output_tokens"] += agent_stats.output_tokens
                total_stats["cached_tokens"] += agent_stats.cached_tokens
                total_stats["cache_creation_tokens"] += agent_stats.cache_creation_tokens
                total_stats["cost"] += agent_stats.cost
                total_stats["requests"] += agent_stats.requests
                total_stats["failed_requests"] += agent_stats.failed_requests

        total_stats["cost"] = round(total_stats["cost"], 4)

        return {
            "total": total_stats,
            "total_tokens": total_stats["input_tokens"] + total_stats["output_tokens"],
        }

    def cleanup(self) -> None:
        self.save_run_data(mark_complete=True)
        if self._events_file:
            try:
                self._events_file.close()
            except (OSError, IOError):
                pass
            self._events_file = None
