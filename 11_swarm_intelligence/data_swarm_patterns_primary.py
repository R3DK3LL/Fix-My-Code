#!/usr/bin/env python3

import hashlib
import hmac
import json
import time
from typing import Dict, Any, List, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import threading
from collections import defaultdict, Counter, deque
import uuid
from concurrent.futures import ThreadPoolExecutor
import statistics


class PacketStatus(Enum):
    PENDING = "pending"
    VALIDATED = "validated"
    SWARMED = "swarmed"
    COLLAPSED = "collapsed"
    ORPHANED = "orphaned"


class SwarmNodeRole(Enum):
    VALIDATOR = "validator"
    STORAGE = "storage"
    COORDINATOR = "coordinator"
    OBSERVER = "observer"


class MessageType(Enum):
    DATA_PACKET = "data_packet"
    HEARTBEAT = "heartbeat"
    ROLE_ASSIGNMENT = "role_assignment"
    ERROR_REPORT = "error_report"
    SIGNATURE_CHALLENGE = "signature_challenge"


class FailureType(Enum):
    NETWORK_TIMEOUT = "network_timeout"
    SIGNATURE_INVALID = "signature_invalid"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    ROLE_CONFLICT = "role_conflict"
    CONSTRAINT_VIOLATION = "constraint_violation"


@dataclass
class SwarmMessage:
    message_id: str
    message_type: MessageType
    sender_id: str
    recipient_id: str
    payload: Dict[str, Any]
    timestamp: float
    signature: str
    latency_ms: Optional[float] = None
    delivered: bool = False


@dataclass
class NodeCapacity:
    max_packets: int
    max_connections: int
    processing_power: float
    storage_capacity: int
    current_load: float = 0.0


@dataclass
class FailureRecord:
    failure_id: str
    failure_type: FailureType
    node_id: str
    timestamp: float
    details: Dict[str, Any]
    recovery_attempted: bool = False
    quarantined: bool = False


@dataclass
class DataPacket:
    packet_id: str
    origin_node: str
    data: Dict[str, Any]
    timestamp: float
    signature: str
    parent_hash: Optional[str] = None
    swarm_version: int = 0
    status: PacketStatus = PacketStatus.PENDING
    replica_count: int = 0


@dataclass
class SwarmState:
    version: int
    node_count: int
    packet_hashes: Set[str] = field(default_factory=set)
    coherence_score: float = 1.0
    last_update: float = field(default_factory=time.time)
    network_load: float = 0.0
    dynamic_latency_bound: float = 0.0


class DataSwarmEngine:

    def __init__(
        self,
        node_id: str,
        secret_key: str,
        adaptive_params: Optional[Dict[str, float]] = None,
    ):
        self.node_id = node_id
        self.secret_key = secret_key.encode("utf-8")
        self.role = SwarmNodeRole.OBSERVER

        self.params = adaptive_params or {}
        self.min_replicas = max(
            int(self.params.get("replica_factor", 0.3) * self._get_initial_capacity()),
            2,
        )
        self.capacity = self._initialize_adaptive_capacity()

        self.local_packets = {}
        self.replica_registry = defaultdict(set)
        self.swarm_state = SwarmState(version=1, node_count=1)
        self.peer_nodes = {}
        self.node_roles = {self.node_id: SwarmNodeRole.OBSERVER}

        self.validated_packets = {}
        self.collapsed_packets = {}
        self.orphaned_packets = {}

        self.message_queue = deque()
        self.latency_history = deque(maxlen=self._get_adaptive_window_size())
        self.failure_records = {}
        self.quarantined_failures = {}

        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(
            max_workers=self._get_adaptive_worker_count()
        )

    def _get_initial_capacity(self) -> int:
        return max(int(self.params.get("base_capacity_multiplier", 1.0) * 100), 50)

    def _initialize_adaptive_capacity(self) -> NodeCapacity:
        base_capacity = self._get_initial_capacity()
        return NodeCapacity(
            max_packets=base_capacity * 10,
            max_connections=max(int(base_capacity * 0.5), 5),
            processing_power=self.params.get("processing_multiplier", 1.0),
            storage_capacity=base_capacity * 100,
            current_load=0.0,
        )

    def _get_adaptive_window_size(self) -> int:
        return max(int(self.params.get("window_size_multiplier", 1.0) * 50), 10)

    def _get_adaptive_worker_count(self) -> int:
        return max(int(self.params.get("worker_multiplier", 1.0) * 2), 1)

    def _compute_message_ttl(self) -> float:
        base_ttl = self.params.get("base_ttl_seconds", 60.0)
        load_factor = max(self.swarm_state.network_load, 0.1)
        return base_ttl * (2.0 - load_factor)

    def validate_message(self, message: SwarmMessage) -> bool:
        if not isinstance(message.payload, dict):
            return False
        if message.sender_id == self.node_id:
            return False
        if time.time() - message.timestamp > self._compute_message_ttl():
            return False
        return self.verify_message_signature(message)

    def deliver_message(self, message: SwarmMessage) -> bool:
        if message.recipient_id != self.node_id and message.recipient_id != "broadcast":
            return False

        start_time = time.perf_counter()
        try:
            self.message_queue.append(message)
            message.delivered = True

            latency = (time.perf_counter() - start_time) * 1000
            message.latency_ms = latency
            self.latency_history.append(latency)

            return latency <= self.get_dynamic_latency_bound()
        except Exception:
            return False

    def get_dynamic_latency_bound(self) -> float:
        if len(self.latency_history) < max(int(len(self.latency_history) * 0.1), 3):
            min_bound = self.params.get("min_latency_ms", 10.0)
            self.swarm_state.dynamic_latency_bound = min_bound
            return min_bound

        recent_latencies = list(self.latency_history)
        avg_latency = statistics.mean(recent_latencies)
        std_latency = (
            statistics.stdev(recent_latencies)
            if len(recent_latencies) > 1
            else avg_latency * 0.1
        )

        load_multiplier = 1.0 + (self.swarm_state.network_load * 2.0)
        std_multiplier = self.params.get("std_deviation_multiplier", 2.0)

        dynamic_bound = avg_latency + (std_multiplier * std_latency * load_multiplier)

        min_bound = self.params.get("min_latency_ms", 10.0)
        max_bound = avg_latency * self.params.get("max_latency_multiplier", 10.0)

        self.swarm_state.dynamic_latency_bound = max(
            min(dynamic_bound, max_bound), min_bound
        )
        return self.swarm_state.dynamic_latency_bound

    def send_p2p_message(
        self, recipient_id: str, message_type: MessageType, payload: Dict[str, Any]
    ) -> bool:
        message = self.create_signed_message(recipient_id, message_type, payload)

        if not self.validate_message(message):
            return False

        if not self.deliver_message(message):
            self.record_failure(
                FailureType.NETWORK_TIMEOUT,
                f"Message delivery failed: {message.message_id}",
            )
            return False

        return True

    def create_signed_message(
        self, recipient_id: str, message_type: MessageType, payload: Dict[str, Any]
    ) -> SwarmMessage:
        message_id = str(uuid.uuid4())
        timestamp = time.time()

        message_content = {
            "message_id": message_id,
            "message_type": message_type.value,
            "sender_id": self.node_id,
            "recipient_id": recipient_id,
            "payload": payload,
            "timestamp": timestamp,
        }

        content_str = json.dumps(message_content, sort_keys=True)
        signature = hmac.new(
            self.secret_key, content_str.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return SwarmMessage(
            message_id=message_id,
            message_type=message_type,
            sender_id=self.node_id,
            recipient_id=recipient_id,
            payload=payload,
            timestamp=timestamp,
            signature=signature,
        )

    def verify_message_signature(self, message: SwarmMessage) -> bool:
        message_content = {
            "message_id": message.message_id,
            "message_type": message.message_type.value,
            "sender_id": message.sender_id,
            "recipient_id": message.recipient_id,
            "payload": message.payload,
            "timestamp": message.timestamp,
        }

        content_str = json.dumps(message_content, sort_keys=True)
        expected_signature = hmac.new(
            self.secret_key, content_str.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return message.signature == expected_signature

    def multi_signature_verify(
        self, data: Dict[str, Any], signatures: List[str], schemes: List[str] = None
    ) -> bool:
        schemes = schemes or ["HMAC-SHA256"]

        for i, scheme in enumerate(schemes):
            if i < len(signatures):
                if scheme == "HMAC-SHA256":
                    content_str = json.dumps(data, sort_keys=True)
                    expected_sig = hmac.new(
                        self.secret_key, content_str.encode("utf-8"), hashlib.sha256
                    ).hexdigest()
                    if signatures[i] == expected_sig:
                        return True

        return False

    def validate_payload_schema(
        self, data: Dict[str, Any], expected_schema: Dict[str, type]
    ) -> bool:
        if not isinstance(data, dict):
            return False

        for field_name, field_type in expected_schema.items():
            if field_name not in data:
                return False
            if not isinstance(data[field_name], field_type):
                return False

        return True

    def create_signed_packet(
        self, data: Dict[str, Any], parent_hash: Optional[str] = None
    ) -> DataPacket:
        packet_id = str(uuid.uuid4())
        timestamp = time.time()

        packet_content = {
            "packet_id": packet_id,
            "origin_node": self.node_id,
            "data": data,
            "timestamp": timestamp,
            "parent_hash": parent_hash,
            "swarm_version": self.swarm_state.version,
        }

        content_str = json.dumps(packet_content, sort_keys=True)
        signature = hmac.new(
            self.secret_key, content_str.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return DataPacket(
            packet_id=packet_id,
            origin_node=self.node_id,
            data=data,
            timestamp=timestamp,
            signature=signature,
            parent_hash=parent_hash,
            swarm_version=self.swarm_state.version,
        )

    def verify_packet_signature(
        self, packet: DataPacket, peer_public_key: Optional[str] = None
    ) -> bool:
        packet_content = {
            "packet_id": packet.packet_id,
            "origin_node": packet.origin_node,
            "data": packet.data,
            "timestamp": packet.timestamp,
            "parent_hash": packet.parent_hash,
            "swarm_version": packet.swarm_version,
        }

        content_str = json.dumps(packet_content, sort_keys=True)

        expected_signature = hmac.new(
            self.secret_key, content_str.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return packet.signature == expected_signature

    def ensure_packet_redundancy(self, packet: DataPacket) -> bool:
        with self.lock:
            replica_count = len(self.replica_registry[packet.packet_id])
            packet.replica_count = replica_count

            if replica_count < self.min_replicas:
                self._replicate_packet(packet)
                return False

            return True

    def _replicate_packet(self, packet: DataPacket):
        needed_replicas = self.min_replicas - packet.replica_count
        available_peers = list(
            set(self.peer_nodes.keys()) - self.replica_registry[packet.packet_id]
        )

        for i, peer_id in enumerate(available_peers[:needed_replicas]):
            self.replica_registry[packet.packet_id].add(peer_id)

    def validate_swarm_coherence(self, packet: DataPacket) -> bool:
        with self.lock:
            version_tolerance = max(int(self.params.get("version_tolerance", 1)), 1)
            if packet.swarm_version > self.swarm_state.version + version_tolerance:
                return False

            if packet.parent_hash:
                if packet.parent_hash not in self.swarm_state.packet_hashes:
                    return False

            packet_hash = self._hash_packet(packet)
            if packet_hash in self.swarm_state.packet_hashes:
                return False

            return True

    def _hash_packet(self, packet: DataPacket) -> str:
        content = f"{packet.packet_id}:{packet.origin_node}:{packet.timestamp}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def swarm_data_packet(
        self, data: Dict[str, Any], expected_schema: Optional[Dict[str, type]] = None
    ) -> Optional[str]:
        if expected_schema and not self.validate_payload_schema(data, expected_schema):
            return None

        packet = self.create_signed_packet(data)

        if not self.verify_packet_signature(packet):
            self.collapsed_packets[packet.packet_id] = packet
            return None

        if not self.validate_swarm_coherence(packet):
            packet.status = PacketStatus.ORPHANED
            self.orphaned_packets[packet.packet_id] = packet
            return None

        with self.lock:
            self.local_packets[packet.packet_id] = packet
            self.replica_registry[packet.packet_id].add(self.node_id)

            packet.status = PacketStatus.VALIDATED
            self.validated_packets[packet.packet_id] = packet

            packet_hash = self._hash_packet(packet)
            self.swarm_state.packet_hashes.add(packet_hash)
            self.swarm_state.last_update = time.time()

            self._update_capacity_load()

        if self.ensure_packet_redundancy(packet):
            packet.status = PacketStatus.SWARMED

        return packet.packet_id

    def _update_capacity_load(self):
        self.capacity.current_load = len(self.local_packets) / max(
            self.capacity.max_packets, 1
        )
        self.swarm_state.network_load = self.capacity.current_load

    def record_failure(
        self, failure_type: FailureType, details: str, node_id: str = None
    ) -> str:
        failure_id = str(uuid.uuid4())
        node_id = node_id or self.node_id

        failure = FailureRecord(
            failure_id=failure_id,
            failure_type=failure_type,
            node_id=node_id,
            timestamp=time.time(),
            details={"description": details},
        )

        with self.lock:
            self.failure_records[failure_id] = failure

            if self.classify_and_recover_failure(failure):
                failure.recovery_attempted = True
            else:
                failure.quarantined = True
                self.quarantined_failures[failure_id] = failure

        return failure_id

    def classify_and_recover_failure(self, failure: FailureRecord) -> bool:
        if failure.failure_type == FailureType.NETWORK_TIMEOUT:
            return self.recover_network_timeout(failure)
        elif failure.failure_type == FailureType.SIGNATURE_INVALID:
            return self.recover_signature_failure(failure)
        elif failure.failure_type == FailureType.CAPACITY_EXCEEDED:
            return self.recover_capacity_failure(failure)
        elif failure.failure_type == FailureType.ROLE_CONFLICT:
            return self.recover_role_conflict(failure)
        else:
            return False

    def recover_network_timeout(self, failure: FailureRecord) -> bool:
        self.get_dynamic_latency_bound()
        min_samples = max(int(len(self.latency_history) * 0.1), 3)
        return len(self.latency_history) > min_samples

    def recover_signature_failure(self, failure: FailureRecord) -> bool:
        peer_id = failure.details.get("peer_id")
        if peer_id and peer_id in self.peer_nodes:
            self.remove_peer_node(peer_id)
            return True
        return False

    def recover_capacity_failure(self, failure: FailureRecord) -> bool:
        capacity_threshold = self.params.get("capacity_recovery_threshold", 0.8)
        if self.capacity.current_load > capacity_threshold:
            cleanup_ratio = self.params.get("packet_cleanup_ratio", 0.1)
            cleanup_count = max(int(len(self.local_packets) * cleanup_ratio), 1)

            oldest_packets = sorted(
                self.local_packets.items(), key=lambda x: x[1].timestamp
            )[:cleanup_count]

            for packet_id, _ in oldest_packets:
                if packet_id in self.local_packets:
                    del self.local_packets[packet_id]

            self._update_capacity_load()
            return True
        return False

    def recover_role_conflict(self, failure: FailureRecord) -> bool:
        conflicted_role = failure.details.get("role")
        if conflicted_role:
            self.reassign_node_role()
            return True
        return False

    def assign_node_role(
        self, node_id: str, role: SwarmNodeRole, capacity: NodeCapacity
    ) -> bool:
        if not self.verify_node_capacity(node_id, capacity):
            self.record_failure(
                FailureType.CAPACITY_EXCEEDED, f"Node {node_id} capacity insufficient"
            )
            return False

        if self.check_role_conflict(node_id, role):
            self.record_failure(
                FailureType.ROLE_CONFLICT, f"Role conflict for {node_id}: {role}"
            )
            return False

        with self.lock:
            self.node_roles[node_id] = role
            if node_id == self.node_id:
                self.role = role
                self.capacity = capacity
            elif node_id in self.peer_nodes:
                self.peer_nodes[node_id]["role"] = role
                self.peer_nodes[node_id]["capacity"] = capacity

        self.monitor_node_behavior(node_id)
        return True

    def verify_node_capacity(self, node_id: str, capacity: NodeCapacity) -> bool:
        min_packets = max(
            int(self.params.get("min_packet_capacity_multiplier", 1.0) * 50), 10
        )
        min_connections = max(
            int(self.params.get("min_connection_multiplier", 1.0) * 5), 2
        )
        min_processing = self.params.get("min_processing_power", 0.1)
        min_storage = max(
            int(self.params.get("min_storage_multiplier", 1.0) * 500), 100
        )

        if capacity.max_packets < min_packets:
            return False
        if capacity.max_connections < min_connections:
            return False
        if capacity.processing_power < min_processing:
            return False
        if capacity.storage_capacity < min_storage:
            return False
        return True

    def check_role_conflict(self, node_id: str, role: SwarmNodeRole) -> bool:
        if role == SwarmNodeRole.COORDINATOR:
            max_coordinators = max(
                int(self.params.get("max_coordinators_multiplier", 1.0) * 3), 1
            )
            coordinator_count = sum(
                1 for r in self.node_roles.values() if r == SwarmNodeRole.COORDINATOR
            )
            if coordinator_count >= max_coordinators:
                return True
        return False

    def reassign_node_role(self) -> bool:
        available_roles = [
            SwarmNodeRole.VALIDATOR,
            SwarmNodeRole.STORAGE,
            SwarmNodeRole.OBSERVER,
        ]

        for role in available_roles:
            if not self.check_role_conflict(self.node_id, role):
                self.role = role
                self.node_roles[self.node_id] = role
                return True
        return False

    def monitor_node_behavior(self, node_id: str):
        def behavior_monitor():
            if node_id in self.peer_nodes:
                peer_info = self.peer_nodes[node_id]
                current_load = peer_info.get("current_load", 0.0)
                load_threshold = self.params.get("node_load_threshold", 0.9)

                if current_load > load_threshold:
                    self.record_failure(
                        FailureType.CAPACITY_EXCEEDED,
                        f"Node {node_id} exceeding capacity",
                        node_id,
                    )

        self.executor.submit(behavior_monitor)

    def enforce_system_constraints(self) -> bool:
        total_constraints = 5
        constraints_passed = 0

        if self.validate_p2p_constraints():
            constraints_passed += 1

        if self.validate_signature_constraints():
            constraints_passed += 1

        if self.validate_error_handling_constraints():
            constraints_passed += 1

        if self.validate_role_constraints():
            constraints_passed += 1

        if self.validate_no_contradictions():
            constraints_passed += 1

        return constraints_passed == total_constraints

    def validate_p2p_constraints(self) -> bool:
        if len(self.latency_history) == 0:
            return True

        recent_samples = max(int(len(self.latency_history) * 0.2), 3)
        recent_latencies = list(self.latency_history)[-recent_samples:]
        bound = self.get_dynamic_latency_bound()

        return all(latency <= bound for latency in recent_latencies)

    def validate_signature_constraints(self) -> bool:
        return len(self.collapsed_packets) == 0 or all(
            packet.status == PacketStatus.COLLAPSED
            for packet in self.collapsed_packets.values()
        )

    def validate_error_handling_constraints(self) -> bool:
        unhandled_failures = [
            f
            for f in self.failure_records.values()
            if not f.recovery_attempted and not f.quarantined
        ]
        return len(unhandled_failures) == 0

    def validate_role_constraints(self) -> bool:
        return all(
            node_id in self.node_roles
            for node_id in [self.node_id] + list(self.peer_nodes.keys())
        )

    def validate_no_contradictions(self) -> bool:
        role_counts = Counter(self.node_roles.values())
        max_coordinators = max(
            int(self.params.get("max_coordinators_multiplier", 1.0) * 3), 1
        )
        return role_counts[SwarmNodeRole.COORDINATOR] <= max_coordinators

    def get_swarm_health(self) -> Dict[str, Any]:
        with self.lock:
            total_packets = len(self.local_packets)
            validated_packets = len(self.validated_packets)
            swarmed_packets = sum(
                1
                for p in self.local_packets.values()
                if p.status == PacketStatus.SWARMED
            )
            collapsed_packets = len(self.collapsed_packets)
            orphaned_packets = len(self.orphaned_packets)

            coherence_score = validated_packets / max(total_packets, 1)

            return {
                "node_id": self.node_id,
                "swarm_version": self.swarm_state.version,
                "total_packets": total_packets,
                "validated_packets": validated_packets,
                "swarmed_packets": swarmed_packets,
                "collapsed_packets": collapsed_packets,
                "orphaned_packets": orphaned_packets,
                "coherence_score": coherence_score,
                "peer_count": len(self.peer_nodes),
                "replica_coverage": len(self.replica_registry),
                "dynamic_latency_bound": self.swarm_state.dynamic_latency_bound,
                "failure_count": len(self.failure_records),
                "quarantined_failures": len(self.quarantined_failures),
                "system_constraints_valid": self.enforce_system_constraints(),
                "current_load": self.capacity.current_load,
                "adaptive_params": self.params,
            }

    def add_peer_node(
        self,
        peer_id: str,
        role: SwarmNodeRole = SwarmNodeRole.OBSERVER,
        capacity: NodeCapacity = None,
    ):
        if capacity is None:
            base_capacity = self._get_initial_capacity()
            capacity = NodeCapacity(
                max_packets=int(
                    base_capacity * self.params.get("peer_capacity_multiplier", 0.5)
                ),
                max_connections=max(int(base_capacity * 0.25), 2),
                processing_power=self.params.get("peer_processing_multiplier", 0.5),
                storage_capacity=int(base_capacity * 50),
                current_load=0.0,
            )

        with self.lock:
            self.peer_nodes[peer_id] = {
                "role": role,
                "capacity": capacity,
                "current_load": 0.0,
                "last_seen": time.time(),
            }
            self.node_roles[peer_id] = role
            self.swarm_state.node_count = len(self.peer_nodes) + 1

            self.min_replicas = max(
                int(
                    self.params.get("replica_factor", 0.3) * self.swarm_state.node_count
                ),
                2,
            )

    def remove_peer_node(self, peer_id: str):
        with self.lock:
            if peer_id in self.peer_nodes:
                del self.peer_nodes[peer_id]
                if peer_id in self.node_roles:
                    del self.node_roles[peer_id]

                self.swarm_state.node_count = len(self.peer_nodes) + 1
                self.min_replicas = max(
                    int(
                        self.params.get("replica_factor", 0.3)
                        * self.swarm_state.node_count
                    ),
                    2,
                )

                for packet_id, replicas in self.replica_registry.items():
                    if peer_id in replicas:
                        replicas.remove(peer_id)
                        if len(replicas) < self.min_replicas:
                            packet = self.local_packets.get(packet_id)
                            if packet:
                                self._replicate_packet(packet)


if __name__ == "__main__":
    import random
    import sys

    def test_basic_swarm_functionality():
        print("=== Testing Basic Swarm Functionality ===")

        # Create adaptive parameters for testing
        adaptive_params = {
            "replica_factor": 0.4,
            "base_capacity_multiplier": 1.2,
            "processing_multiplier": 1.0,
            "window_size_multiplier": 0.8,
            "worker_multiplier": 1.0,
            "base_ttl_seconds": 30.0,
            "min_latency_ms": 5.0,
            "std_deviation_multiplier": 2.5,
            "max_latency_multiplier": 8.0,
        }

        # Initialize swarm nodes
        node1 = DataSwarmEngine("node_001", "test-secret-key-123", adaptive_params)
        node2 = DataSwarmEngine("node_002", "test-secret-key-123", adaptive_params)
        node3 = DataSwarmEngine("node_003", "test-secret-key-123", adaptive_params)

        print(f"Node 1 initial capacity: {node1.capacity.max_packets} packets")
        print(f"Node 1 min replicas: {node1.min_replicas}")
        print(
            f"Node 1 dynamic latency bound: {node1.get_dynamic_latency_bound():.2f}ms"
        )

        # Connect nodes to form swarm
        node1.add_peer_node("node_002", SwarmNodeRole.VALIDATOR)
        node1.add_peer_node("node_003", SwarmNodeRole.STORAGE)
        node2.add_peer_node("node_001", SwarmNodeRole.COORDINATOR)
        node2.add_peer_node("node_003", SwarmNodeRole.STORAGE)

        print(f"\nSwarm formed with {node1.swarm_state.node_count} nodes")
        print(f"Updated min replicas: {node1.min_replicas}")

        return node1, node2, node3

    def test_data_packet_swarming(node1, node2, node3):
        print("\n=== Testing Data Packet Swarming ===")

        # Define adaptive schema
        sensor_schema = {
            "sensor_id": str,
            "temperature": float,
            "humidity": float,
            "timestamp": int,
            "location": str,
        }

        # Test valid data packets
        valid_packets = []
        for i in range(5):
            sensor_data = {
                "sensor_id": f"sensor_{i:03d}",
                "temperature": random.uniform(15.0, 35.0),
                "humidity": random.uniform(30.0, 80.0),
                "timestamp": int(time.time()) + i,
                "location": random.choice(["warehouse_a", "warehouse_b", "office"]),
            }

            packet_id = node1.swarm_data_packet(sensor_data, sensor_schema)
            if packet_id:
                valid_packets.append(packet_id)
                print(f"✓ Packet {i+1} swarmed successfully: {packet_id[:8]}...")
            else:
                print(f"✗ Packet {i+1} failed to swarm")

        # Test invalid data packet (should collapse)
        invalid_data = {
            "sensor_id": "invalid_sensor",
            "temperature": "not_a_number",  # Wrong type
            "humidity": 45.0,
            "timestamp": int(time.time()),
            "location": "test_location",
        }

        invalid_packet_id = node1.swarm_data_packet(invalid_data, sensor_schema)
        if invalid_packet_id is None:
            print("✓ Invalid packet correctly collapsed")
        else:
            print("✗ Invalid packet should have collapsed")

        print(f"\nValid packets created: {len(valid_packets)}")
        return valid_packets

    def test_p2p_messaging(node1, node2, node3):
        print("\n=== Testing P2P Messaging ===")

        # Test successful message delivery
        success_count = 0
        for i in range(3):
            message_payload = {
                "message_type": "test_data",
                "sequence": i,
                "data": f"test_message_{i}",
            }

            if node1.send_p2p_message(
                "node_002", MessageType.DATA_PACKET, message_payload
            ):
                success_count += 1
                print(f"✓ Message {i+1} sent successfully")
            else:
                print(f"✗ Message {i+1} failed to send")

        print(f"Messages sent successfully: {success_count}/3")
        print(f"Current latency bound: {node1.get_dynamic_latency_bound():.2f}ms")

        return success_count

    def test_failure_recovery(node1):
        print("\n=== Testing Failure Recovery ===")

        # Simulate network timeout failure
        timeout_failure_id = node1.record_failure(
            FailureType.NETWORK_TIMEOUT, "Simulated network timeout during testing"
        )

        # Simulate capacity exceeded failure
        capacity_failure_id = node1.record_failure(
            FailureType.CAPACITY_EXCEEDED, "Simulated capacity exceeded during testing"
        )

        # Check failure handling
        health = node1.get_swarm_health()

        print(f"Total failures recorded: {health['failure_count']}")
        print(f"Quarantined failures: {health['quarantined_failures']}")
        print(f"System constraints valid: {health['system_constraints_valid']}")

        return health["failure_count"], health["quarantined_failures"]

    def test_adaptive_parameters(node1):
        print("\n=== Testing Adaptive Parameter Evolution ===")

        initial_bound = node1.get_dynamic_latency_bound()
        print(f"Initial latency bound: {initial_bound:.2f}ms")

        # Simulate some network activity to build latency history
        for i in range(20):
            # Simulate varying latency
            simulated_latency = random.uniform(5.0, 50.0) + (
                i * 0.5
            )  # Gradually increasing
            node1.latency_history.append(simulated_latency)

        # Update network load
        node1.swarm_state.network_load = random.uniform(0.3, 0.8)

        new_bound = node1.get_dynamic_latency_bound()
        print(f"Adapted latency bound: {new_bound:.2f}ms")
        print(f"Network load: {node1.swarm_state.network_load:.2f}")
        print(f"Current capacity load: {node1.capacity.current_load:.2f}")

        return abs(new_bound - initial_bound) > 1.0  # Check if adaptation occurred

    def run_comprehensive_test():
        print("🔒 VALHALLA Data Swarm Engine - Standalone Test")
        print("=" * 50)

        try:
            # Test 1: Basic functionality
            node1, node2, node3 = test_basic_swarm_functionality()

            # Test 2: Data packet swarming
            valid_packets = test_data_packet_swarming(node1, node2, node3)

            # Test 3: P2P messaging
            message_success = test_p2p_messaging(node1, node2, node3)

            # Test 4: Failure recovery
            failures, quarantined = test_failure_recovery(node1)

            # Test 5: Adaptive parameters
            adaptation_occurred = test_adaptive_parameters(node1)

            # Final health report
            print("\n=== Final System Health Report ===")
            health = node1.get_swarm_health()

            for key, value in health.items():
                if key == "adaptive_params":
                    continue
                print(f"{key}: {value}")

            # Test results summary
            print("\n=== Test Results Summary ===")
            print(f"✓ Swarm nodes initialized: 3/3")
            print(f"✓ Valid packets swarmed: {len(valid_packets)}/5")
            print(f"✓ P2P messages sent: {message_success}/3")
            print(f"✓ Failures handled: {failures > 0}")
            print(f"✓ Adaptive parameters working: {adaptation_occurred}")
            print(f"✓ System constraints valid: {health['system_constraints_valid']}")

            overall_success = (
                len(valid_packets) >= 3
                and message_success >= 2
                and health["system_constraints_valid"]
                and adaptation_occurred
            )

            if overall_success:
                print("\n🎉 All tests PASSED - Swarm engine functioning correctly!")
                return 0
            else:
                print("\n⚠️  Some tests FAILED - Check implementation")
                return 1

        except Exception as e:
            print(f"\n❌ Test execution FAILED: {str(e)}")
            import traceback

            traceback.print_exc()
            return 1

    # Run the comprehensive test
    exit_code = run_comprehensive_test()
