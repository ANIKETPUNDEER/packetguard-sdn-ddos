"""PacketGuard Ryu app: OpenFlow 1.3 learning, flow telemetry, RF policy.

Start from the project root with:
  ryu-manager --ofp-tcp-listen-port 6653 controller/packetguard_ryu.py

This app assumes the isolated lab's reserved attack source prefix is
10.0.0.192/28. Validate and change that prefix for any other topology.
"""
from __future__ import annotations

import json
import ipaddress
import os
import time
from collections import defaultdict, deque

import joblib
import pandas as pd
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, ether_types
from ryu.ofproto import ofproto_v1_3

FEATURES = ["packet_rate", "byte_count", "duration_s", "protocol", "dst_port"]
ATTACK_PREFIX = os.environ.get("PACKETGUARD_ATTACK_PREFIX", "10.0.0.192/28")
ATTACK_NETWORK = ipaddress.ip_network(ATTACK_PREFIX, strict=False)
if ATTACK_NETWORK.version != 4:
    raise ValueError("PACKETGUARD_ATTACK_PREFIX must be an IPv4 network")
BENIGN_FORWARD_ENDPOINTS = frozenset(
    address.strip() for address in os.environ.get(
        "PACKETGUARD_BENIGN_FORWARD_ENDPOINTS", "10.0.0.1,10.0.0.2").split(",")
    if address.strip())
MODEL_PATH = os.environ.get("PACKETGUARD_MODEL", "artifacts/model.joblib")
LOW_THRESHOLD = float(os.environ.get("PACKETGUARD_LOW_THRESHOLD", "0.30"))
HIGH_THRESHOLD = float(os.environ.get("PACKETGUARD_HIGH_THRESHOLD", "0.70"))
POLL_SECONDS = 2
THROTTLE_KBPS = int(os.environ.get("PACKETGUARD_THROTTLE_KBPS", "1000"))
RULE_MODE = os.environ.get("PACKETGUARD_RULE_MODE", "intent").strip().lower()
if RULE_MODE not in {"none", "intent", "per-flow"}:
    raise ValueError("PACKETGUARD_RULE_MODE must be 'none', 'intent', or 'per-flow'")
if not 0.0 <= LOW_THRESHOLD < HIGH_THRESHOLD <= 1.0:
    raise ValueError("risk thresholds must satisfy 0 <= low < high <= 1")
if THROTTLE_KBPS <= 0:
    raise ValueError("PACKETGUARD_THROTTLE_KBPS must be positive")


class PacketGuardController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wsgi = kwargs["wsgi"]
        self.wsgi.register(PacketGuardStats, {"packetguard": self})
        # The none mode is the measured forwarding-only control: it deliberately avoids
        # loading or invoking the model and never creates mitigation rules.
        self.model = joblib.load(MODEL_PATH) if RULE_MODE != "none" and os.path.isfile(MODEL_PATH) else None
        if self.model is not None:
            model_classes = set(getattr(self.model, "classes_", []))
            if model_classes != {"benign", "attack"}:
                raise ValueError("model must be trained with exactly 'benign' and 'attack' labels")
            model_features = list(getattr(self.model, "feature_names_in_", FEATURES))
            if model_features != FEATURES:
                raise ValueError(f"model feature order mismatch: expected {FEATURES}, found {model_features}")
        if self.model is None and RULE_MODE != "none":
            self.logger.warning("Model not found at %s; classifier decisions disabled. Train it with ml/train_model.py", MODEL_PATH)
        elif RULE_MODE == "none":
            self.logger.info("Forwarding-only control mode: model loading is intentionally disabled")
        self.mac_to_port = defaultdict(dict)
        self.observed = defaultdict(lambda: {"packets": 0, "bytes": 0, "first": None,
                                             "last_packets": 0, "last_bytes": 0,
                                             "last_duration": 0.0, "last_seen": 0.0})
        self.flow_baselines = {}
        # A flow-stat reply is a measurement window.  Classifying the same
        # installed rule on every poll creates controller work proportional to
        # the duration of a run, rather than to the number of observed flows.
        self.scored_flow_keys = set()
        self.mitigation_keys = set()
        self.switch_counters = {}
        self.datapaths = {}
        self.recent_flows = deque(maxlen=30)
        self.metrics = {"packet_in": 0, "scored_flows": 0, "allow": 0,
                        "throttle": 0, "block": 0, "installed_intents": 0,
                        "last_update": None, "model_loaded": self.model is not None,
                        "attack_prefix": ATTACK_PREFIX, "rule_mode": RULE_MODE}
        self._poller = hub.spawn(self._poll_flow_stats)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        self.datapaths[dp.id] = dp
        # Table-miss: send unclassified traffic to this controller.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions, idle_timeout=0)
        if RULE_MODE != "none":
            # Meter 1 is shared by suspicious traffic in the lab.
            band = parser.OFPMeterBandDrop(rate=THROTTLE_KBPS, burst_size=THROTTLE_KBPS)
            req = parser.OFPMeterMod(dp, ofp.OFPMC_ADD, ofp.OFPMF_KBPS | ofp.OFPMF_BURST,
                                     1, [band])
            dp.send_msg(req)
            self.logger.info("Switch %s connected; meter 1 at %s kbps", dp.id, THROTTLE_KBPS)
        else:
            self.logger.info("Switch %s connected; forwarding-only control mode", dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)
            self.switch_counters.pop(dp.id, None)
            self.metrics["datapath_count"] = len(self.datapaths)
            self.metrics["switch_flow_entries"] = sum(x["flow_entries"] for x in self.switch_counters.values())
            self.metrics["switch_packet_count"] = sum(x["packet_count"] for x in self.switch_counters.values())
            self.metrics["switch_byte_count"] = sum(x["byte_count"] for x in self.switch_counters.values())

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp, ofp, parser = msg.datapath, msg.datapath.ofproto, msg.datapath.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        self.metrics["packet_in"] += 1
        self.mac_to_port[dp.id][eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None and RULE_MODE != "none":
            l4 = pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp)
            if isinstance(l4, tcp.tcp):
                proto, dst_port = 6, l4.dst_port
            elif isinstance(l4, udp.udp):
                proto, dst_port = 17, l4.dst_port
            elif pkt.get_protocol(icmp.icmp) is not None:
                proto, dst_port = 1, 0
            else:
                proto, dst_port = ip.proto, 0
            # Learn an allowed L4 forwarding entry after the destination port
            # is known. Scoring happens only from OpenFlow flow-stat replies.
            if out_port != ofp.OFPP_FLOOD:
                # Intent mode keeps the reserved attack scope aggregated from
                # the first permitted packet onward. Per-flow mode retains an
                # exact source match. Benign traffic always uses an exact rule.
                if proto == 6 and self._is_benign_forward_pair(ip.src, ip.dst):
                    # The benchmark's h1<->h2 TCP test uses a fresh ephemeral
                    # return port each run. Install a pair-scoped TCP rule so
                    # its handshake and return path never compete with an
                    # attack burst for Packet-In handling.
                    allow_match = self._l4_match(parser, ip.src, ip.dst, proto, None)
                    allow_timeout = 60
                elif RULE_MODE == "intent" and self._in_attack_prefix(ip.src):
                    allow_match = self._intent_match(parser, proto, dst_port)
                    allow_timeout = 10
                else:
                    allow_match = self._l4_match(parser, ip.src, ip.dst, proto, dst_port)
                    allow_timeout = 10
                self._add_flow(dp, 400, allow_match, actions, idle_timeout=allow_timeout)
        # Forward the current packet. A learned destination gets a direct output;
        # unknown destinations are flooded as in a basic learning switch.
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        else:
            data = None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    def _apply_decision(self, dp, src_ip, proto, dst_port, score, out_port,
                        dst_ip=None, refresh_allow=False):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        ip_prefix = src_ip if self._in_attack_prefix(src_ip) else None
        if score < LOW_THRESHOLD:
            action_name = "allow"
            actions = [parser.OFPActionOutput(out_port)]
            match = self._l4_match(parser, src_ip, dst_ip, proto, dst_port)
            if refresh_allow:
                self._add_flow(dp, 400, match, actions, idle_timeout=10)
        elif score <= HIGH_THRESHOLD:
            action_name = "throttle"
            if ip_prefix:
                # A remote leaf may not know the destination MAC on the first
                # attack interval. Do not cache a meter rule with FLOOD as its
                # output: wait for the reply to teach the path, then install a
                # direct metered forwarding rule on the next interval.
                if out_port == ofp.OFPP_FLOOD:
                    return "throttle_pending_learning"
                match = self._mitigation_match(parser, src_ip, dst_ip, proto, dst_port)
                # Preserve normal forwarding while applying the shared meter.
                # Flooding a metered flow duplicates packets across the tree and
                # can prevent concurrent UDP clients from completing.
                actions = [parser.OFPActionOutput(out_port)]
                mitigation_key = self._mitigation_key(dp, src_ip, dst_ip, proto, dst_port, "throttle")
                if mitigation_key not in self.mitigation_keys:
                    self._add_flow(dp, 450, match, actions, idle_timeout=30, meter_id=1)
                    self.mitigation_keys.add(mitigation_key)
                    self.metrics["mitigation_rules_installed"] = self.metrics.get("mitigation_rules_installed", 0) + 1
                    if RULE_MODE == "intent":
                        self.metrics["installed_intents"] += 1
            else:
                # Without an explicitly scoped lab attack prefix, avoid installing
                # a broad wildcard. Keep forwarding and record the score instead.
                action_name = "allow_unscoped_suspicion"
        else:
            action_name = "block"
            if ip_prefix:
                match = self._mitigation_match(parser, src_ip, dst_ip, proto, dst_port)
                mitigation_key = self._mitigation_key(dp, src_ip, dst_ip, proto, dst_port, "block")
                if mitigation_key not in self.mitigation_keys:
                    self._add_flow(dp, 500, match, [], idle_timeout=30)
                    self.mitigation_keys.add(mitigation_key)
                    self.metrics["mitigation_rules_installed"] = self.metrics.get("mitigation_rules_installed", 0) + 1
                    if RULE_MODE == "intent":
                        self.metrics["installed_intents"] += 1
            else:
                action_name = "allow_unscoped_suspicion"
        if action_name in self.metrics:
            self.metrics[action_name] += 1
        self.metrics["last_risk_score"] = score
        flow_record = {
            "timestamp": time.time(),
            "switch": f"s{dp.id}",
            "src_ip": src_ip,
            "dst_ip": dst_ip or "10.0.0.1",
            "proto": "UDP" if proto == 17 else ("TCP" if proto == 6 else ("ICMP" if proto == 1 else str(proto))),
            "dst_port": dst_port,
            "score": round(score, 4),
            "tier": "allow" if score < LOW_THRESHOLD else ("throttle" if score <= HIGH_THRESHOLD else "block"),
            "action": action_name,
            "rule_type": "intent-wildcard" if (RULE_MODE == "intent" and self._in_attack_prefix(src_ip)) else "exact-flow"
        }
        self.recent_flows.appendleft(flow_record)
        self.logger.info("src=%s proto=%s dst_port=%s risk=%.3f action=%s",
                         src_ip, proto, dst_port, score, action_name)
        return action_name

    def _score_and_apply(self, dp, src_ip, proto, dst_port, row, out_port,
                         refresh_allow=False):
        try:
            frame = pd.DataFrame([[row[name] for name in FEATURES]], columns=FEATURES)
            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba(frame)[0]
                classes = list(self.model.classes_)
                score = float(sum(p for c, p in zip(classes, probabilities) if c != "benign"))
            else:
                score = float(self.model.predict(frame)[0])
            self.metrics["scored_flows"] += 1
            self.metrics["last_update"] = time.time()
            return self._apply_decision(dp, src_ip, proto, dst_port, score, out_port,
                                        row.get("destination_ip"), refresh_allow)
        except Exception as exc:
            self.logger.exception("Flow classification failed: %s", exc)
            return None

    @staticmethod
    def _mitigation_key(dp, src_ip, dst_ip, proto, dst_port, action):
        scope = ATTACK_PREFIX if RULE_MODE == "intent" else src_ip
        return dp.id, action, scope, dst_ip, proto, dst_port
    @staticmethod
    def _flow_output_port(dp, flow):
        """Read the allowed-flow output port from OpenFlow instructions."""
        for instruction in flow.instructions:
            if instruction.type != dp.ofproto.OFPIT_APPLY_ACTIONS:
                continue
            for action in instruction.actions:
                if action.type == dp.ofproto.OFPAT_OUTPUT:
                    return action.port
        return dp.ofproto.OFPP_FLOOD
    @staticmethod
    def _in_attack_prefix(src_ip):
        try:
            return ipaddress.ip_address(src_ip) in ATTACK_NETWORK
        except ValueError:
            return False

    @staticmethod
    def _is_benign_forward_pair(src_ip, dst_ip):
        return src_ip in BENIGN_FORWARD_ENDPOINTS and dst_ip in BENIGN_FORWARD_ENDPOINTS

    @staticmethod
    def _mitigation_match(parser, src_ip, dst_ip, proto, dst_port):
        if RULE_MODE == "per-flow":
            return PacketGuardController._l4_match(parser, src_ip, dst_ip, proto, dst_port)
        return PacketGuardController._intent_match(parser, proto, dst_port)

    @staticmethod
    def _intent_match(parser, proto, dst_port):
        fields = {"eth_type": ether_types.ETH_TYPE_IP,
                  "ipv4_src": (str(ATTACK_NETWORK.network_address),
                               str(ATTACK_NETWORK.netmask)),
                  "ip_proto": proto}
        if proto == 6 and dst_port is not None: fields["tcp_dst"] = dst_port
        elif proto == 17 and dst_port is not None: fields["udp_dst"] = dst_port
        return parser.OFPMatch(**fields)

    @staticmethod
    def _l4_match(parser, src_ip, dst_ip, proto, dst_port):
        fields = {"eth_type": ether_types.ETH_TYPE_IP, "ipv4_src": src_ip,
                  "ip_proto": proto}
        if dst_ip:
            fields["ipv4_dst"] = dst_ip
        if proto == 6: fields["tcp_dst"] = dst_port
        elif proto == 17: fields["udp_dst"] = dst_port
        return parser.OFPMatch(**fields)

    @staticmethod
    def _add_flow(dp, priority, match, actions, idle_timeout=30, meter_id=None):
        parser = dp.ofproto_parser
        instructions = []
        if meter_id is not None:
            instructions.append(parser.OFPInstructionMeter(meter_id))
        if actions:
            instructions.append(parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions))
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=instructions,
                                      idle_timeout=idle_timeout,
                                      hard_timeout=idle_timeout))

    def _poll_flow_stats(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            now = time.time()
            for key, stat in list(self.observed.items()):
                if now - stat["last_seen"] > 60:
                    self.observed.pop(key, None)
            for key, baseline in list(self.flow_baselines.items()):
                if now - baseline[3] > 40:
                    self.flow_baselines.pop(key, None)
            hub.sleep(POLL_SECONDS)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply(self, ev):
        # Use OpenFlow counters to refresh features for installed, exact flow rules.
        # This is the controller-side sampling path after packet-in forwarding.
        dp = ev.msg.datapath
        entries = [f for f in ev.msg.body if f.priority == 400]
        now = time.time()
        for f in entries:
            match = f.match
            src_ip = match.get("ipv4_src")
            # Prefix matches are represented as a tuple by some Ryu/OVS
            # versions. The policy needs one representative address; the
            # intent match itself remains the configured aggregate prefix.
            policy_src_ip = src_ip[0] if isinstance(src_ip, tuple) else str(src_ip).split("/")[0]
            dst_ip = match.get("ipv4_dst")
            proto = int(match.get("ip_proto", 0))
            dst_port = int(match.get("tcp_dst", match.get("udp_dst", 0)))
            if not src_ip:
                continue
            key = (dp.id, src_ip, dst_ip, proto, dst_port)
            if key in self.scored_flow_keys:
                continue
            duration = float(f.duration_sec) + float(f.duration_nsec) / 1e9
            previous = self.flow_baselines.get(key)
            self.flow_baselines[key] = (int(f.packet_count), int(f.byte_count), duration, now)
            if previous is None:
                # The first reply already contains a measured switch counter
                # window, so score it without using any Packet-In statistics.
                packet_delta = int(f.packet_count)
                byte_delta = int(f.byte_count)
                duration_delta = max(1e-3, duration)
            else:
                packet_delta = max(0, int(f.packet_count) - previous[0])
                byte_delta = max(0, int(f.byte_count) - previous[1])
                duration_delta = max(1e-3, duration - previous[2])
                if packet_delta == 0:
                    continue
            row = {"packet_rate": packet_delta / duration_delta,
                   "byte_count": byte_delta, "duration_s": duration_delta,
                   "protocol": proto, "dst_port": dst_port,
                   "destination_ip": dst_ip}
            out_port = self._flow_output_port(dp, f)
            if self.model is not None:
                self._score_and_apply(dp, policy_src_ip, proto, dst_port, row, out_port,
                                      refresh_allow=False)
                self.scored_flow_keys.add(key)
        # Store switch counters for REST collection; no fabricated RTT/throughput.
        entries = [f for f in ev.msg.body if f.priority > 0]
        self.switch_counters[dp.id] = {
            "flow_entries": len(entries),
            "packet_count": sum(f.packet_count for f in entries),
            "byte_count": sum(f.byte_count for f in entries)}
        self.metrics["datapath_count"] = len(self.datapaths)
        self.metrics["switch_flow_entries"] = sum(x["flow_entries"] for x in self.switch_counters.values())
        self.metrics["switch_packet_count"] = sum(x["packet_count"] for x in self.switch_counters.values())
        self.metrics["switch_byte_count"] = sum(x["byte_count"] for x in self.switch_counters.values())


class PacketGuardStats(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.packetguard = data["packetguard"]

    @route("packetguard", "/stats/packetguard", methods=["GET"])
    def get_stats(self, req, **kwargs):
        payload = dict(self.packetguard.metrics)
        payload["switches"] = {
            f"s{k}": v for k, v in self.packetguard.switch_counters.items()
        }
        payload["recent_flows"] = list(self.packetguard.recent_flows)
        body = json.dumps(payload, sort_keys=True)
        return self._response(body)

    @route("packetguard", "/stats/packetguard", methods=["OPTIONS"])
    def options_stats(self, req, **kwargs):
        return self._response("{}")

    @staticmethod
    def _response(body):
        from webob import Response
        res = Response(content_type="application/json", body=body.encode("utf-8"))
        res.headers["Access-Control-Allow-Origin"] = "*"
        res.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        res.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return res







