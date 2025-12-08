// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
use std::cmp::Ordering;
#[cfg(feature = "ipv6")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result};
use futures_util::{Stream, StreamExt, TryStreamExt};
use ipnet::Ipv4Net;
#[cfg(feature = "ipv6")]
use ipnet::Ipv6Net;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{
    address::AddressAttribute,
    link::{
        InfoKind, LinkAttribute, LinkFlags, LinkInfo as AttrLinkInfo, LinkLayerType, LinkMessage,
    },
    neighbour::{NeighbourMessage, NeighbourState},
    route::{RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol},
    rule::{RuleAction, RuleAttribute, RuleMessage},
    AddressFamily, IpProtocol as RouteIpProtocol, RouteNetlinkMessage,
};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::{new_connection, Handle, IpVersion, NeighbourAddRequest, RouteMessageBuilder};
use tokio::process::Command;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::IpProtocol;
use crate::utils::{IpAddress, IpNetwork};

impl From<IpProtocol> for RouteIpProtocol {
    fn from(value: IpProtocol) -> Self {
        match value {
            IpProtocol::Tcp => RouteIpProtocol::Tcp,
            IpProtocol::Udp => RouteIpProtocol::Udp,
            IpProtocol::Icmp => RouteIpProtocol::Icmp,
        }
    }
}

const fn nl_mgrp(group: u32) -> u32 {
    if group > 31 {
        panic!("use netlink_sys::Socket::add_membership() for this group");
    }
    if group == 0 {
        0
    } else {
        1 << (group - 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEncap {
    BareIp,
    Ethernet,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct LinkInfo(LinkMessage);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IfAddresses {
    pub ipv4: Vec<Ipv4Addr>,
    #[cfg(feature = "ipv6")]
    pub ipv6: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone)]
pub struct RouteHelper {
    handle: Handle,
}

impl LinkInfo {
    pub fn index(&self) -> u32 {
        self.0.header.index
    }

    pub fn is_up(&self) -> bool {
        self.0.header.flags.contains(LinkFlags::Up)
    }

    pub fn name(&self) -> Option<String> {
        self.0.attributes.iter().find_map(|attr| {
            if let LinkAttribute::IfName(if_name) = attr {
                Some(if_name.clone())
            } else {
                None
            }
        })
    }

    pub fn address(&self) -> Option<&Vec<u8>> {
        self.0.attributes.iter().find_map(|attr| {
            if let LinkAttribute::Address(addr) = attr {
                Some(addr)
            } else {
                None
            }
        })
    }

    fn kind(&self) -> Option<&InfoKind> {
        let infos = self.0.attributes.iter().find_map(|attr| {
            if let LinkAttribute::LinkInfo(addr) = attr {
                Some(addr)
            } else {
                None
            }
        })?;
        infos.iter().find_map(|attr| {
            if let AttrLinkInfo::Kind(kind) = attr {
                Some(kind)
            } else {
                None
            }
        })
    }

    fn encap_from_link_type(&self) -> PacketEncap {
        use PacketEncap::*;
        match self.0.header.link_layer_type {
            LinkLayerType::Ether => Ethernet,
            LinkLayerType::Loopback => Ethernet,
            LinkLayerType::None => BareIp,
            LinkLayerType::Ppp => BareIp,
            LinkLayerType::Tunnel => BareIp,
            LinkLayerType::Tunnel6 => BareIp,
            LinkLayerType::Rawip => BareIp,
            LinkLayerType::Ipgre => Unsupported,
            LinkLayerType::Ip6gre => Unsupported,
            LinkLayerType::Netlink => Unsupported,
            _ => Unknown,
        }
    }

    fn encap_from_kind(&self) -> PacketEncap {
        use PacketEncap::*;
        let Some(kind) = self.kind() else {
            return Unknown;
        };
        // XXX: found out unknown encap type
        match kind {
            InfoKind::Dummy => Ethernet,
            InfoKind::Ifb => Ethernet,
            InfoKind::Bridge => Ethernet,
            InfoKind::Tun => BareIp,
            InfoKind::Nlmon => Unsupported,
            InfoKind::Vlan => Ethernet,
            InfoKind::Veth => Ethernet,
            InfoKind::Vxlan => Ethernet,
            InfoKind::Bond => Ethernet,
            InfoKind::IpVlan => Ethernet,
            InfoKind::MacVlan => Ethernet,
            InfoKind::MacVtap => Ethernet,
            InfoKind::GreTap => Unsupported,
            InfoKind::GreTap6 => Unsupported,
            // most tunnel has just bare IP
            InfoKind::IpTun => BareIp,
            InfoKind::SitTun => BareIp,
            InfoKind::GreTun => Unsupported,
            InfoKind::GreTun6 => Unsupported,
            InfoKind::Vti => Unknown,
            InfoKind::Vrf => Unknown,
            InfoKind::Gtp => Unknown,
            InfoKind::Ipoib => BareIp,
            InfoKind::Wireguard => BareIp,
            InfoKind::Xfrm => Unknown,
            InfoKind::MacSec => Unknown,
            InfoKind::Hsr => Unknown,
            InfoKind::Other(_) => Unknown,
            _ => Unknown,
        }
    }

    pub fn encap(&self) -> PacketEncap {
        let encap = self.encap_from_link_type();
        if !matches!(encap, PacketEncap::Unknown) {
            return encap;
        }

        let encap = self.encap_from_kind();
        if !matches!(encap, PacketEncap::Unknown) {
            return encap;
        }

        if self.address().is_some() {
            PacketEncap::Ethernet
        } else {
            PacketEncap::Unknown
        }
    }
}

const ROUTE_LOCAL_TABLE_ID: u32 = 255;

impl RouteHelper {
    pub fn spawn() -> Result<Self> {
        let (conn, handle, _) = new_connection()?;
        tokio::spawn(conn);

        Ok(Self { handle })
    }

    pub async fn query_link_info(&self, if_name: &str) -> Result<Option<LinkInfo>> {
        let link = self
            .handle
            .link()
            .get()
            .match_name(if_name.to_string())
            .execute()
            .try_next()
            .await;
        match link {
            Ok(link) => Ok(link.map(LinkInfo)),
            Err(e) => {
                if route_err_is_no_dev(&e) {
                    Ok(None)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    async fn query_link_info_by_index(&self, if_index: u32) -> Result<LinkInfo> {
        let link = self
            .handle
            .link()
            .get()
            .match_index(if_index)
            .execute()
            .try_next()
            .await?;
        let Some(link) = link else {
            return Err(anyhow::anyhow!("interface {} does not exist", if_index));
        };

        Ok(LinkInfo(link))
    }

    pub async fn query_all_addresses(&self, if_index: u32) -> Result<IfAddresses> {
        let mut addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(if_index)
            .execute();

        let mut res = IfAddresses::default();

        while let Some(msg) = addresses.try_next().await? {
            #[cfg(feature = "ipv6")]
            let matches = matches!(
                msg.header.family,
                AddressFamily::Inet | AddressFamily::Inet6
            );
            #[cfg(not(feature = "ipv6"))]
            let matches = matches!(msg.header.family, AddressFamily::Inet);
            if matches {
                // Cited from <if_addr.h>
                // Important comment:
                // IFA_ADDRESS is prefix address, rather than local interface address.
                // It makes no difference for normally configured broadcast interfaces,
                // but for point-to-point IFA_ADDRESS is DESTINATION address,
                // local address is supplied in IFA_LOCAL attribute.
                //
                // Thus we prefer local address if it's found in returned attributes.
                let mut local_address = None;
                let mut address = None;
                for attr in msg.attributes {
                    match attr {
                        AddressAttribute::Local(addr) => local_address = Some(addr),
                        AddressAttribute::Address(addr) => address = Some(addr),
                        _ => (),
                    }
                }

                #[allow(clippy::collapsible_match)]
                if let Some(addr) = local_address.or(address) {
                    match addr {
                        IpAddr::V4(addr) => res.ipv4.push(addr),
                        #[cfg(feature = "ipv6")]
                        IpAddr::V6(addr) => res.ipv6.push(addr),
                        #[allow(unreachable_patterns)]
                        _ => (),
                    }
                }
            }
        }
        Ok(res)
    }

    async fn local_ip_rules(&self, is_ipv4: bool) -> Result<Vec<(RuleMessage, u32)>> {
        let ip_version = if is_ipv4 {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        let mut s = self.handle.rule().get(ip_version).execute();

        let mut res = Vec::new();

        while let Some(rule) = s.try_next().await? {
            if rule.header.table == ROUTE_LOCAL_TABLE_ID as _
                && rule.header.action == RuleAction::ToTable
                && rule
                    .attributes
                    .contains(&RuleAttribute::Table(ROUTE_LOCAL_TABLE_ID))
            {
                let priority = rule.attributes.iter().find_map(|attr| {
                    if let &RuleAttribute::Priority(num) = attr {
                        Some(num)
                    } else {
                        None
                    }
                });
                let priority = priority.unwrap_or(0);
                res.push((rule, priority));
            }
        }

        Ok(res)
    }

    async fn deprioritize_local_ip_rule(&self, is_ipv4: bool, new_priority: u32) -> Result<()> {
        let mut to_delete = Vec::new();
        let mut found_not_less = false;
        for (rule, priority) in self.local_ip_rules(is_ipv4).await? {
            match priority.cmp(&new_priority) {
                Ordering::Less => to_delete.push(rule),
                _ => found_not_less = true,
            }
        }

        if !found_not_less {
            let mut add_local_rule = self
                .handle
                .rule()
                .add()
                .action(RuleAction::ToTable)
                .table_id(ROUTE_LOCAL_TABLE_ID)
                .priority(new_priority);

            add_local_rule.message_mut().header.family = if is_ipv4 {
                AddressFamily::Inet
            } else {
                AddressFamily::Inet6
            };

            // Add protocol=kernel to prevent it from being deleted by systemd-networkd
            // in case `ManageForeignRoutingPolicyRules` was not disabled.
            rule_set_protocol_kernel(add_local_rule.message_mut());

            if let Err(e) = add_local_rule.execute().await {
                if !route_err_is_exist(&e) {
                    return Err(anyhow::anyhow!(e));
                }
            }
        }

        for rule in to_delete {
            self.handle.rule().del(rule).execute().await?;
        }

        Ok(())
    }
}

pub enum MonitorEvent {
    ChangeAddress { if_index: u32 },
    ChangeLink { if_name: String },
    DelLink { if_name: String },
}

pub trait RouteIpNetwork: IpNetwork + Copy + Eq {
    const FAMILY: AddressFamily;
    const IS_IPV4: bool;

    fn neigh_add(&self, if_index: u32, handle: &Handle) -> NeighbourAddRequest;

    fn from_route_address(address: &RouteAddress, prefix_len: u8) -> Option<Self>;
}

impl RouteIpNetwork for Ipv4Net {
    const FAMILY: AddressFamily = AddressFamily::Inet;
    const IS_IPV4: bool = true;

    fn neigh_add(&self, if_index: u32, handle: &Handle) -> NeighbourAddRequest {
        handle.neighbours().add(if_index, IpAddr::V4(self.addr()))
    }

    fn from_route_address(address: &RouteAddress, prefix_len: u8) -> Option<Self> {
        if prefix_len > Self::Addr::LEN {
            return None;
        }
        if let RouteAddress::Inet(v4) = address {
            Some(Ipv4Net::new(*v4, prefix_len).unwrap())
        } else {
            None
        }
    }
}

#[cfg(feature = "ipv6")]
impl RouteIpNetwork for Ipv6Net {
    const FAMILY: AddressFamily = AddressFamily::Inet6;
    const IS_IPV4: bool = false;

    fn neigh_add(&self, if_index: u32, handle: &Handle) -> NeighbourAddRequest {
        handle.neighbours().add(if_index, IpAddr::V6(self.addr()))
    }

    fn from_route_address(address: &RouteAddress, prefix_len: u8) -> Option<Self> {
        if prefix_len > Self::LEN {
            return None;
        }
        if let RouteAddress::Inet6(v6) = address {
            Some(Ipv6Net::new(*v6, prefix_len).unwrap())
        } else {
            None
        }
    }
}

struct RouteDescriber<N> {
    destination: N,
    output_if_index: u32,
    table_id: u32,
    route_type: RouteType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RouteType {
    HairpinDest,
    DefaultRoute,
}

impl<N: RouteIpNetwork> RouteDescriber<N> {
    fn matches(&self, route: &RouteMessage) -> bool {
        let dest_match = if self.is_default_route() {
            // 对于默认路由，检查是否是默认路由（destination_prefix_length == 0 且没有 Destination 属性）
            route.header.destination_prefix_length == 0 && route_destination::<N>(route).is_none()
        } else {
            // 对于 hairpin 目标路由，使用原有的匹配逻辑
            Some(self.destination) == route_destination(route)
        };

        dest_match
            && self.table_id == route_table_id(route)
            && Some(self.output_if_index) == route_output_if_index(route)
    }

    fn is_default_route(&self) -> bool {
        self.route_type == RouteType::DefaultRoute
    }

    fn is_hairpin_dest(&self) -> bool {
        self.route_type == RouteType::HairpinDest
    }
}

pub struct HairpinRouting<N> {
    rt_helper: RouteHelper,
    external_if_index: u32,
    external_if_name: Option<String>,
    table_id: u32,
    ip_rule_pref: u32,
    local_ip_rule_pref: u32,
    internal_if_names: Vec<String>,
    internal_if_indices: std::collections::HashMap<String, u32>,
    ip_protocols: Vec<IpProtocol>,
    hairpin_dests: Vec<N>,
    rules: Vec<RuleMessage>,
    routes: Vec<RouteDescriber<N>>,
    neighs: Vec<NeighbourMessage>,
    cache_ll_addr: Option<Option<Vec<u8>>>,
    hairpin_rule_configured: bool,
    forward_rules: Vec<ForwardRule>,
    iptables_warned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardRule {
    binary: &'static str,
    args: Vec<String>,
}

impl<N: RouteIpNetwork + std::fmt::Debug> HairpinRouting<N> {
    pub fn new(
        rt_helper: RouteHelper,
        external_if_index: u32,
        table_id: u32,
        ip_rule_pref: u32,
        local_ip_rule_pref: u32,
        mut internal_if_names: Vec<String>,
        mut ip_protocols: Vec<IpProtocol>,
    ) -> Self {
        internal_if_names.dedup();
        ip_protocols.dedup();
        Self {
            rt_helper,
            external_if_index,
            external_if_name: None,
            table_id,
            ip_rule_pref,
            local_ip_rule_pref,
            internal_if_names,
            internal_if_indices: std::collections::HashMap::new(),
            ip_protocols,
            hairpin_dests: Default::default(),
            rules: Default::default(),
            routes: Default::default(),
            neighs: Default::default(),
            cache_ll_addr: Default::default(),
            hairpin_rule_configured: false,
            forward_rules: Vec::new(),
            iptables_warned: false,
        }
    }

    fn handle(&self) -> &Handle {
        &self.rt_helper.handle
    }

    fn iptables_bin() -> &'static str {
        if N::IS_IPV4 {
            "iptables"
        } else {
            "ip6tables"
        }
    }

    async fn external_if_name(&mut self) -> Result<String> {
        if let Some(name) = &self.external_if_name {
            return Ok(name.clone());
        }

        let link = self
            .rt_helper
            .query_link_info_by_index(self.external_if_index)
            .await?;
        let name = link
            .name()
            .unwrap_or_else(|| format!("if{}", self.external_if_index));
        self.external_if_name = Some(name.clone());
        Ok(name)
    }

    async fn ensure_internal_if_indices(&mut self) -> Result<()> {
        if self.internal_if_indices.is_empty() {
            self.resolve_internal_interfaces().await?;
        }

        Ok(())
    }

    async fn iptables_rule_exists(&self, binary: &str, args: &[String]) -> Result<bool> {
        let mut check_args = vec!["-C".to_string(), "FORWARD".to_string()];
        check_args.extend_from_slice(args);
        let output = Command::new(binary)
            .args(&check_args)
            .output()
            .await
            .with_context(|| format!("failed to execute {} check command", binary))?;

        if output.status.success() {
            return Ok(true);
        }

        if matches!(output.status.code(), Some(1)) {
            return Ok(false);
        }

        Err(anyhow::anyhow!(
            "checking {} rule failed: {}",
            binary,
            String::from_utf8_lossy(&output.stderr)
        ))
    }

    async fn insert_iptables_rule(&self, binary: &str, args: &[String]) -> Result<()> {
        let mut insert_args = vec!["-I".to_string(), "FORWARD".to_string(), "1".to_string()];
        insert_args.extend_from_slice(args);

        let output = Command::new(binary)
            .args(&insert_args)
            .output()
            .await
            .with_context(|| format!("failed to execute {} insert command", binary))?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "failed to insert {} rule: {}",
                binary,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    async fn ensure_forward_rule(&mut self, binary: &'static str, args: Vec<String>) -> Result<()> {
        let tracked = self
            .forward_rules
            .iter()
            .any(|rule| rule.binary == binary && rule.args == args);
        if self.iptables_rule_exists(binary, &args).await? {
            return Ok(());
        }

        self.insert_iptables_rule(binary, &args).await?;
        if !tracked {
            self.forward_rules.push(ForwardRule { binary, args });
        }
        Ok(())
    }

    async fn ensure_forward_rules(&mut self) -> Result<()> {
        if self.internal_if_names.is_empty() {
            return Ok(());
        }

        if unsafe { libc::geteuid() } != 0 {
            if !self.iptables_warned {
                warn!("skipping iptables forward rule setup: einat is not running as root");
                self.iptables_warned = true;
            }
            return Ok(());
        }

        self.ensure_internal_if_indices().await?;
        if self.internal_if_indices.is_empty() {
            return Ok(());
        }

        let ext_if_name = self.external_if_name().await?;
        let binary = Self::iptables_bin();
        let internal_if_list: Vec<String> = self.internal_if_indices.keys().cloned().collect();

        for internal_if in internal_if_list {
            let mut forward_args = vec![
                "-i".to_string(),
                internal_if.clone(),
                "-o".to_string(),
                ext_if_name.clone(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ];
            if let Err(e) = self.ensure_forward_rule(binary, forward_args.clone()).await {
                if !self.iptables_warned {
                    warn!(
                        "failed to ensure iptables forward rule {:?}: {}. hairpin routes continue without iptables rule",
                        forward_args, e
                    );
                    self.iptables_warned = true;
                }
                continue;
            }

            forward_args = vec![
                "-i".to_string(),
                ext_if_name.clone(),
                "-o".to_string(),
                internal_if.clone(),
                "-m".to_string(),
                "conntrack".to_string(),
                "--ctstate".to_string(),
                "ESTABLISHED,RELATED".to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ];
            if let Err(e) = self.ensure_forward_rule(binary, forward_args.clone()).await {
                if !self.iptables_warned {
                    warn!(
                        "failed to ensure iptables forward rule {:?}: {}. hairpin routes continue without iptables rule",
                        forward_args, e
                    );
                    self.iptables_warned = true;
                }
            }
        }

        Ok(())
    }

    /// 设置内部接口索引映射
    pub async fn resolve_internal_interfaces(&mut self) -> Result<()> {
        self.internal_if_indices.clear();

        info!(
            "Resolving internal interfaces: {:?}",
            self.internal_if_names
        );

        for if_name in &self.internal_if_names {
            if let Ok(Some(link)) = self
                .handle()
                .link()
                .get()
                .match_name(if_name.clone())
                .execute()
                .try_next()
                .await
            {
                info!(
                    "Found interface {} with index {}",
                    if_name, link.header.index
                );
                self.internal_if_indices
                    .insert(if_name.clone(), link.header.index);
            } else {
                warn!(
                    "Interface '{}' not found, skipping default route addition",
                    if_name
                );
            }
        }

        if self.internal_if_indices.is_empty() {
            warn!("No valid internal interfaces found for default route configuration");
        }

        Ok(())
    }

    fn default_destination() -> N {
        if N::IS_IPV4 {
            N::from_route_address(&RouteAddress::Inet(Ipv4Addr::new(0, 0, 0, 0)), 0)
                .expect("Failed to create IPv4 default route")
        } else {
            #[cfg(feature = "ipv6")]
            {
                N::from_route_address(
                    &RouteAddress::Inet6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
                    0,
                )
                .expect("Failed to create IPv6 default route")
            }
            #[cfg(not(feature = "ipv6"))]
            {
                panic!("IPv6 support not enabled");
            }
        }
    }

    async fn default_gateway_for_external(&self) -> Result<Option<IpAddr>> {
        // 优先对于 IPv4，从策略路由规则中找到与外部接口源地址匹配的 table，
        // 再到对应的路由表中查默认网关。
        if N::IS_IPV4 {
            let addrs = self
                .rt_helper
                .query_all_addresses(self.external_if_index)
                .await?;

            if let Some(table_id) = self.external_table_from_source_rules(&addrs).await? {
                if let Some(gw) = self.default_gateway_in_table(table_id).await? {
                    return Ok(Some(gw));
                }
            }
        }

        // 回退：使用主路由表中的默认路由（保持 ppp/pppoe 行为不变）。
        self.default_gateway_in_table(RouteHeader::RT_TABLE_MAIN as u32)
            .await
    }

    /// 根据源地址匹配 `ip rule` 中的 `from <addr> lookup <table>`，得到外部接口使用的路由表。
    async fn external_table_from_source_rules(
        &self,
        addrs: &IfAddresses,
    ) -> Result<Option<u32>> {
        if !N::IS_IPV4 {
            return Ok(None);
        }

        let mut rules = self.handle().rule().get(IpVersion::V4).execute();
        let mut selected: Option<(u32, u32)> = None; // (priority, table_id)

        while let Some(rule) = rules.try_next().await? {
            if rule.header.family != AddressFamily::Inet {
                continue;
            }

            // 只关心 `from <ip>` 规则（IPv4）
            let src = rule.attributes.iter().find_map(|attr| {
                if let RuleAttribute::Source(ip) = attr {
                    if let IpAddr::V4(v4) = ip {
                        Some(*v4)
                    } else {
                        None
                    }
                } else {
                    None
                }
            });
            let Some(src) = src else {
                continue;
            };

            if !addrs.ipv4.contains(&src) {
                continue;
            }

            let table_id = rule_table_id(&rule);
            if table_id == 0 || table_id == ROUTE_LOCAL_TABLE_ID {
                continue;
            }

            let priority = rule
                .attributes
                .iter()
                .find_map(|attr| {
                    if let RuleAttribute::Priority(p) = attr {
                        Some(*p)
                    } else {
                        None
                    }
                })
                .unwrap_or(u32::MAX);

            match &mut selected {
                None => {
                    selected = Some((priority, table_id));
                }
                Some((best_prio, _)) if priority < *best_prio => {
                    *best_prio = priority;
                    selected = Some((priority, table_id));
                }
                _ => {}
            }
        }

        Ok(selected.map(|(_, table)| table))
    }

    /// 在指定的路由表中查找 `default via <gw> dev <external_if>` 形式的默认网关。
    async fn default_gateway_in_table(&self, table_id: u32) -> Result<Option<IpAddr>> {
        let mut route = RouteMessageBuilder::<IpAddr>::new().build();
        route.header.address_family = N::FAMILY;

        let mut routes = self.handle().route().get(route).execute();

        while let Some(route) = routes.try_next().await? {
            if route_table_id(&route) != table_id {
                continue;
            }

            // 只匹配真正的默认路由
            if route.header.destination_prefix_length != 0
                || route_destination::<N>(&route).is_some()
            {
                continue;
            }

            // 必须是当前外部接口
            if route_output_if_index(&route) != Some(self.external_if_index) {
                continue;
            }

            // ppp/pppoe 通常是 `default dev pppX`，没有 gateway，此时保持链路作用域行为。
            let Some(gateway) = route_gateway(&route) else {
                return Ok(None);
            };

            if (gateway.is_ipv4() && !N::IS_IPV4) || (gateway.is_ipv6() && N::IS_IPV4) {
                continue;
            }

            return Ok(Some(gateway));
        }

        Ok(None)
    }

    /// 添加默认路由到指定的路由表
    async fn add_default_route(&mut self, output_if_index: u32) -> Result<()> {
        info!(
            "Adding default route: table_id={}, output_if_index={}",
            self.table_id, output_if_index
        );

        // 验证接口是否存在
        match self
            .handle()
            .link()
            .get()
            .match_index(output_if_index)
            .execute()
            .try_next()
            .await
        {
            Ok(Some(link)) => {
                info!(
                    "Confirmed interface exists: index={}, name={}",
                    output_if_index,
                    link_name(&link)
                );
            }
            Ok(None) => {
                error!("Interface with index {} does not exist!", output_if_index);
                return Err(anyhow::anyhow!("Interface {} not found", output_if_index));
            }
            Err(e) => {
                error!("Failed to verify interface {}: {:?}", output_if_index, e);
                return Err(anyhow::anyhow!("Interface verification failed: {}", e));
            }
        }

        let default_dest = Self::default_destination();
        let gateway = self.default_gateway_for_external().await?;

        let mut route_builder = RouteMessageBuilder::<IpAddr>::new()
            .table_id(self.table_id)
            .output_interface(output_if_index);

        route_builder = route_builder
            .destination_prefix(default_dest.ip_addr(), default_dest.prefix_len())
            .expect("invalid default dest");

        if gateway.is_none() {
            // ppp 等点对点接口使用链路作用域的默认路由
            route_builder = route_builder.scope(netlink_packet_route::route::RouteScope::Link);
        }

        let mut route = if let Some(gateway) = gateway {
            info!(
                "Adding default route with gateway {} on interface index {}",
                gateway, output_if_index
            );
            route_builder
                .gateway(gateway)
                .expect("invalid gateway")
                .build()
        } else {
            info!(
                "Adding on-link default route without gateway on interface index {}",
                output_if_index
            );
            route_builder.build()
        };

        // 设置协议为Unspec，这样就不会显示proto信息
        route.header.protocol = netlink_packet_route::route::RouteProtocol::Unspec;

        info!("Attempting to add default route using resolved gateway");
        if let Err(e) = self.handle().route().add(route).execute().await {
            if route_err_is_exist(&e) {
                info!("Default route already exists in table {}", self.table_id);
            } else if gateway.is_some() {
                // 若通过网关添加失败，尝试退回链路作用域的默认路由
                warn!(
                    "Failed to add gateway default route ({}), falling back to on-link default route",
                    e
                );

                let fallback_builder = RouteMessageBuilder::<IpAddr>::new()
                    .table_id(self.table_id)
                    .output_interface(output_if_index)
                    .destination_prefix(default_dest.ip_addr(), default_dest.prefix_len())
                    .expect("invalid default dest")
                    .scope(netlink_packet_route::route::RouteScope::Link);
                let mut fallback_route = fallback_builder.build();
                fallback_route.header.protocol = netlink_packet_route::route::RouteProtocol::Unspec;

                if let Err(e2) = self.handle().route().add(fallback_route).execute().await {
                    if route_err_is_exist(&e2) {
                        info!("Default route already exists in table {}", self.table_id);
                    } else {
                        error!(
                            "Failed to add default route with and without gateway, errors: {}, {}",
                            e, e2
                        );
                        return Err(anyhow::anyhow!("Failed to add default route: {}", e2));
                    }
                }
            } else {
                error!("Failed to add default route: {}", e);
                return Err(anyhow::anyhow!("Failed to add default route: {}", e));
            }
        }

        self.routes.push(RouteDescriber {
            destination: default_dest,
            output_if_index,
            table_id: self.table_id,
            route_type: RouteType::DefaultRoute,
        });

        Ok(())
    }

    async fn reconfigure_(&mut self, hairpin_dests: Vec<N>) -> Result<()> {
        self.reconfigure_dests(hairpin_dests).await?;
        self.ensure_internal_if_indices().await?;

        if !self.hairpin_rule_configured {
            // 解析内部接口索引
            if !self.internal_if_names.is_empty() {
                self.rt_helper
                    .deprioritize_local_ip_rule(N::IS_IPV4, self.local_ip_rule_pref)
                    .await?;
            }

            for iif_name in self.internal_if_names.clone() {
                for protocol in self.ip_protocols.clone() {
                    self.add_rule(&iif_name, protocol.into(), self.ip_rule_pref)
                        .await?;
                }
            }

            // 添加默认路由，指向外部接口
            // 注意：默认路由应该指向外部接口（如ppp2），而不是内部接口（如nlbr_ppp2）
            info!(
                "Adding default route for external interface (index {}) to table {}",
                self.external_if_index, self.table_id
            );
            if let Err(e) = self.add_default_route(self.external_if_index).await {
                error!("Failed to add default route for external interface: {}", e);
                warn!("Continuing despite default route failure");
            }

            self.hairpin_rule_configured = true;
        }

        self.ensure_forward_rules().await?;

        Ok(())
    }

    pub async fn reconfigure(&mut self, hairpin_dests: Vec<N>) -> Result<()> {
        let res = self.reconfigure_(hairpin_dests).await;
        if res.is_err() {
            let _ = self.deconfigure().await;
        }
        res
    }

    async fn add_route(&mut self, dest: N) -> Result<()> {
        let route = RouteMessageBuilder::<IpAddr>::new()
            .table_id(self.table_id)
            .output_interface(self.external_if_index)
            .destination_prefix(dest.ip_addr(), dest.prefix_len())
            .expect("invalid dest")
            .build();

        if let Err(e) = self.handle().route().add(route).execute().await {
            if !route_err_is_exist(&e) {
                return Err(e.into());
            }
        }

        self.routes.push(RouteDescriber {
            destination: dest,
            output_if_index: self.external_if_index,
            table_id: self.table_id,
            route_type: RouteType::HairpinDest,
        });

        if let Some(ll_addr) = self.get_ll_addr().await? {
            let mut req = dest
                .neigh_add(self.external_if_index, self.handle())
                .link_local_address(&ll_addr)
                .replace()
                .state(NeighbourState::Permanent);
            let neigh = req.message_mut().clone();

            req.execute().await?;
            self.neighs.push(neigh);
        }

        Ok(())
    }

    async fn del_all_route(&mut self) -> Result<()> {
        let mut route = RouteMessageBuilder::<IpAddr>::new().build();
        route.header.address_family = N::FAMILY;

        let mut s = self.handle().route().get(route).execute();

        while let Some(route) = s.try_next().await? {
            if let Some((_describer_index, describer)) = self
                .routes
                .iter()
                .enumerate()
                .find(|(_, describer)| describer.matches(&route))
            {
                let route_type_str = if describer.is_default_route() {
                    "default route"
                } else {
                    "hairpin destination route"
                };

                info!(
                    "Deleting {} (dest: {:?}, table: {}, oif: {})",
                    route_type_str,
                    describer.destination,
                    describer.table_id,
                    describer.output_if_index
                );

                if let Err(e) = self.handle().route().del(route).execute().await {
                    if !(route_err_is_no_entry(&e) || route_err_is_no_dev(&e)) {
                        error!("failed to delete {}: {}", route_type_str, e);
                    }
                }
            }
        }
        self.routes.clear();

        for neigh in core::mem::take(&mut self.neighs) {
            if let Err(e) = self.handle().neighbours().del(neigh).execute().await {
                if !(route_err_is_no_entry(&e) || route_err_is_no_dev(&e)) {
                    error!("failed to delete neigh entry: {}", e);
                }
            }
        }

        self.cache_ll_addr = None;
        self.internal_if_indices.clear();

        Ok(())
    }

    async fn add_rule(
        &mut self,
        iif_name: &str,
        ip_protocol: RouteIpProtocol,
        priority: u32,
    ) -> Result<()> {
        let mut req = self
            .handle()
            .rule()
            .add()
            .input_interface(iif_name.to_string())
            .table_id(self.table_id)
            .priority(priority)
            .action(RuleAction::ToTable);
        req.message_mut().header.family = N::FAMILY;
        req.message_mut()
            .attributes
            .push(RuleAttribute::IpProtocol(ip_protocol));
        rule_set_protocol_kernel(req.message_mut());

        let rule = req.message_mut().clone();

        if let Err(e) = req.execute().await {
            if !route_err_is_exist(&e) {
                return Err(anyhow::anyhow!(e));
            }
            warn!(
                "overwriting existing IP route rule, from iif {} lookup {} pref {}",
                &iif_name, self.table_id, priority
            );
        }

        self.rules.push(rule);

        Ok(())
    }

    async fn get_ll_addr(&mut self) -> Result<Option<Vec<u8>>> {
        if let Some(ll_addr) = &self.cache_ll_addr {
            return Ok(ll_addr.clone());
        }
        let link = self
            .rt_helper
            .query_link_info_by_index(self.external_if_index)
            .await?;

        let ll_addr = if matches!(link.encap(), PacketEncap::Ethernet) {
            let ll_addr = link.address().cloned();
            if let Some(ll_addr) = ll_addr {
                if ll_addr.iter().all(|&i| i == 0) {
                    warn!(
                        "link address of if {} is unspecified",
                        self.external_if_index
                    );
                    None
                } else {
                    Some(ll_addr)
                }
            } else {
                warn!("no link address on if {}", self.external_if_index);
                None
            }
        } else {
            None
        };

        self.cache_ll_addr = Some(ll_addr.clone());
        Ok(ll_addr.clone())
    }

    async fn reconfigure_dests(&mut self, hairpin_dests: Vec<N>) -> Result<()> {
        if self.hairpin_dests == hairpin_dests {
            return Ok(());
        }
        self.del_all_route().await?;

        for dest in hairpin_dests.iter() {
            self.add_route(*dest).await?;
        }

        self.hairpin_dests = hairpin_dests;

        Ok(())
    }

    pub async fn deconfigure(&mut self) -> Result<()> {
        for rule in core::mem::take(&mut self.rules) {
            let _ = self.handle().rule().del(rule).execute().await;
        }
        let _ = self.del_all_route().await;
        self.cleanup_forward_rules().await;

        self.hairpin_rule_configured = false;

        Ok(())
    }

    async fn cleanup_forward_rules(&mut self) {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let binary = Self::iptables_bin();
        for rule in core::mem::take(&mut self.forward_rules) {
            let mut delete_args = vec!["-D".to_string(), "FORWARD".to_string()];
            delete_args.extend(rule.args.clone());

            match Command::new(rule.binary).args(&delete_args).output().await {
                Ok(output) => {
                    if !output.status.success() && !matches!(output.status.code(), Some(1)) {
                        warn!(
                            "failed to delete {} rule {:?}: {}",
                            binary,
                            rule.args,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
                Err(e) => warn!(
                    "failed to execute {} delete command for {:?}: {}",
                    binary, rule.args, e
                ),
            }
        }
    }
}

fn link_msg_get_name(msg: LinkMessage) -> Option<String> {
    let if_index = msg.header.index;
    let if_name = msg.attributes.into_iter().find_map(|attr| {
        if let LinkAttribute::IfName(if_name) = attr {
            Some(if_name)
        } else {
            None
        }
    });
    if if_name.is_none() {
        error!("no interface name in link message of if {}", if_index);
        return None;
    };
    if_name
}

fn link_name(msg: &LinkMessage) -> String {
    msg.attributes
        .iter()
        .find_map(|attr| {
            if let LinkAttribute::IfName(name) = attr {
                Some(name.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| format!("if{}", msg.header.index))
}

/// This must be called from Tokio context.
pub fn spawn_monitor() -> Result<(JoinHandle<()>, impl Stream<Item = MonitorEvent>)> {
    let (mut conn, _, mut group_messages) = new_connection()?;

    let groups = nl_mgrp(libc::RTNLGRP_IPV4_IFADDR) | nl_mgrp(libc::RTNLGRP_LINK);
    #[cfg(feature = "ipv6")]
    let groups = groups | nl_mgrp(libc::RTNLGRP_IPV6_IFADDR);

    let group_addr = SocketAddr::new(0, groups);
    conn.socket_mut().socket_mut().bind(&group_addr)?;

    let task = tokio::spawn(conn);

    fn filter_msg(msg: RouteNetlinkMessage) -> Option<MonitorEvent> {
        use RouteNetlinkMessage::*;
        let event = match msg {
            NewAddress(msg) | DelAddress(msg) => MonitorEvent::ChangeAddress {
                if_index: msg.header.index,
            },
            NewLink(msg) => MonitorEvent::ChangeLink {
                if_name: link_msg_get_name(msg)?,
            },
            DelLink(msg) => MonitorEvent::DelLink {
                if_name: link_msg_get_name(msg)?,
            },
            _ => return None,
        };
        Some(event)
    }

    let events = async_stream::stream!({
        while let Some((msg, _)) = group_messages.next().await {
            if let NetlinkPayload::InnerMessage(msg) = msg.payload {
                if let Some(event) = filter_msg(msg) {
                    yield event;
                }
            }
        }
    });

    Ok((task, events))
}

fn route_err_is(e: &rtnetlink::Error, err_code: i32) -> bool {
    if let rtnetlink::Error::NetlinkError(e) = e {
        if let Some(code) = e.code {
            if -code.get() == err_code {
                return true;
            }
        }
    }
    false
}

fn route_err_is_exist(e: &rtnetlink::Error) -> bool {
    route_err_is(e, libc::EEXIST)
}

fn route_err_is_no_entry(e: &rtnetlink::Error) -> bool {
    route_err_is(e, libc::ENOENT)
}

fn route_err_is_no_dev(e: &rtnetlink::Error) -> bool {
    route_err_is(e, libc::ENODEV)
}

fn rule_set_protocol_kernel(rule: &mut RuleMessage) {
    rule.attributes
        .push(RuleAttribute::Protocol(RouteProtocol::Kernel));
}

fn route_destination<N: RouteIpNetwork>(route: &RouteMessage) -> Option<N> {
    let dest = route.attributes.iter().find_map(|attr| {
        if let RouteAttribute::Destination(dest) = attr {
            Some(dest)
        } else {
            None
        }
    });
    if let Some(dest) = dest {
        N::from_route_address(dest, route.header.destination_prefix_length)
    } else {
        None
    }
}

fn route_gateway(route: &RouteMessage) -> Option<IpAddr> {
    route.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::Gateway(RouteAddress::Inet(addr)) => Some(IpAddr::V4(*addr)),
        #[cfg(feature = "ipv6")]
        RouteAttribute::Gateway(RouteAddress::Inet6(addr)) => Some(IpAddr::V6(*addr)),
        _ => None,
    })
}

fn route_output_if_index(route: &RouteMessage) -> Option<u32> {
    route.attributes.iter().find_map(|attr| {
        if let RouteAttribute::Oif(oif) = attr {
            Some(*oif)
        } else {
            None
        }
    })
}

fn route_table_id(route: &RouteMessage) -> u32 {
    let table_id = route.attributes.iter().find_map(|attr| {
        if let RouteAttribute::Table(table_id) = attr {
            Some(*table_id)
        } else {
            None
        }
    });
    table_id.unwrap_or(route.header.table as _)
}

fn rule_table_id(rule: &RuleMessage) -> u32 {
    let table_id = rule.attributes.iter().find_map(|attr| {
        if let RuleAttribute::Table(table_id) = attr {
            Some(*table_id)
        } else {
            None
        }
    });
    table_id.unwrap_or(rule.header.table as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_async_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    #[ignore = "netlink"]
    fn get_link() {
        new_async_rt().block_on(async {
            let rt_helper = RouteHelper::spawn().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                rt_helper.query_link_info_by_index(1).await.unwrap();
            })
            .await
            .unwrap();
        });
    }

    #[test]
    #[ignore = "netlink"]
    fn get_addr() {
        new_async_rt().block_on(async {
            let rt_helper = RouteHelper::spawn().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                rt_helper.query_all_addresses(1).await.unwrap();
            })
            .await
            .unwrap();
        });
    }

    #[test]
    #[ignore = "netlink"]
    fn get_local_rule() {
        new_async_rt().block_on(async {
            let rt_helper = RouteHelper::spawn().unwrap();
            let rules = rt_helper.local_ip_rules(true).await.unwrap();
            dbg!(rules);
        })
    }

    #[test]
    #[ignore = "netlink"]
    fn get_routes() {
        new_async_rt().block_on(async {
            let rt_helper = RouteHelper::spawn().unwrap();
            let mut route = RouteMessageBuilder::<IpAddr>::new().build();
            route.header.address_family = AddressFamily::Inet;
            let req = rt_helper.handle.route().get(route);
            let mut routes = req.execute();
            while let Some(route) = routes.try_next().await.unwrap() {
                dbg!(route);
            }
        })
    }
}
