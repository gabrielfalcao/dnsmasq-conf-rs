pub(crate) mod errors;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::MAIN_SEPARATOR_STR;
use std::str::FromStr;

pub use errors::{Error, Result};
use hickory_proto::rr::domain::Name;
use iocore::Path;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
#[derive(Parser, Debug, Clone)]
#[grammar = "dnsmasq-conf/grammar.pest"]
pub struct ConfFormat;
impl ConfFormat {
    pub fn parse_into_config_attributes(string: &str) -> Result<Vec<ConfigAttribute>> {
        let mut config_pairs = ConfFormat::parse(Rule::config, string).map_err(|e| {
            let fancy_e = e.renamed_rules(|rule| match *rule {
                Rule::EOI => "end of input".to_string(),
                Rule::int => "an integer".to_string(),
                Rule::boolean => "a boolean".to_string(),
                Rule::address => "a host dns name and optional ipv4 address".to_string(),
                Rule::key_value => "a key/value pair".to_string(),
                Rule::log_facility => "path to log file".to_string(),
                Rule::conf_file => "path to a conf file entry".to_string(),
                Rule::server => "server ip address".to_string(),
                Rule::attribute => "attribute".to_string(),
                Rule::ipv4_int => "ipv4_int".to_string(),
                Rule::value => "value".to_string(),
                Rule::ip_address => "ip_address".to_string(),
                Rule::dns_name | Rule::dns_name_glob => "dns_name".to_string(),
                Rule::port_limit => "port-limit".to_string(),
                Rule::min_port => "min-port".to_string(),
                Rule::max_port => "max-port".to_string(),
                Rule::auth_server => "auth-server".to_string(),
                Rule::edns_packet_max => "edns-packet-max".to_string(),
                Rule::listen_address => "listen-address".to_string(),
                Rule::except_interface => "except_interface".to_string(),
                Rule::eq => "=".to_string(),
                Rule::double_quoted_string => "double-quoted string".to_string(),
                Rule::single_quoted_string => "single-quoted string".to_string(),
                Rule::forbidden_ebcdic_character => "forbidden EBCDIC character".to_string(),
                Rule::WHITESPACE => "whitespace".to_string(),
                _ => format!("{:#?}", *rule).replace("_", " "),
            });
            eprintln!("{}", fancy_e.to_string());

            return Error::ParseError(fancy_e.to_string());
        })?;
        let mut attributes = Vec::new();
        for p in config_pairs.next().unwrap().into_inner() {
            match p.as_rule() {
                Rule::boolean => attributes.push(ConfigAttribute::Boolean(p.as_str().to_string())),
                Rule::conf_file => {
                    let conf_file = p
                        .into_inner()
                        .next()
                        .expect("conf_file MUST be a compound atomic")
                        .as_str();

                    attributes.push(ConfigAttribute::ConfPath(conf_file.to_string()));
                },
                Rule::address => {
                    let pair =
                        p.into_inner().map(|h| h.as_str().to_string()).collect::<Vec<String>>();
                    let name = pair[0].to_string();
                    if pair.len() == 2 {
                        let ip_address = pair[1].to_string();
                        let name = Name::from_str(name.as_str())?;
                        let ip_address = Ipv4Addr::from_str(ip_address.as_str())?;
                        attributes.push(ConfigAttribute::AddressWithIpv4(name, ip_address));
                    } else {
                        let name = Name::from_str(name.as_str())?;
                        attributes.push(ConfigAttribute::AddressName(name));
                    }
                },
                Rule::listen_address => {
                    let ip_address = Ipv4Addr::from_str(p.into_inner().as_str())?;
                    attributes.push(ConfigAttribute::ListenAddress(ip_address));
                },
                Rule::auth_server => {
                    let mut pair = p.into_inner();
                    let name = pair
                        .next()
                        .expect("auth_server MUST be a compound atomic")
                        .as_str()
                        .to_string();
                    let name = Name::from_str(name.as_str())?;
                    let ip_address_or_interface =
                        pair.next().expect("auth_server MUST be a compound atomic");
                    attributes.push(match Ipv4Addr::from_str(ip_address_or_interface.as_str()) {
                        Ok(ip_address) => ConfigAttribute::AuthServerIpv4(name, ip_address),
                        Err(_) => ConfigAttribute::AuthServerInterface(
                            name,
                            ip_address_or_interface.as_str().to_string(),
                        ),
                    });

                    // let pair =
                    //     p.into_inner().map(|h| h.as_str().to_string()).collect::<Vec<String>>();
                    // let name = pair[0].to_string();
                    // let ip_address_or_interface = pair[1].to_string();
                },
                Rule::log_facility => {
                    let log_facility = p
                        .into_inner()
                        .next()
                        .expect("log_facility MUST be a compound atomic")
                        .as_str();

                    attributes.push(ConfigAttribute::LogFacility(log_facility.to_string()));
                },
                Rule::server => {
                    let ip_address = Ipv4Addr::from_str(p.into_inner().as_str())?;
                    attributes.push(ConfigAttribute::Server(ip_address));
                },
                Rule::port => {
                    let port = u16::from_str(p.into_inner().as_str())?;
                    attributes.push(ConfigAttribute::Port(port));
                },
                Rule::min_port => {
                    let port = u16::from_str(p.into_inner().as_str())?;
                    attributes.push(ConfigAttribute::MinPort(port));
                },
                Rule::max_port => {
                    let port = u16::from_str(p.into_inner().as_str())?;
                    attributes.push(ConfigAttribute::MaxPort(port));
                },
                Rule::port_limit => {
                    let port = u64::from_str(p.into_inner().as_str())?;
                    attributes.push(ConfigAttribute::PortLimit(port));
                },
                Rule::cache_size => {
                    let port = u64::from_str(p.into_inner().as_str())?;
                    attributes.push(ConfigAttribute::CacheSize(port));
                },
                Rule::edns_packet_max => {
                    let value = u64::from_str(
                        p.into_inner()
                            .next()
                            .expect("edns_packet_max MUST be a compound atomic")
                            .as_str(),
                    )?;
                    attributes.push(ConfigAttribute::EdnsPacketMax(value));
                },
                Rule::except_interface => {
                    let value = p.into_inner().as_str().to_string();
                    attributes.push(ConfigAttribute::ExceptInterface(value));
                },
                Rule::key_value => {
                    let mut pair = p.into_inner();
                    let key = pair.next().unwrap().as_str().to_string();
                    let value = pair.next().expect("key_value MUST be a compound atomic");
                    let value_pair =
                        value.into_inner().next().expect("value MUST be a compound atomic");
                    let value = Value::from_pair(value_pair)?;
                    attributes.push(ConfigAttribute::KeyValue(key, value));
                },
                Rule::EOI
                | Rule::config
                | Rule::key
                | Rule::attribute
                | Rule::ip_address
                | Rule::ipv4_int
                | Rule::interface
                | Rule::value
                | Rule::dns_name
                | Rule::dns_name_glob
                | Rule::eq
                | Rule::delimiter
                | Rule::WHITESPACE
                | Rule::int
                | Rule::double_quoted_string
                | Rule::single_quoted_string
                | Rule::forbidden_ebcdic_character
                | Rule::string
                | Rule::path => {},
            }
        }
        Ok(attributes)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Listener {
    Ipv4Addr(Ipv4Addr),
    Interface(String),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Value {
    Ipv4Addr(Ipv4Addr),
    UnsignedInteger(u64),
    Path(String),
    String(String),
}
impl Value {
    pub fn from_pair(p: Pair<Rule>) -> Result<Value> {
        match p.as_rule() {
            Rule::ip_address => Ok(Value::Ipv4Addr(Ipv4Addr::from_str(p.as_str())?)),
            Rule::path => Ok(Value::Path(p.as_str().to_string())),
            Rule::int => Ok(Value::UnsignedInteger(u64::from_str(p.as_str())?)),
            Rule::string => Ok(Value::String(p.as_str().to_string())),
            rule => {
                let (line, column) = p.line_col();
                Err(Error::ParseError(format!(
                    "unexpected {:#?} value {:#?} (line {}, column {})",
                    rule,
                    p.as_str(),
                    line,
                    column
                )))
            },
        }
    }

    pub fn path_from_heuristic(value: &str) -> Result<Value> {
        let path = Path::raw(value);
        if path.try_canonicalize().exists() {
            Ok(Value::Path(value.to_string()))
        } else if path.extension().is_some() {
            Ok(Value::Path(value.to_string()))
        } else if value.contains(MAIN_SEPARATOR_STR) {
            Ok(Value::Path(value.to_string()))
        } else {
            Err(Error::HeuristicError(format!("{:#?} does not appear to be a path because it does not exist, and contains neither the separator {:#?} nor a file extension", value, MAIN_SEPARATOR_STR)))
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ConfigAttribute {
    Boolean(String),
    ConfPath(String),
    LogFacility(String),
    KeyValue(String, Value),
    Server(Ipv4Addr),
    CacheSize(u64),
    AddressWithIpv4(Name, Ipv4Addr),
    AddressName(Name),
    Port(u16),
    MinPort(u16),
    MaxPort(u16),
    PortLimit(u64),
    ExceptInterface(String),
    EdnsPacketMax(u64),
    AuthServerInterface(Name, String),
    AuthServerIpv4(Name, Ipv4Addr),
    ListenAddress(Ipv4Addr),
    #[default]
    None,
}
impl std::fmt::Debug for ConfigAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ConfigAttribute::ConfPath(path) => {
                    format!("ConfPath({:#?})", path.to_string())
                },
                ConfigAttribute::LogFacility(path) => {
                    format!("LogFacility({:#?})", path)
                },
                ConfigAttribute::Boolean(string) => {
                    format!("Boolean({})", string)
                },
                ConfigAttribute::KeyValue(key, value) => {
                    format!("KeyValue({}={:#?})", key, value)
                },
                ConfigAttribute::Server(ipv4addr) => {
                    format!("Server({:#?})", ipv4addr)
                },
                ConfigAttribute::AddressWithIpv4(name, ipv4addr) => {
                    format!("AddressWithIpv4({:#?})", (name, ipv4addr))
                },
                ConfigAttribute::AddressName(name) => {
                    format!("AddressName({:#?})", name)
                },
                ConfigAttribute::Port(val_u16) => {
                    format!("Port({:#?})", val_u16)
                },
                ConfigAttribute::MinPort(val_u16) => {
                    format!("MinPort({:#?})", val_u16)
                },
                ConfigAttribute::MaxPort(val_u16) => {
                    format!("MaxPort({:#?})", val_u16)
                },
                ConfigAttribute::PortLimit(val_u64) => {
                    format!("PortLimit({:#?})", val_u64)
                },
                ConfigAttribute::ExceptInterface(string) => {
                    format!("ExceptInterface({:#?})", string)
                },
                ConfigAttribute::EdnsPacketMax(val_u64) => {
                    format!("EdnsPacketMax({:#?})", val_u64)
                },
                ConfigAttribute::AuthServerInterface(name, string) => {
                    format!("AuthServerInterface({:#?})", (name, string))
                },
                ConfigAttribute::AuthServerIpv4(name, ipv4addr) => {
                    format!("AuthServerIpv4({:#?})", (name, ipv4addr))
                },
                ConfigAttribute::ListenAddress(ipv4addr) => {
                    format!("ListenAddress({:#?})", ipv4addr.to_string())
                },
                ConfigAttribute::CacheSize(val_u64) => {
                    format!("CacheSize({:#?})", val_u64)
                },
                ConfigAttribute::None => {
                    format!("None")
                },
            }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Config {
    pub path: Path,
    pub conf_file: Vec<String>,
    pub server: Vec<Ipv4Addr>,
    pub strict_order: bool,
    pub domain_needed: bool,
    pub expand_hosts: bool,
    pub log_queries: bool,
    pub log_debug: bool,
    pub bogus_priv: bool,
    pub log_facility: Option<String>,
    pub address: Vec<(Name, Option<Ipv4Addr>)>,
    pub key_value: BTreeMap<String, Value>,
    pub port: Option<u16>,
    pub min_port: Option<u16>,
    pub max_port: Option<u16>,
    pub edns_packet_max: Option<u64>,
    pub port_limit: Option<u64>,
    pub cache_size: Option<u64>,
    pub except_interface: Option<String>,
    pub listen_address: Option<Ipv4Addr>,
    pub auth_server: Option<(Name, Listener)>,
}
impl Config {
    pub fn new(path: &Path) -> Config {
        Config {
            path: valid_path(path).unwrap().relative_to_cwd().tildify(),
            conf_file: Vec::default(),
            server: Vec::default(),
            strict_order: bool::default(),
            domain_needed: bool::default(),
            expand_hosts: bool::default(),
            log_queries: bool::default(),
            log_debug: bool::default(),
            bogus_priv: bool::default(),
            log_facility: Option::default(),
            address: Vec::default(),
            key_value: BTreeMap::default(),
            port: Option::default(),
            min_port: Option::default(),
            max_port: Option::default(),
            edns_packet_max: Option::default(),
            port_limit: Option::default(),
            cache_size: Option::default(),
            except_interface: Option::default(),
            listen_address: Option::default(),
            auth_server: Option::default(),
        }
    }

    pub fn from_attributes(attributes: Vec<ConfigAttribute>, path: &Path) -> Result<Config> {
        let mut config = Config::new(path);
        config.update_from_attributes(attributes)?;
        Ok(config)
    }

    pub fn update_from_attributes(&mut self, attributes: Vec<ConfigAttribute>) -> Result<()> {
        for attr in attributes {
            match attr {
                ConfigAttribute::ConfPath(path) => self.conf_file.push(path.to_string()),
                ConfigAttribute::LogFacility(path) => {
                    self.log_facility = Some(path);
                },
                ConfigAttribute::Boolean(string) => {
                    self.set_true(string)?;
                },
                ConfigAttribute::KeyValue(key, value) => {
                    self.key_value.insert(key.to_string(), value.clone());
                },
                ConfigAttribute::Server(ipv4addr) => {
                    self.server.push(ipv4addr.clone());
                },
                ConfigAttribute::AddressWithIpv4(name, ipv4addr) => {
                    self.address.push((name.clone(), Some(ipv4addr.clone())));
                },
                ConfigAttribute::AddressName(name) => {
                    self.address.push((name.clone(), None));
                },
                ConfigAttribute::Port(val_u16) => {
                    self.port = Some(val_u16);
                },
                ConfigAttribute::MinPort(val_u16) => {
                    self.min_port = Some(val_u16);
                },
                ConfigAttribute::MaxPort(val_u16) => {
                    self.max_port = Some(val_u16);
                },
                ConfigAttribute::PortLimit(val_u64) => {
                    self.port_limit = Some(val_u64);
                },
                ConfigAttribute::CacheSize(val_u64) => {
                    self.cache_size = Some(val_u64);
                },
                ConfigAttribute::ExceptInterface(string) => {
                    self.except_interface = Some(string.to_string());
                },
                ConfigAttribute::EdnsPacketMax(val_u64) => {
                    self.edns_packet_max = Some(val_u64);
                },
                ConfigAttribute::AuthServerInterface(name, string) => {
                    self.auth_server = Some((name, Listener::Interface(string)));
                },
                ConfigAttribute::AuthServerIpv4(name, ipv4addr) => {
                    self.auth_server = Some((name, Listener::Ipv4Addr(ipv4addr)));
                },
                ConfigAttribute::ListenAddress(ipv4addr) => {
                    self.listen_address = Some(ipv4addr.clone());
                },
                _ => {},
            }
        }
        Ok(())
    }

    pub fn from_path<'i>(path: &Path) -> Result<Config> {
        let string = path.read()?;
        let attributes = ConfFormat::parse_into_config_attributes(string.as_str())?;
        Ok(Config::from_attributes(attributes, path)?)
    }

    pub fn set_true<T: std::fmt::Display + std::fmt::Debug>(&mut self, flag: T) -> Result<()> {
        match flag.to_string().replace("-", "_").as_str() {
            "strict_order" => {
                self.strict_order = true;
            },
            "domain_needed" => {
                self.domain_needed = true;
            },
            "expand_hosts" => {
                self.expand_hosts = true;
            },
            "log_queries" => {
                self.log_queries = true;
            },
            "log_debug" => {
                self.log_debug = true;
            },
            "bogus_priv" => {
                self.bogus_priv = true;
            },
            _ => return Err(Error::ConfigError(format!("unexpected boolean flag: {:#?}", flag))),
        }
        Ok(())
    }

    pub fn path(&self) -> Path {
        self.path.clone()
    }

    pub fn parent_path(&self) -> Path {
        self.path()
            .parent()
            .expect(format!("{:#?} to have a parent folder", self.path().to_string()).as_str())
    }

    pub fn is_unified(&self) -> bool {
        self.conf_file.is_empty()
    }

    pub fn unify(&self) -> Result<Config> {
        let mut unified = self.clone();
        let main_conf_parent_path = get_parent_path(&self.path())?;
        let last_path = self.path();
        let last_parent_path = main_conf_parent_path.clone();

        while unified.conf_file.len() > 0 {
            let conf_path = unified.conf_file.remove(0).to_string();
            let path = {
                let mut potential_parents =
                    vec![last_parent_path.clone(), main_conf_parent_path.clone(), Path::cwd()];
                let lookup_paths = potential_parents
                    .iter()
                    .map(|h| h.relative_to_cwd().tildify().to_string())
                    .collect::<Vec<String>>();
                loop {
                    if potential_parents.is_empty() {
                        return Err(Error::ConfigError(format!(
                            "error in config file {:#?}: could not find {:#?} in: {}",
                            last_path.to_string(),
                            conf_path,
                            lookup_paths.join(", ")
                        )));
                    }
                    let parent = potential_parents.remove(0);
                    let possible_path = valid_path(parent.join(conf_path.as_str()));
                    if possible_path.is_ok() {
                        break possible_path?;
                    }
                }
            };
            let sub_config_attributes = path.read()?;
            let attributes =
                ConfFormat::parse_into_config_attributes(sub_config_attributes.as_str())?;
            unified.update_from_attributes(attributes)?;
        }
        Ok(unified)
    }
}

pub fn valid_path(path: impl std::fmt::Display) -> Result<Path> {
    let path_str = path.to_string();
    let path = Path::raw(path_str.as_str()).try_canonicalize();
    if !path.exists() {
        Err(Error::IOError(format!("{:#?} does not exist", path_str.as_str())))
    } else if !path.is_file() {
        Err(Error::IOError(format!(
            "{:#?} is not a file ({})",
            path_str.as_str(),
            path.kind()
        )))
    } else {
        Ok(path)
    }
}

pub fn get_parent_path(path: &Path) -> Result<Path> {
    Ok(path.parent().ok_or_else(|| {
        Error::IOError(format!("{:#?} does not have a parent folder", path.to_string()))
    })?)
}
